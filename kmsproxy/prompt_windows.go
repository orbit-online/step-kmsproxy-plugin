//go:build windows

package kmsproxy

import (
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32              = windows.NewLazySystemDLL("user32.dll")
	createWindowEx      = user32.NewProc("CreateWindowExW")
	destroyWindow       = user32.NewProc("DestroyWindow")
	enumThreadWindows   = user32.NewProc("EnumThreadWindows")
	getWindow           = user32.NewProc("GetWindow")
	setForegroundWindow = user32.NewProc("SetForegroundWindow")
	keybdEvent          = user32.NewProc("keybd_event")
	flashWindowEx       = user32.NewProc("FlashWindowEx")
	getLastInputInfo    = user32.NewProc("GetLastInputInfo")
	getTickCount        = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount")
)

// promptIdle is how long the user must not have typed or clicked before a
// dialog takes the focus: keys meant for another window would go into the
// PIN field, and a wrong PIN counts towards the TPM lockout.
const promptIdle = 2 * time.Second

// promptOwner makes the owner window of a dialog that this process, which
// has no window and isn't in the foreground, shows: its taskbar button,
// titled title, is how the user finds the dialog. Once the dialog is up, it
// comes to the front if the user has been idle for promptIdle; else the
// button flashes until the user clicks it. The dialog must run on the
// calling goroutine, which stays on its thread until done.
//
// Windows lets a process take the foreground when it had the last input,
// so promptOwner presses Alt (which types nothing) first: without it,
// SetForegroundWindow leaves the dialog behind the window in front, or
// gives it the focus while it stays hidden behind (measured on Windows 11).
func promptOwner(title string) (owner uintptr, done func()) {
	runtime.LockOSThread()
	const wsPopup, wsVisible, wsExAppWindow = 0x80000000, 0x10000000, 0x40000
	owner, _, _ = createWindowEx.Call(wsExAppWindow, ptr(u16("STATIC")), ptr(u16(title)), wsPopup|wsVisible, 0, 0, 0, 0, 0, 0, 0, 0)
	stop := make(chan struct{})
	if owner != 0 {
		go raisePrompt(owner, windows.GetCurrentThreadId(), stop)
	}
	return owner, func() {
		close(stop)
		if owner != 0 {
			destroyWindow.Call(owner)
		}
		runtime.UnlockOSThread()
	}
}

// raisePrompt brings the dialog that owner owns to the front, or flashes
// owner.
func raisePrompt(owner uintptr, tid uint32, stop chan struct{}) {
	const gwOwner = 4
	var dialog uintptr
	find := syscall.NewCallback(func(h, _ uintptr) uintptr {
		if o, _, _ := getWindow.Call(h, gwOwner); o == owner && windows.IsWindowVisible(windows.HWND(h)) {
			dialog = h
			return 0
		}
		return 1
	})
	for dialog == 0 {
		select {
		case <-stop:
			return
		case <-time.After(50 * time.Millisecond):
		}
		enumThreadWindows.Call(uintptr(tid), find, 0)
	}
	if userIdle() >= promptIdle {
		const vkMenu, keyUp = 0x12, 0x2
		keybdEvent.Call(vkMenu, 0, 0, 0)
		keybdEvent.Call(vkMenu, 0, keyUp, 0)
		setForegroundWindow.Call(dialog)
	}
	if uintptr(windows.GetForegroundWindow()) != dialog {
		// FLASHWINFO: the taskbar button flashes until the window comes to
		// the front (FLASHW_ALL | FLASHW_TIMERNOFG).
		fi := struct {
			cbSize  uint32
			hwnd    uintptr
			flags   uint32
			count   uint32
			timeout uint32
		}{hwnd: owner, flags: 0x3 | 0xC}
		fi.cbSize = uint32(unsafe.Sizeof(fi))
		flashWindowEx.Call(ptr(&fi))
	}
}

// userIdle is how long ago the user last typed or clicked.
func userIdle() time.Duration {
	li := struct{ cbSize, dwTime uint32 }{cbSize: 8}
	if r, _, _ := getLastInputInfo.Call(ptr(&li)); r == 0 {
		return 0
	}
	now, _, _ := getTickCount.Call()
	return time.Duration(uint32(now)-li.dwTime) * time.Millisecond
}
