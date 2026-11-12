package gate

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// commctrl.h
const (
	tdfAllowDialogCancellation = 0x0008
	tdfCallbackTimer           = 0x0800
	tdnTimer                   = 4
	tdmClickButton             = 0x0400 + 102 // WM_USER + 102
	tdWarningIcon              = 0xFFFF       // MAKEINTRESOURCEW(-1)
	idAlways, idTemp, idDeny   = 100, 101, 102
)

// TaskDialogIndirect is in Comctl32 version 6 only, which a process gets from a manifest
const commonControlsManifest = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<dependency><dependentAssembly><assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/></dependentAssembly></dependency>
</assembly>
`

var (
	kernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procCreateActCtx     = kernel32.NewProc("CreateActCtxW")
	procActivateActCtx   = kernel32.NewProc("ActivateActCtx")
	procDeactivateActCtx = kernel32.NewProc("DeactivateActCtx")
	procSendMessage      = windows.NewLazySystemDLL("user32.dll").NewProc("SendMessageW")

	commonControls struct {
		once        sync.Once
		actCtx      uintptr
		taskDialog  uintptr
		err         error
		callback    uintptr
		dialogs     sync.Map // callback data -> context.Context
		nextDialog  uintptr
		nextDialogM sync.Mutex
	}
)

// ACTCTXW (winbase.h)
type actCtx struct {
	size                  uint32
	flags                 uint32
	source                *uint16
	processorArchitecture uint16
	langID                uint16
	assemblyDirectory     *uint16
	resourceName          *uint16
	applicationName       *uint16
	module                windows.Handle
}

// AskUser asks with a task dialog. When ctx ends, its timer callback closes the dialog
func AskUser(ctx context.Context, caller Caller, domains []string) (Answer, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	cc := &commonControls
	cc.once.Do(loadCommonControls)
	if cc.err != nil {
		return Dismissed, cc.err
	}
	var cookie uintptr
	if r, _, err := procActivateActCtx.Call(cc.actCtx, uintptr(unsafe.Pointer(&cookie))); r == 0 {
		return Dismissed, fmt.Errorf("Activate Common Controls 6: %w", err)
	}
	defer procDeactivateActCtx.Call(0, cookie)

	cc.nextDialogM.Lock()
	cc.nextDialog++
	id := cc.nextDialog
	cc.nextDialogM.Unlock()
	cc.dialogs.Store(id, ctx)
	defer cc.dialogs.Delete(id)

	summary, body := promptText(caller, domains)
	strs := map[string]*uint16{}
	for _, s := range []string{"kmsproxy", summary, body, labelAlways, labelTemp, labelDeny} {
		p, err := windows.UTF16PtrFromString(s)
		if err != nil {
			return Dismissed, err
		}
		strs[s] = p
	}
	ptr := unsafe.Sizeof(uintptr(0))
	// TASKDIALOG_BUTTON and TASKDIALOGCONFIG are declared under #pragma pack(1), so they're laid out by hand
	ids := map[string]int32{labelAlways: idAlways, labelTemp: idTemp, labelDeny: idDeny}
	labels := buttons(caller)
	buttonsCfg := packed{}
	for _, label := range labels {
		buttonsCfg.u32(uint32(ids[label]))
		buttonsCfg.ptr(uintptr(unsafe.Pointer(strs[label])), ptr)
	}
	cfg := packed{}
	cfg.u32(0) // cbSize, set below
	cfg.ptr(0, ptr)
	cfg.ptr(0, ptr)
	cfg.u32(tdfAllowDialogCancellation | tdfCallbackTimer)
	cfg.u32(0)
	cfg.ptr(uintptr(unsafe.Pointer(strs["kmsproxy"])), ptr)
	cfg.ptr(tdWarningIcon, ptr)
	cfg.ptr(uintptr(unsafe.Pointer(strs[summary])), ptr)
	cfg.ptr(uintptr(unsafe.Pointer(strs[body])), ptr)
	cfg.u32(uint32(len(labels)))
	cfg.ptr(uintptr(unsafe.Pointer(&buttonsCfg.b[0])), ptr)
	cfg.u32(uint32(int32(idDeny)))
	cfg.u32(0)
	cfg.ptr(0, ptr)
	cfg.u32(0)
	for range 6 { // verification, expanded information and its two control texts, footer icon, footer
		cfg.ptr(0, ptr)
	}
	cfg.ptr(cc.callback, ptr)
	cfg.ptr(id, ptr)
	cfg.u32(0)
	binary.LittleEndian.PutUint32(cfg.b, uint32(len(cfg.b)))

	var button int32
	r, _, _ := syscall.SyscallN(cc.taskDialog, uintptr(unsafe.Pointer(&cfg.b[0])), uintptr(unsafe.Pointer(&button)), 0, 0)
	runtime.KeepAlive(strs)
	runtime.KeepAlive(buttonsCfg.b)
	runtime.KeepAlive(cfg.b)
	if ctx.Err() != nil {
		return Dismissed, nil
	}
	if r != 0 {
		return Dismissed, fmt.Errorf("TaskDialogIndirect: HRESULT %#x", r)
	}
	switch button {
	case idAlways:
		return AllowAlways, nil
	case idTemp:
		return AllowTemp, nil
	case idDeny:
		return Deny, nil
	}
	return Dismissed, nil
}

// loadCommonControls creates an activation context for Comctl32 6 from a manifest, loads it within that context
// (side-by-side redirection comes before the system folder in the DLL search order) and sets up the dialog callback
func loadCommonControls() {
	cc := &commonControls
	dir, err := os.MkdirTemp("", "kmsproxy-")
	if err != nil {
		cc.err = err
		return
	}
	defer os.RemoveAll(dir)
	manifest := filepath.Join(dir, "comctl6.manifest")
	if cc.err = os.WriteFile(manifest, []byte(commonControlsManifest), 0o600); cc.err != nil {
		return
	}
	source, _ := windows.UTF16PtrFromString(manifest)
	ac := actCtx{source: source}
	ac.size = uint32(unsafe.Sizeof(ac))
	h, _, err := procCreateActCtx.Call(uintptr(unsafe.Pointer(&ac)))
	if h == uintptr(windows.InvalidHandle) {
		cc.err = fmt.Errorf("Create an activation context for Common Controls 6: %w", err)
		return
	}
	cc.actCtx = h
	var cookie uintptr
	if r, _, err := procActivateActCtx.Call(h, uintptr(unsafe.Pointer(&cookie))); r == 0 {
		cc.err = fmt.Errorf("Activate Common Controls 6: %w", err)
		return
	}
	defer procDeactivateActCtx.Call(0, cookie)
	module, err := windows.LoadLibrary("comctl32.dll")
	if err != nil {
		cc.err = fmt.Errorf("Load Common Controls 6: %w", err)
		return
	}
	if cc.taskDialog, err = windows.GetProcAddress(module, "TaskDialogIndirect"); err != nil {
		cc.err = errors.Join(errors.New("No TaskDialogIndirect: Common Controls 6 didn't load"), err)
		return
	}
	cc.callback = windows.NewCallback(func(hwnd, msg, wparam, lparam, data uintptr) uintptr {
		if msg == tdnTimer {
			if ctx, ok := cc.dialogs.Load(data); ok && ctx.(context.Context).Err() != nil {
				// AskUser returns Dismissed whatever button closed it, once ctx has ended
				procSendMessage.Call(hwnd, tdmClickButton, idDeny, 0)
			}
		}
		return 0 // S_OK
	})
}

// packed builds a struct without padding
type packed struct{ b []byte }

func (p *packed) u32(v uint32) { p.b = binary.LittleEndian.AppendUint32(p.b, v) }

func (p *packed) ptr(v uintptr, size uintptr) {
	if size == 8 {
		p.b = binary.LittleEndian.AppendUint64(p.b, uint64(v))
	} else {
		p.b = binary.LittleEndian.AppendUint32(p.b, uint32(v))
	}
}
