package gate

import (
	"fmt"
	"net"
	"os"
	"os/exec"
)

// IdentifyCaller finds the process on the other end of a loopback connection with lsof, which only sees the user's own
// processes, and names it by its code signature: the designated requirement, Apple's "same program" across updates,
// and whether it runs in the App Sandbox. Unsigned code is named by its command
func IdentifyCaller(local, remote string) (Caller, error) {
	r, err := net.ResolveTCPAddr("tcp", remote)
	if err != nil {
		return Caller{}, err
	}
	host := r.IP.String()
	if r.IP.To4() == nil {
		host = "[" + host + "]"
	}
	// Exits 1 when it finds nothing
	out, _ := exec.Command("lsof", "-nP", fmt.Sprintf("-iTCP@%s:%d", host, r.Port), "-Fpcu").Output()
	pid, command, uid := parseLsof(out, os.Getpid())
	if pid == 0 {
		return Caller{ID: "darwin unidentified", Description: "a process of another user"}, nil
	}
	requirement := ""
	if out, err := exec.Command("codesign", "--display", "-r-", fmt.Sprintf("+%d", pid)).Output(); err == nil {
		requirement = parseRequirement(out)
	}
	sandboxed := false
	if out, err := exec.Command("codesign", "--display", "--entitlements", "-", "--xml", fmt.Sprintf("+%d", pid)).Output(); err == nil {
		sandboxed = appSandbox.Match(out)
	}
	code := requirement
	if code == "" {
		code = "unsigned " + command
	}
	desc := command
	if uid != os.Getuid() {
		desc += fmt.Sprintf(" as uid %d", uid)
	}
	if sandboxed {
		desc += ", sandboxed"
	}
	return Caller{ID: fmt.Sprintf("darwin uid=%d code=%s sandbox=%t", uid, code, sandboxed), Description: desc}, nil
}
