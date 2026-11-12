package gate

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"unsafe"

	psnet "github.com/shirou/gopsutil/v4/net"
	"golang.org/x/sys/windows"
)

// TOKEN_INFORMATION_CLASS values past what x/sys/windows names (winnt.h)
const (
	tokenIsAppContainer  = 29
	tokenAppContainerSid = 31
)

// IdentifyCaller finds the process on the other end of a loopback connection in the TCP table, and names it by its
// user, its AppContainer (the sandbox of packaged apps) and its executable
func IdentifyCaller(local, remote string) (Caller, error) {
	l, err := net.ResolveTCPAddr("tcp", local)
	if err != nil {
		return Caller{}, err
	}
	r, err := net.ResolveTCPAddr("tcp", remote)
	if err != nil {
		return Caller{}, err
	}
	conns, err := psnet.ConnectionsWithContext(context.Background(), "tcp")
	if err != nil {
		return Caller{}, fmt.Errorf("Read the TCP table: %w", err)
	}
	pid := int32(0)
	for _, c := range conns {
		if c.Laddr.Port == uint32(r.Port) && net.ParseIP(c.Laddr.IP).Equal(r.IP) &&
			c.Raddr.Port == uint32(l.Port) && net.ParseIP(c.Raddr.IP).Equal(l.IP) {
			pid = c.Pid
			break
		}
	}
	if pid == 0 {
		return Caller{}, fmt.Errorf("No process owns the connection from %s", remote)
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return Caller{ID: "windows unidentified", Description: fmt.Sprintf("process %d of another user", pid)}, nil
	}
	defer windows.CloseHandle(h)
	exe := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(exe))
	if err := windows.QueryFullProcessImageName(h, 0, &exe[0], &size); err != nil {
		return Caller{}, fmt.Errorf("Find the executable of process %d: %w", pid, err)
	}
	path := windows.UTF16ToString(exe[:size])
	var token windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); err != nil {
		return Caller{ID: "windows unidentified exe=" + strings.ToLower(path),
			Description: filepath.Base(path) + " of another user"}, nil
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return Caller{}, err
	}
	container := appContainer(token)
	desc := filepath.Base(path)
	if container != "" {
		desc += ", sandboxed"
	}
	if !isCurrentUser(user.User.Sid) {
		desc += " as " + user.User.Sid.String()
	}
	return Caller{
		ID:          fmt.Sprintf("windows user=%s appcontainer=%s exe=%s", user.User.Sid, container, strings.ToLower(path)),
		Description: desc,
	}, nil
}

// appContainer is the AppContainer SID of token, empty when it isn't in one
func appContainer(token windows.Token) string {
	var is uint32
	var n uint32
	if windows.GetTokenInformation(token, tokenIsAppContainer, (*byte)(unsafe.Pointer(&is)), 4, &n) != nil || is == 0 {
		return ""
	}
	buf := make([]byte, 128)
	for {
		err := windows.GetTokenInformation(token, tokenAppContainerSid, &buf[0], uint32(len(buf)), &n)
		if err == windows.ERROR_INSUFFICIENT_BUFFER && int(n) > len(buf) {
			buf = make([]byte, n)
			continue
		}
		if err != nil {
			return "unknown"
		}
		// TOKEN_APPCONTAINER_INFORMATION holds one PSID
		return (*struct{ Sid *windows.SID })(unsafe.Pointer(&buf[0])).Sid.String()
	}
}

func isCurrentUser(sid *windows.SID) bool {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	return err == nil && user.User.Sid.Equals(sid)
}
