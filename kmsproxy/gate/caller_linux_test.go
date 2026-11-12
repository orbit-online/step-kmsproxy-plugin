package gate

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func ownCgroup(t *testing.T) string {
	if _, err := os.Stat(cgroupRoot + "/cgroup.controllers"); err != nil {
		t.Skip("no cgroup2 filesystem at", cgroupRoot)
	}
	raw, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if path, ok := strings.CutPrefix(line, "0::"); ok {
			return path
		}
	}
	t.Skip("no cgroup v2")
	return ""
}

func TestIdentifySelf(t *testing.T) {
	ownCgroup(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	caller, err := IdentifyCaller(server.LocalAddr().String(), server.RemoteAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("linux uid=%d cgroup=%s ns=host", os.Getuid(), NormalizeCgroup(ownCgroup(t)))
	if caller.ID != want {
		t.Fatalf("ID %q, want %q", caller.ID, want)
	}
	exe, _ := os.Executable()
	if !strings.Contains(caller.Description, exe[strings.LastIndex(exe, "/")+1:]) {
		t.Fatalf("description %q doesn't name the test binary", caller.Description)
	}
}

func TestIdentifyNamespaced(t *testing.T) {
	ownCgroup(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	cmd := exec.Command("bash", "-c", fmt.Sprintf("exec 3<>/dev/tcp/127.0.0.1/%d && read -t 10 <&3", port))
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("no user namespaces: %v", err)
	}
	defer cmd.Process.Kill()
	ln.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	caller, err := IdentifyCaller(server.LocalAddr().String(), server.RemoteAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	// Root in the namespace is still the user outside it
	want := fmt.Sprintf("linux uid=%d cgroup=%s ns=namespaced", os.Getuid(), NormalizeCgroup(ownCgroup(t)))
	if caller.ID != want {
		t.Fatalf("ID %q, want %q", caller.ID, want)
	}
	if !strings.Contains(caller.Description, "bash") || !strings.Contains(caller.Description, "sandboxed") {
		t.Fatalf("description %q", caller.Description)
	}
}

func TestNormalizeCgroup(t *testing.T) {
	for in, want := range map[string]string{
		"/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-firefox-3456.scope":                "/user.slice/user.slice/user.service/app.slice/app-gnome-firefox.scope",
		"/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-org.mozilla.firefox-12345.scope": "/user.slice/user.slice/user.service/app.slice/app-flatpak-org.mozilla.firefox.scope",
		"/a/vte-spawn-0c7b1d4e-3f2a-4b9c-8d1e-2f3a4b5c6d7e.scope":                                             "/a/vte-spawn.scope",
		"/machine.slice/libpod-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope":        "/machine.slice/libpod.scope",
		"/system.slice/nix-daemon.service":                                                                    "/system.slice/nix-daemon.service",
		"/user.slice/user-1000.slice/session-3.scope":                                                         "/user.slice/user.slice/session.scope",
		"/app-org.chromium.Chromium@a1b2c3d4e5f60718293a4b5c6d7e8f90.service":                                 "/app-org.chromium.Chromium.service",
		"/app": "/app",
	} {
		if got := NormalizeCgroup(in); got != want {
			t.Errorf("NormalizeCgroup(%q) = %q, want %q", in, got, want)
		}
	}
}
