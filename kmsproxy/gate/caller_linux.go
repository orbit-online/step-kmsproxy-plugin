package gate

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// INET_DIAG_CGROUP_ID from linux/inet_diag.h: the cgroup v2 id of the task that created the socket
const inetDiagCgroupID = 21

const cgroupRoot = "/sys/fs/cgroup"

// IdentifyCaller finds the client socket of a loopback connection with sock_diag: its owner uid and the cgroup it was
// created in, which a sandboxed process can't leave. The processes holding it, found in that cgroup, say whether it
// runs in namespaces other than the proxy's. The ID is the uid, the cgroup with instance ids dropped (every
// "app-gnome-firefox-1234.scope" is the same principal) and whether it's namespaced
func IdentifyCaller(local, remote string) (Caller, error) {
	l, err := net.ResolveTCPAddr("tcp", local)
	if err != nil {
		return Caller{}, err
	}
	r, err := net.ResolveTCPAddr("tcp", remote)
	if err != nil {
		return Caller{}, err
	}
	uid, inode, cgroupID, err := sockDiag(r, l)
	if err != nil {
		return Caller{}, fmt.Errorf("Look up the client socket: %w", err)
	}
	cgroup, err := cgroupPath(cgroupID)
	if err != nil {
		return Caller{}, err
	}
	holders := socketHolders(cgroup, inode)
	ns := "unknown"
	if len(holders) > 0 {
		ns = "host"
		for _, pid := range holders {
			if !sameNamespaces(pid) {
				ns = "namespaced"
			}
		}
	}
	// The executables, from /proc/<pid>/exe rather than the name a process can set itself. Within one cgroup they're a
	// label, not a boundary: any process there can run a binary of the same name
	var names []string
	for _, pid := range holders {
		if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
			if name := ExeName(exe); !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	slices.Sort(names)
	exes := strings.Join(names, ",")
	if exes == "" {
		exes = "unknown"
	}
	unit := NormalizeCgroup(cgroup)
	desc := "an unidentified process"
	if len(names) > 0 {
		desc = strings.Join(names, ", ")
	}
	desc += " in " + filepath.Base(unit)
	if uid != uint32(os.Getuid()) {
		desc += fmt.Sprintf(" as uid %d", uid)
	}
	switch ns {
	case "namespaced":
		desc += ", sandboxed"
	case "unknown":
		desc += ", namespaces unknown"
	}
	return Caller{ID: fmt.Sprintf("linux uid=%d cgroup=%s exe=%s ns=%s", uid, unit, exes, ns), Description: desc}, nil
}

// sockDiag asks the kernel about the TCP socket from src to dst: its owner's uid, its inode and its cgroup id
func sockDiag(src, dst *net.TCPAddr) (uid, inode uint32, cgroupID uint64, err error) {
	family, srcIP, dstIP := byte(unix.AF_INET), src.IP.To4(), dst.IP.To4()
	if srcIP == nil || dstIP == nil {
		family, srcIP, dstIP = unix.AF_INET6, src.IP.To16(), dst.IP.To16()
	}
	uid, inode, cgroupID, err = sockDiagFamily(family, srcIP, dstIP, src.Port, dst.Port)
	if errors.Is(err, unix.ENOENT) && family == unix.AF_INET {
		// An IPv6 socket connected to a v4-mapped address
		uid, inode, cgroupID, err = sockDiagFamily(unix.AF_INET6, src.IP.To16(), dst.IP.To16(), src.Port, dst.Port)
	}
	return uid, inode, cgroupID, err
}

func sockDiagFamily(family byte, srcIP, dstIP net.IP, sport, dport int) (uid, inode uint32, cgroupID uint64, err error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return 0, 0, 0, err
	}
	defer unix.Close(fd)
	// struct nlmsghdr, then struct inet_diag_req_v2 (linux/inet_diag.h)
	req := make([]byte, unix.NLMSG_HDRLEN+56)
	ne := binary.NativeEndian
	ne.PutUint32(req[0:], uint32(len(req)))
	ne.PutUint16(req[4:], unix.SOCK_DIAG_BY_FAMILY)
	ne.PutUint16(req[6:], unix.NLM_F_REQUEST)
	b := req[unix.NLMSG_HDRLEN:]
	b[0], b[1] = family, unix.IPPROTO_TCP
	ne.PutUint32(b[4:], ^uint32(0)) // every state
	id := b[8:]                     // struct inet_diag_sockid
	binary.BigEndian.PutUint16(id[0:], uint16(sport))
	binary.BigEndian.PutUint16(id[2:], uint16(dport))
	copy(id[4:20], srcIP)
	copy(id[20:36], dstIP)
	ne.PutUint32(id[40:], ^uint32(0)) // INET_DIAG_NOCOOKIE
	ne.PutUint32(id[44:], ^uint32(0))
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return 0, 0, 0, err
	}
	buf := make([]byte, 8192)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return 0, 0, 0, err
	}
	msgs, err := syscall.ParseNetlinkMessage(buf[:n])
	if err != nil {
		return 0, 0, 0, err
	}
	for _, m := range msgs {
		if m.Header.Type == unix.NLMSG_ERROR {
			if len(m.Data) >= 4 {
				if errno := -int32(ne.Uint32(m.Data)); errno != 0 {
					return 0, 0, 0, syscall.Errno(errno)
				}
			}
			continue
		}
		// struct inet_diag_msg: 4 bytes, the 48 byte sockid, expires, rqueue, wqueue, then uid and inode
		if len(m.Data) < 72 {
			return 0, 0, 0, errors.New("Short inet_diag_msg")
		}
		uid, inode = ne.Uint32(m.Data[64:]), ne.Uint32(m.Data[68:])
		for a := m.Data[72:]; len(a) >= 4; {
			l, t := int(ne.Uint16(a)), ne.Uint16(a[2:])
			if l < 4 || l > len(a) {
				break
			}
			if t == inetDiagCgroupID && l >= 12 {
				return uid, inode, ne.Uint64(a[4:]), nil
			}
			a = a[min((l+3)&^3, len(a)):]
		}
		return 0, 0, 0, errors.New("The kernel reported no cgroup for the socket")
	}
	return 0, 0, 0, unix.ENOENT
}

var (
	cgroupsMu sync.Mutex
	cgroups   map[uint64]string
)

// cgroupPath finds the cgroup with id below cgroupRoot. A cgroup id is its directory's inode number
func cgroupPath(id uint64) (string, error) {
	cgroupsMu.Lock()
	defer cgroupsMu.Unlock()
	if path, ok := cgroups[id]; ok {
		return path, nil
	}
	cgroups = map[uint64]string{}
	filepath.WalkDir(cgroupRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		var st unix.Stat_t
		if unix.Stat(path, &st) == nil {
			cgroups[st.Ino] = "/" + strings.TrimPrefix(strings.TrimPrefix(path, cgroupRoot), "/")
		}
		return nil
	})
	if path, ok := cgroups[id]; ok {
		return path, nil
	}
	return "", fmt.Errorf("No cgroup with id %d", id)
}

// socketHolders are the pids with the socket inode open, looked for in the cgroup first, then everywhere. Processes of
// other users can't be read and are left out
func socketHolders(cgroup string, inode uint32) []int {
	target := fmt.Sprintf("socket:[%d]", inode)
	var pids []int
	if raw, err := os.ReadFile(filepath.Join(cgroupRoot, cgroup, "cgroup.procs")); err == nil {
		for _, f := range strings.Fields(string(raw)) {
			if pid, err := strconv.Atoi(f); err == nil {
				pids = append(pids, pid)
			}
		}
	}
	if holders := holding(pids, target); len(holders) > 0 {
		return holders
	}
	pids = pids[:0]
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	return holding(pids, target)
}

func holding(pids []int, target string) []int {
	var holders []int
	for _, pid := range pids {
		fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name())); err == nil && link == target {
				holders = append(holders, pid)
				break
			}
		}
	}
	return holders
}

// sameNamespaces says whether pid shares the proxy's user and mount namespace
func sameNamespaces(pid int) bool {
	for _, ns := range []string{"user", "mnt"} {
		var own, other unix.Stat_t
		if unix.Stat("/proc/self/ns/"+ns, &own) != nil ||
			unix.Stat(fmt.Sprintf("/proc/%d/ns/%s", pid, ns), &other) != nil ||
			own.Ino != other.Ino || own.Dev != other.Dev {
			return false
		}
	}
	return true
}

// ExeName is the name of an executable, without the dots and "-wrapped" Nix wrappers add (.kubectl-wrapped is kubectl), so
// a rule outlives updates that move it to another store path
func ExeName(path string) string {
	name := strings.TrimLeft(filepath.Base(path), ".")
	for strings.HasSuffix(name, "-wrapped") {
		name = strings.TrimSuffix(name, "-wrapped")
	}
	return name
}

// An instance id systemd or a launcher puts in a unit or cgroup name: a number, a UUID or a long hex string
var instanceID = regexp.MustCompile(`^(.+?)[-@](?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,})(\.scope|\.service|\.slice)?$`)

// NormalizeCgroup drops instance ids from each part of a cgroup path, so the same app or sandbox gets the same path
// every time it starts
func NormalizeCgroup(path string) string {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		parts[i] = instanceID.ReplaceAllString(p, "$1$2")
	}
	return strings.Join(parts, "/")
}
