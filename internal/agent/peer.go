package agentserver

import (
	"bytes"
	"encoding/binary"
	"net"
	"path/filepath"
	"strings"

	"fssh/internal/i18n"

	"golang.org/x/sys/unix"
)

// PeerInfo identifies the local process on the other end of an agent connection.
type PeerInfo struct {
	PID        int
	Name       string
	Args       []string
	ParentName string
}

// peerInfo looks up the connecting process via LOCAL_PEERPID. Errors yield
// an empty PeerInfo: identification is best effort and never blocks signing.
func peerInfo(c net.Conn) PeerInfo {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return PeerInfo{}
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return PeerInfo{}
	}
	var pid int
	var serr error
	if err := raw.Control(func(fd uintptr) {
		pid, serr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	}); err != nil || serr != nil || pid <= 0 {
		return PeerInfo{}
	}
	return processInfo(pid)
}

func processInfo(pid int) PeerInfo {
	info := PeerInfo{PID: pid}
	if buf, err := unix.SysctlRaw("kern.procargs2", pid); err == nil {
		exe, args := parseProcArgs(buf)
		info.Args = args
		if exe != "" {
			info.Name = filepath.Base(exe)
		}
	}
	if kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid); err == nil {
		if info.Name == "" {
			info.Name = cString(kp.Proc.P_comm[:])
		}
		if ppid := int(kp.Eproc.Ppid); ppid > 1 {
			if pk, err := unix.SysctlKinfoProc("kern.proc.pid", ppid); err == nil {
				info.ParentName = cString(pk.Proc.P_comm[:])
			}
		}
	}
	return info
}

// parseProcArgs decodes kern.procargs2: a little-endian int32 argc, the
// executable path, NUL padding, then argc NUL-terminated arguments.
func parseProcArgs(buf []byte) (exe string, args []string) {
	if len(buf) < 4 {
		return "", nil
	}
	argc := int(binary.LittleEndian.Uint32(buf[:4]))
	rest := buf[4:]
	i := bytes.IndexByte(rest, 0)
	if i < 0 {
		return string(rest), nil
	}
	exe = string(rest[:i])
	rest = rest[i:]
	for len(rest) > 0 && rest[0] == 0 {
		rest = rest[1:]
	}
	for len(args) < argc && len(rest) > 0 {
		j := bytes.IndexByte(rest, 0)
		if j < 0 {
			args = append(args, string(rest))
			break
		}
		args = append(args, string(rest[:j]))
		rest = rest[j+1:]
	}
	return exe, args
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// launchers are parents not worth showing: "zsh → ssh" adds nothing, but
// "git → ssh" tells the user why ssh is asking.
var launchers = map[string]bool{
	"zsh": true, "bash": true, "sh": true, "fish": true, "dash": true, "tcsh": true,
	"login": true, "launchd": true, "tmux": true, "screen": true, "sudo": true,
}

// Display returns a short label such as "ssh" or "git → ssh".
func (p PeerInfo) Display() string {
	if p.Name == "" {
		return i18n.T("agent.unknown_process")
	}
	parent := strings.TrimPrefix(p.ParentName, "-")
	if parent != "" && !launchers[parent] && parent != p.Name {
		return parent + " → " + p.Name
	}
	return p.Name
}
