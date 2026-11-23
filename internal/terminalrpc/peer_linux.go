//go:build linux

package terminalrpc

import (
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func rootOwned(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0
}

func controllerServiceCgroup(data string) bool {
	for _, line := range strings.Split(data, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		path := parts[2]
		const service = "/system.slice/nli-controller-agent.service"
		if strings.HasSuffix(path, service) || strings.Contains(path, service+"/") {
			return true
		}
	}
	return false
}
func trustedPeer(conn net.Conn) bool {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return false
	}
	var cred *unix.Ucred
	var socketErr error
	if raw.Control(func(fd uintptr) { cred, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }) != nil || socketErr != nil || cred == nil {
		return false
	}
	if cred.Uid == 0 {
		return true
	}
	account, err := user.Lookup("nli")
	if err != nil {
		return false
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || cred.Uid != uint32(uid) || cred.Pid <= 0 {
		return false
	}
	data, err := os.ReadFile("/proc/" + strconv.Itoa(int(cred.Pid)) + "/cgroup")
	if err != nil || len(data) > 64<<10 {
		return false
	}
	return controllerServiceCgroup(string(data))
}
