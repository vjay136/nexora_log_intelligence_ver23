//go:build linux

package terminalaccess

import (
	"os"
	"syscall"
)

func executeHelper(kind string, original, canonical []string) error {
	environment := []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TERM=xterm-256color", "SYSTEMD_PAGER=cat", "SYSTEMD_PAGERSECURE=1"}
	if os.Geteuid() != 0 {
		args := append([]string{"/usr/bin/sudo", "-n", HelperBinary, kind}, original...)
		return syscall.Exec("/usr/bin/sudo", args, environment)
	}
	executable := "/usr/bin/systemctl"
	if kind == "--journal" {
		executable = "/usr/bin/journalctl"
	}
	return syscall.Exec(executable, append([]string{executable}, canonical...), environment)
}
