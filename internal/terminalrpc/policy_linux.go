//go:build linux

package terminalrpc

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

func openHostPolicy(path string) (*os.File, error) {
	dir, err := openDirectoryNoFollow(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), filepath.Base(path), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
