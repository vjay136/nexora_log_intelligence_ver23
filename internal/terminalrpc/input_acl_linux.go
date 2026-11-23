//go:build linux

package terminalrpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const InputDirectory = "/var/log/nli/input"

func openDirectoryNoFollow(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("input directory must be canonical")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if openErr != nil {
			return nil, errors.New("NLI input directory is unavailable or contains a symlink")
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), path), nil
}

func applyHeldACL(ctx context.Context, spec string, files []*os.File) error {
	args := []string{"-m", spec, "--"}
	for i := range files {
		args = append(args, fmt.Sprintf("/proc/self/fd/%d", 3+i))
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/setfacl", args...)
	cmd.ExtraFiles = files
	if err := cmd.Run(); err != nil {
		return errors.New("NLI input ACL refresh failed; verify the host terminal setup")
	}
	return nil
}

func refreshInputACL(ctx context.Context) error {
	dir, err := openDirectoryNoFollow(InputDirectory)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err = applyHeldACL(ctx, "u:nli-terminal:rwx,d:u:nli-terminal:rwx,d:u:nli:r-x", []*os.File{dir}); err != nil {
		return err
	}
	return refreshHeldLogACL(ctx, dir, applyHeldACL)
}

// Openat and the held descriptor keep ACL changes attached to the checked inode
// even if a user renames the path. Hardlinks cannot turn a read-only external
// file into a writable input. Special files never block this root process.
func refreshHeldLogACL(ctx context.Context, dir *os.File, apply func(context.Context, string, []*os.File) error) error {
	var batch []*os.File
	closeBatch := func() {
		for _, file := range batch {
			file.Close()
		}
		batch = nil
	}
	defer closeBatch()
	count := 0
	for {
		entries, readErr := dir.ReadDir(128)
		for _, entry := range entries {
			count++
			if count > 4096 {
				return errors.New("NLI input directory exceeds the safe terminal ACL scan limit")
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if !strings.HasSuffix(entry.Name(), ".log") {
				continue
			}
			fd, err := unix.Openat(int(dir.Fd()), entry.Name(), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				continue
			}
			var st unix.Stat_t
			if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
				unix.Close(fd)
				continue
			}
			batch = append(batch, os.NewFile(uintptr(fd), entry.Name()))
			if len(batch) == 64 {
				err = apply(ctx, "u:nli-terminal:rw", batch)
				closeBatch()
				if err != nil {
					return err
				}
			}
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				return readErr
			}
			break
		}
	}
	if len(batch) > 0 {
		return apply(ctx, "u:nli-terminal:rw", batch)
	}
	return nil
}
