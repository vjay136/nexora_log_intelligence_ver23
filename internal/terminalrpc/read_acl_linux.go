//go:build linux

package terminalrpc

import (
	"context"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

var readAccessRoots = []string{"/var/log/nli/output", "/etc/nli/parsers", "/var/lib/nli/parsers", "/var/lib/nli/parser-assets", "/var/lib/nli-controller/parser-assets"}

// Only these fixed, non-secret trees are readable. A caller cannot supply paths
// or ACL syntax. Atomic parser generation replacement requires fresh inode ACLs.
func refreshReadAccess(ctx context.Context) error {
	remaining := 4096
	for _, path := range readAccessRoots {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		}
		dir, err := openDirectoryNoFollow(path)
		if err != nil {
			return err
		}
		err = refreshHeldReadACL(ctx, dir, 0, &remaining, applyHeldACL)
		dir.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func refreshHeldReadACL(ctx context.Context, dir *os.File, depth int, remaining *int, apply func(context.Context, string, []*os.File) error) error {
	if depth > 32 {
		return errors.New("NLI read access directory depth exceeds the safe scan limit")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := apply(ctx, "u:nli-terminal:r-x,d:u:nli-terminal:r-x", []*os.File{dir}); err != nil {
		return err
	}
	var batch []*os.File
	closeBatch := func() {
		for _, file := range batch {
			file.Close()
		}
		batch = nil
	}
	defer closeBatch()
	for {
		entries, readErr := dir.ReadDir(128)
		for _, entry := range entries {
			*remaining--
			if *remaining < 0 {
				return errors.New("NLI read access exceeds the safe terminal ACL scan limit")
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			fd, err := unix.Openat(int(dir.Fd()), entry.Name(), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				continue
			}
			var st unix.Stat_t
			if unix.Fstat(fd, &st) != nil {
				unix.Close(fd)
				continue
			}
			file := os.NewFile(uintptr(fd), entry.Name())
			switch st.Mode & unix.S_IFMT {
			case unix.S_IFDIR:
				err = refreshHeldReadACL(ctx, file, depth+1, remaining, apply)
				file.Close()
				if err != nil {
					return err
				}
			case unix.S_IFREG:
				if st.Nlink != 1 {
					file.Close()
					continue
				}
				batch = append(batch, file)
				if len(batch) == 64 {
					err = apply(ctx, "u:nli-terminal:r--", batch)
					closeBatch()
					if err != nil {
						return err
					}
				}
			default:
				file.Close()
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
		return apply(ctx, "u:nli-terminal:r--", batch)
	}
	return nil
}
