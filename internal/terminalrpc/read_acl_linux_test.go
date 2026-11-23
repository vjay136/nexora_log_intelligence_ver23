//go:build linux

package terminalrpc

import (
	"context"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestReadAccessRefreshPinsNewGenerationAndSkipsUnsafeInodes(t *testing.T) {
	base := t.TempDir()
	live := filepath.Join(base, "parser-assets")
	old := live + ".old"
	_ = os.Mkdir(live, 0700)
	_ = os.WriteFile(filepath.Join(live, "bundle.json"), []byte("old"), 0600)
	_ = os.Rename(live, old)
	_ = os.Mkdir(live, 0700)
	_ = os.Mkdir(filepath.Join(live, "templates"), 0700)
	fresh := filepath.Join(live, "templates", "new.json")
	_ = os.WriteFile(fresh, []byte("new"), 0600)
	_ = os.Symlink(filepath.Join(old, "bundle.json"), filepath.Join(live, "link.json"))
	_ = os.Link(filepath.Join(old, "bundle.json"), filepath.Join(live, "hard.json"))
	held, err := openDirectoryNoFollow(live)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	remaining := 4096
	seen := 0
	err = refreshHeldReadACL(context.Background(), held, 0, &remaining, func(_ context.Context, spec string, files []*os.File) error {
		if strings.Contains(spec, "w") {
			t.Fatal("read ACL granted write", spec)
		}
		for _, file := range files {
			info, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if !info.Mode().IsRegular() {
				continue
			}
			seen++
			_ = os.Rename(fresh, fresh+".moved")
			_ = os.WriteFile(fresh, []byte("replacement"), 0600)
			data := make([]byte, 32)
			n, _ := file.ReadAt(data, 0)
			if string(data[:n]) != "new" {
				t.Fatal("ACL applied to unchecked replacement inode")
			}
		}
		return nil
	})
	if err != nil || seen != 1 {
		t.Fatalf("new generation ACL count=%d err=%v", seen, err)
	}
}

func TestActualReadACLRefreshAfterAtomicGenerationSwap(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ACL test")
	}
	if _, err := exec.LookPath("/usr/bin/setfacl"); err != nil {
		t.Skip("setfacl unavailable")
	}
	if _, err := user.Lookup("nli-terminal"); err != nil {
		t.Skip("terminal operator account unavailable")
	}
	base := t.TempDir()
	live := filepath.Join(base, "assets")
	staging := filepath.Join(base, "staging")
	_ = os.Mkdir(live, 0700)
	_ = os.WriteFile(filepath.Join(live, "bundle.json"), []byte("old"), 0600)
	apply := func(path string) {
		held, err := openDirectoryNoFollow(path)
		if err != nil {
			t.Fatal(err)
		}
		defer held.Close()
		remaining := 4096
		if err = refreshHeldReadACL(context.Background(), held, 0, &remaining, applyHeldACL); err != nil {
			t.Fatal(err)
		}
	}
	apply(live)
	_ = os.Mkdir(staging, 0700)
	_ = os.WriteFile(filepath.Join(staging, "bundle.json"), []byte("new"), 0600)
	_ = os.Rename(live, live+".old")
	_ = os.Rename(staging, live)
	before, err := exec.Command("/usr/bin/getfacl", "-cp", filepath.Join(live, "bundle.json")).Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(before), "user:nli-terminal:") {
		t.Fatal("test staging unexpectedly inherited operator ACL")
	}
	apply(live)
	after, err := exec.Command("/usr/bin/getfacl", "-cp", filepath.Join(live, "bundle.json")).Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(after), "user:nli-terminal:r--") {
		t.Fatalf("new generation lacks read-only operator ACL: %s", after)
	}
	// Permit traversal through only this test's private ancestry, then prove
	// the actual operator UID can read the replacement inode and cannot write.
	_ = os.Chmod(filepath.Dir(base), 0711)
	_ = os.Chmod(base, 0711)
	account, err := user.Lookup("nli-terminal")
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.ParseUint(account.Uid, 10, 32)
	gid, _ := strconv.ParseUint(account.Gid, 10, 32)
	read := exec.Command("/usr/bin/cat", filepath.Join(live, "bundle.json"))
	read.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	if output, err := read.CombinedOutput(); err != nil || string(output) != "new" {
		t.Fatalf("operator cannot read new parser generation: %v %s", err, output)
	}
	write := exec.Command("/bin/sh", "-c", `printf forbidden > "$1"`, "test", filepath.Join(live, "bundle.json"))
	write.SysProcAttr = read.SysProcAttr
	if err := write.Run(); err == nil {
		t.Fatal("operator wrote read-only parser generation")
	}
}
