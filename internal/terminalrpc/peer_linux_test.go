//go:build linux

package terminalrpc

import (
	"context"
	"golang.org/x/sys/unix"
	"nexora.local/nli-v20/internal/nodeterminal"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestUnixBrokerUsesActualPeerCredentials(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root Linux peer test")
	}
	dir, err := os.MkdirTemp("/tmp", "nli-terminal-peer-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	_ = os.Chmod(dir, 0755)
	path := filepath.Join(dir, "terminal.sock")
	manager, err := nodeterminal.New(nodeterminal.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown()
	server, err := NewServer(manager, HostConfig{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, path, "") }()
	client := NewClient(path)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err = client.Status(ctx); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Remove filesystem protection only in this isolated test. Kernel peer UID
	// authorization must continue to deny an unrelated local account.
	if err = os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	// go test's build directory is private; copy the test executable into this
	// isolated traversable directory so a dropped-UID child can execute it.
	binary, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(dir, "peer-probe")
	if err = os.WriteFile(probe, binary, 0755); err != nil {
		t.Fatal(err)
	}
	request := exec.Command(probe, "-test.run=^TestUnixBrokerUntrustedProbe$")
	request.Env = append(os.Environ(), "NLI_TERMINAL_PEER_PROBE="+path)
	request.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	if output, err := request.CombinedOutput(); err != nil {
		t.Fatalf("untrusted peer probe %v %s", err, output)
	}
	cancel()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}
func TestUnixBrokerUntrustedProbe(t *testing.T) {
	path := os.Getenv("NLI_TERMINAL_PEER_PROBE")
	if path == "" {
		t.Skip("subprocess only")
	}
	if _, err := NewClient(path).Status(context.Background()); err == nil {
		t.Fatal("untrusted local peer accepted")
	}
}

func TestHostPolicyPinnedFileOwnershipAndSyntax(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned host policy")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(`{"enabled":false,"privilege_mode":"operator"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHostConfig(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHostConfig(path); err == nil {
		t.Fatal("group-readable host policy accepted")
	}
	_ = os.Chmod(path, 0600)
	_ = os.WriteFile(path, []byte(`{"enabled":false} {"enabled":true}`), 0600)
	if _, err := LoadHostConfig(path); err == nil {
		t.Fatal("trailing policy accepted")
	}
	_ = os.Remove(path)
	target := filepath.Join(dir, "target.json")
	_ = os.WriteFile(target, []byte(`{"enabled":false}`), 0600)
	_ = os.Symlink(target, path)
	if _, err := LoadHostConfig(path); err == nil {
		t.Fatal("symlink host policy accepted")
	}
}

func TestControllerSystemCgroupOnly(t *testing.T) {
	for _, cg := range []string{"0::/system.slice/nli-controller-agent.service", "0::/container/system.slice/nli-controller-agent.service/child"} {
		if !controllerServiceCgroup(cg) {
			t.Fatal(cg)
		}
	}
	for _, cg := range []string{"0::/user.slice/nli-controller-agent.service", "0::/system.slice/nli-controller-agent.service.evil", "0::/system.slice/nli-agent.service"} {
		if controllerServiceCgroup(cg) {
			t.Fatal(cg)
		}
	}
}
func TestHeldInputACLDoesNotFollowLinksOrRaceRename(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "safe.log")
	if err := os.WriteFile(regular, []byte("ok"), 0600); err != nil {
		t.Fatal(err)
	}
	_ = os.Symlink(regular, filepath.Join(dir, "sym.log"))
	_ = os.Link(regular, filepath.Join(dir, "hard.log"))
	_ = unix.Mkfifo(filepath.Join(dir, "fifo.log"), 0600)
	// Hard-linked files are excluded entirely; create a separate single-link file.
	only := filepath.Join(dir, "only.log")
	_ = os.WriteFile(only, []byte("pinned"), 0600)
	held, err := openDirectoryNoFollow(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	seen := 0
	err = refreshHeldLogACL(context.Background(), held, func(_ context.Context, _ string, files []*os.File) error {
		for _, f := range files {
			seen++
			_ = os.Rename(only, only+".moved")
			data := make([]byte, 6)
			n, _ := f.ReadAt(data, 0)
			if string(data[:n]) != "pinned" {
				t.Fatal("unverified inode ACL target")
			}
		}
		return nil
	})
	if err != nil || seen != 1 {
		t.Fatalf("unsafe ACL targets count=%d err=%v", seen, err)
	}
}
