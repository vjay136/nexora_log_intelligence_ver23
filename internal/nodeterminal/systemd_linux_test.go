//go:build linux

package nodeterminal

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func systemdFixture(t *testing.T) {
	t.Helper()
	if os.Getenv("NLI_TERMINAL_SYSTEMD_TEST") != "1" {
		t.Skip("opt-in disposable systemd fixture")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("systemd tests must run inside an isolated Docker fixture")
	}
	if os.Geteuid() != 0 {
		t.Fatal("systemd fixture requires root")
	}
	for _, args := range [][]string{{"daemon-reload"}, {"start", "nli-node-terminal.service"}} {
		if out, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
			t.Fatalf("fixture systemd: %s %v", out, err)
		}
	}
}
func waitFilePID(t *testing.T, path string) int {
	t.Helper()
	for n := 0; n < 250; n++ {
		data, err := os.ReadFile(path)
		if err == nil {
			pid, e := strconv.Atoi(strings.TrimSpace(string(data)))
			if e == nil {
				return pid
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("detached process fixture did not write PID")
	return 0
}
func processAlive(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	end := strings.LastIndexByte(string(data), ')')
	parts := strings.Fields(string(data)[end+1:])
	return len(parts) > 0 && parts[0] != "Z"
}
func waitDead(t *testing.T, pid int) {
	t.Helper()
	for n := 0; n < 250; n++ {
		if !processAlive(pid) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("contained detached process survived terminal shutdown", pid)
}
func TestSystemdContainedShellKillsDetachedChildrenAndBindsBroker(t *testing.T) {
	systemdFixture(t)
	dir := t.TempDir()
	m := rootTestManager(t, func(c *Config) { c.Systemd = true; c.WorkDir = dir; c.MaxLifetime = 30 * time.Second })
	id := "systemd-detached-session-1234"
	if _, err := m.Open(id, 80, 24); err != nil {
		t.Fatal(err)
	}
	waitOutput(t, m, id, ":")
	marker := filepath.Join(dir, "detached.pid")
	command := "setsid /bin/sh -c 'echo $$ > " + marker + "; exec /usr/bin/sleep 30' </dev/null >/dev/null 2>&1 &\nprintf 'DETACHED_STARTED\\n'\n"
	if _, err := m.Input(id, 1, []byte(command)); err != nil {
		t.Fatal(err)
	}
	pid := waitFilePID(t, marker)
	if !processAlive(pid) {
		t.Fatal("detached fixture not alive")
	}
	if err := m.Close(id, "operator_close"); err != nil {
		t.Fatal(err)
	}
	waitDead(t, pid)
	// A separate session also dies when its fixed broker service disappears.
	id = "systemd-broker-bound-123456"
	if _, err := m.Open(id, 80, 24); err != nil {
		t.Fatal(err)
	}
	waitOutput(t, m, id, ":")
	marker = filepath.Join(dir, "bound.pid")
	command = "setsid /bin/sh -c 'echo $$ > " + marker + "; exec /usr/bin/sleep 30' </dev/null >/dev/null 2>&1 &\nprintf 'BOUND_STARTED\\n'\n"
	if _, err := m.Input(id, 1, []byte(command)); err != nil {
		t.Fatal(err)
	}
	pid = waitFilePID(t, marker)
	if output, err := exec.Command("systemctl", "stop", "nli-node-terminal.service").CombinedOutput(); err != nil {
		t.Fatalf("stop fake broker %s %v", output, err)
	}
	waitDead(t, pid)
	t.Cleanup(func() { _ = exec.Command("systemctl", "start", "nli-node-terminal.service").Run() })
}
func TestSystemdDisabledStartupCleansOnlyOwnedSessionUnits(t *testing.T) {
	systemdFixture(t)
	digest := sha256.Sum256([]byte(t.Name()))
	owned := fmt.Sprintf("nli-terminal-session-%x.service", digest[:16])
	operator := "nli-terminal-session-operator-demo.service"
	for _, name := range []string{owned, operator} {
		args := []string{"--quiet", "--unit=" + name, "--property=RuntimeMaxSec=30", "/usr/bin/sleep", "30"}
		if output, err := exec.Command("systemd-run", args...).CombinedOutput(); err != nil {
			t.Fatalf("create stale fixture %s %v", output, err)
		}
	}
	t.Cleanup(func() { _ = exec.Command("systemctl", "stop", owned, operator).Run() })
	m, err := New(Config{Systemd: true, Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Shutdown()
	if exec.Command("systemctl", "is-active", "--quiet", owned).Run() == nil {
		t.Fatal("disabled host retained stale owned session")
	}
	if exec.Command("systemctl", "is-active", "--quiet", operator).Run() != nil {
		t.Fatal("cleanup stopped an unrelated similarly named operator service")
	}
}

func TestSystemdOperatorRunsAsDedicatedUID(t *testing.T) {
	systemdFixture(t)
	account, err := user.Lookup("nobody")
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(Config{Systemd: true, Enabled: true, Username: account.Username, WorkDir: "/tmp", MaxLifetime: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Shutdown()
	id := "systemd-dedicated-user-1234"
	if _, err = m.Open(id, 80, 24); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Input(id, 1, []byte("printf 'ACTUAL_UID='; id -u; if test -r /etc/shadow; then printf 'BAD_SHADOW_READ\\n'; else printf 'SHADOW_PROTECTED\\n'; fi\n")); err != nil {
		t.Fatal(err)
	}
	output := waitOutput(t, m, id, "SHADOW_PROTECTED\r\n")
	if !strings.Contains(string(output.Data), "ACTUAL_UID="+account.Uid+"\r\n") || strings.Contains(string(output.Data), "BAD_SHADOW_READ\r\n") {
		t.Fatal("contained shell did not preserve dedicated uid", string(output.Data))
	}
}
