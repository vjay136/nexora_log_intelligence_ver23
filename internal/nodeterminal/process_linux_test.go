//go:build linux

package nodeterminal

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"testing"
	"time"
)

func rootTestManager(t *testing.T, change func(*Config)) *Manager {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Enabled: true, Username: u.Username, AllowRoot: os.Geteuid() == 0, WorkDir: "/tmp", IdleTimeout: 20 * time.Second, MaxLifetime: 30 * time.Second}
	if change != nil {
		change(&cfg)
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Shutdown)
	return m
}
func waitOutput(t *testing.T, m *Manager, id, contains string) Output {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		out, err := m.Read(id, 0, 64<<10)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out.Data), contains) {
			return out
		}
		time.Sleep(20 * time.Millisecond)
	}
	out, _ := m.Read(id, 0, 64<<10)
	t.Fatalf("output missing %q: %q", contains, out.Data)
	return out
}
func TestRealPTYCommandsResizeInterruptAndCleanEnvironment(t *testing.T) {
	t.Setenv("NLI_TERMINAL_PRIVATE_TEST_VALUE", "must-not-inherit")
	m := rootTestManager(t, nil)
	id := "session-commands-123456"
	state, err := m.Open(id, 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	again, err := m.Open(id, 80, 24)
	if err != nil || !again.StartedAt.Equal(state.StartedAt) {
		t.Fatal("open replay spawned twice")
	}
	waitOutput(t, m, id, "/tmp")
	command := []byte("cd /; printf 'PIPE_OK='; printf abc | tr a-z A-Z; printf '\\nENV=%s\\n' \"${NLI_TERMINAL_PRIVATE_TEST_VALUE-unset}\"\n")
	if _, err := m.Input(id, 1, command); err != nil {
		t.Fatal(err)
	}
	out := waitOutput(t, m, id, "ENV=unset")
	if !strings.Contains(string(out.Data), "PIPE_OK=ABC") || strings.Contains(string(out.Data), "must-not-inherit") {
		t.Fatal("command/env mismatch", string(out.Data))
	}
	before := out.State.InputAck
	if _, err := m.Input(id, 1, command); err != nil {
		t.Fatal("duplicate input", err)
	}
	if before != 1 {
		t.Fatal("input not acknowledged")
	}
	if _, err := m.Input(id, 1, []byte("different\n")); !errors.Is(err, ErrSequence) {
		t.Fatal("modified replay accepted", err)
	}
	if _, err := m.Input(id, 3, []byte("bad gap\n")); !errors.Is(err, ErrSequence) {
		t.Fatal("input gap accepted")
	}
	if err = m.Resize(id, 111, 37); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Input(id, 2, []byte("stty size; printf 'SIZE_DONE\\n'\n")); err != nil {
		t.Fatal(err)
	}
	out = waitOutput(t, m, id, "SIZE_DONE\r\n")
	if !strings.Contains(string(out.Data), "37 111") {
		t.Fatal("PTY resize", string(out.Data))
	}
	_, err = m.Input(id, 3, []byte("sleep 30\n"))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	_, err = m.Input(id, 4, []byte{3})
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Input(id, 5, []byte("printf 'INTERRUPT_OK\\n'\n"))
	if err != nil {
		t.Fatal(err)
	}
	waitOutput(t, m, id, "INTERRUPT_OK\r\n")
	if err = m.Close(id, "operator_close"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		out, _ = m.Read(id, 0, 64<<10)
		if out.Closed {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !out.Closed || out.Reason != "operator_close" {
		t.Fatal("session survived close", out.State)
	}
}
func TestCapacityLifetimeAndPollingDoesNotRefreshIdle(t *testing.T) {
	m := rootTestManager(t, func(c *Config) {
		c.MaxSessions = 1
		c.IdleTimeout = 300 * time.Millisecond
		c.MaxLifetime = time.Second
	})
	id := "session-capacity-123456"
	if _, err := m.Open(id, 80, 24); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Open("session-capacity-SECOND", 80, 24); !errors.Is(err, ErrCapacity) {
		t.Fatal("capacity not enforced", err)
	}
	deadline := time.Now().Add(4 * time.Second)
	var out Output
	for time.Now().Before(deadline) {
		out, _ = m.Read(id, 0, 4096)
		_ = m.Resize(id, 80, 24)
		if out.Closed {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !out.Closed || out.Reason != "idle_timeout" {
		t.Fatal("polling kept unattended session alive", out.State)
	}
}
func TestDedicatedUIDAndInputOutputLimits(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("uid transition requires root test container")
	}
	u, err := user.Lookup("nobody")
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(Config{Enabled: true, Username: "nobody", WorkDir: "/tmp", MaxInputBytes: 256, MaxOutputBytes: 4096, OutputBytesPerSecond: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Shutdown()
	id := "session-unprivileged-12345"
	if _, err = m.Open(id, 80, 24); err != nil {
		t.Fatal(err)
	}
	_, err = m.Input(id, 1, []byte("printf 'UID='; id -u; printf 'BOUND='; printf '%010000d' 0; printf 'END_BOUND\\n'\n"))
	if err != nil {
		t.Fatal(err)
	}
	out := waitOutput(t, m, id, "END_BOUND\r\n")
	if !out.Truncated || len(out.Data) > 4096 {
		t.Fatal("output buffer not bounded", out)
	}
	_, err = m.Input(id, 2, []byte("printf 'ACTUAL_UID='; id -u\n"))
	if err != nil {
		t.Fatal(err)
	}
	out = waitOutput(t, m, id, "ACTUAL_UID="+u.Uid+"\r\n")
	if strings.Contains(string(out.Data), "ACTUAL_UID=0\r\n") {
		t.Fatal("terminal retained broker uid")
	}
	if _, err = m.Input(id, 3, make([]byte, 257)); err == nil {
		t.Fatal("oversized input accepted")
	}
	if _, err = New(Config{Enabled: true, Username: "root", WorkDir: "/tmp"}); err == nil {
		t.Fatal("implicit root accepted")
	}
}
func TestSessionChurnBounded(t *testing.T) {
	if os.Getenv("NLI_TERMINAL_STRESS") != "1" {
		t.Skip("opt-in local PTY stress")
	}
	m := rootTestManager(t, func(c *Config) {
		c.MaxSessions = 4
		c.IdleTimeout = 10 * time.Second
		c.MaxLifetime = 20 * time.Second
		c.OutputBytesPerSecond = 1 << 20
	})
	for i := 0; i < 1000; i++ {
		id := fmt.Sprintf("stress-session-%08d", i)
		if _, err := m.Open(id, 80, 24); err != nil {
			t.Fatal(i, err)
		}
		if _, err := m.Input(id, 1, []byte("printf 'DONE_"+strconv.Itoa(i)+"\\n'; exit\n")); err != nil {
			t.Fatal(err)
		}
		waitOutput(t, m, id, "DONE_"+strconv.Itoa(i)+"\r\n")
		_ = m.Close(id, "stress_completed")
		for n := 0; n < 100; n++ {
			out, _ := m.Read(id, 0, 4096)
			if out.Closed {
				break
			}
			time.Sleep(time.Millisecond)
		}
		m.mu.Lock()
		size := len(m.sessions)
		m.mu.Unlock()
		if size > 16 {
			t.Fatal("closed session retention unbounded", size)
		}
	}
}
