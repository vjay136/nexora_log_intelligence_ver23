package controlplane

import (
	"nexora.local/nli-v20/internal/protocol"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTerminalApprovalEnableDisablePersistenceAndFreshHostOptIn(t *testing.T) {
	f := newAPIFixture(t)
	node := "approval-node"
	token := terminalTestEnroll(t, f, node)
	st := protocol.TerminalStatus{Supported: true, Enabled: true, Generation: "first-broker", AccessEpoch: strings.Repeat("a", 64), MaxSessions: 4, IdleTimeoutSeconds: 300, LifetimeSeconds: 1800}
	terminalTestExchangeWithoutApproval(t, f, node, token, protocol.TerminalExchangeRequest{Terminal: st})
	open := map[string]any{"node_id": node, "cols": 80, "rows": 24, "password": "Admin-password-12345!", "reason": "approval lifecycle test"}
	resp, data := f.request("POST", "/api/v1/terminal/sessions", open)
	if resp.StatusCode != 409 || !strings.Contains(string(data), "approval") {
		t.Fatalf("unapproved host allowed: %d %s", resp.StatusCode, data)
	}
	resp, data = f.request("GET", "/api/v1/notifications", nil)
	if resp.StatusCode != 200 || !strings.Contains(string(data), "Node Terminal approval required") {
		t.Fatalf("approval notification missing: %d %s", resp.StatusCode, data)
	}
	change := func(action string, revision int) int {
		t.Helper()
		resp, data := f.request("POST", "/api/v1/terminal/access", map[string]any{"node_id": node, "access_epoch": st.AccessEpoch, "revision": revision, "action": action})
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d %s", action, resp.StatusCode, data)
		}
		return f.server.terminal.access.view(node).Revision
	}
	v := f.server.terminal.access.view(node)
	revision := change("approve", v.Revision)
	resp, data = f.request("POST", "/api/v1/terminal/sessions", open)
	if resp.StatusCode != 200 {
		t.Fatalf("approved open: %d %s", resp.StatusCode, data)
	}
	if !newTerminalAccessStore(f.server.cfg.StateDir).allowed(node, st.AccessEpoch) {
		t.Fatal("approval was not durable")
	}
	revision = change("request_disable", revision)
	if !f.server.terminal.access.allowed(node, st.AccessEpoch) {
		t.Fatal("disable applied before approval")
	}
	revision = change("approve", revision)
	if f.server.terminal.access.allowed(node, st.AccessEpoch) || newTerminalAccessStore(f.server.cfg.StateDir).allowed(node, st.AccessEpoch) {
		t.Fatal("disabled host retained access")
	}
	f.server.terminal.mu.Lock()
	for _, session := range f.server.terminal.sessions {
		if session.NodeID == node && terminalActive(session) {
			t.Error("approved disable retained an active session")
		}
	}
	f.server.terminal.mu.Unlock()
	revision = change("request_enable", revision)
	revision = change("approve", revision)
	st.Generation = "restarted-broker"
	terminalTestExchangeWithoutApproval(t, f, node, token, protocol.TerminalExchangeRequest{Terminal: st})
	if !f.server.terminal.access.allowed(node, st.AccessEpoch) {
		t.Fatal("ordinary broker restart unnecessarily revoked the same host opt-in")
	}
	st.AccessEpoch = strings.Repeat("b", 64)
	terminalTestExchangeWithoutApproval(t, f, node, token, protocol.TerminalExchangeRequest{Terminal: st})
	if f.server.terminal.access.allowed(node, st.AccessEpoch) {
		t.Fatal("new host opt-in reused an old approval")
	}
	resp, _ = f.request("POST", "/api/v1/terminal/access", map[string]any{"node_id": node, "access_epoch": strings.Repeat("a", 64), "revision": revision, "action": "approve"})
	if resp.StatusCode != 409 {
		t.Fatal("stale approval accepted", resp.StatusCode)
	}
	v = f.server.terminal.access.view(node)
	resp, _ = f.request("POST", "/api/v1/terminal/access", map[string]any{"node_id": node, "access_epoch": st.AccessEpoch, "revision": v.Revision, "action": "reject"})
	if resp.StatusCode != 200 || f.server.terminal.access.allowed(node, st.AccessEpoch) {
		t.Fatal("rejected host request granted access", resp.StatusCode)
	}
}

func TestTerminalCorruptApprovalPolicyFailsClosedWithoutErasingIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "terminal-access.json")
	data := []byte("not valid approval state\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	a := newTerminalAccessStore(dir)
	epoch := strings.Repeat("c", 64)
	a.observe("node", protocol.TerminalStatus{Enabled: true, Generation: "generation", AccessEpoch: epoch})
	if a.allowed("node", epoch) {
		t.Fatal("corrupt policy granted access")
	}
	if _, err := a.update("node", epoch, "approve", "admin", 1); err == nil {
		t.Fatal("corrupt policy was silently replaced")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(data) {
		t.Fatal("original policy was erased")
	}
}
