package controlplane

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"nexora.local/nli-v20/internal/fleet"
	"testing"
	"time"

	"nexora.local/nli-v20/internal/protocol"
)

func terminalTestEnroll(t *testing.T, f *apiFixture, id string) string {
	t.Helper()
	data, _ := json.Marshal(map[string]any{"id": id, "hostname": id, "os": "linux", "arch": "x86_64", "version": "23.0.0"})
	req, _ := http.NewRequest(http.MethodPost, f.http.URL+"/api/v1/node/register", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-NLI-Enrollment", "Enrollment-token-123456789012")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 201 {
		t.Fatalf("enroll %d %s", resp.StatusCode, body)
	}
	return decodeMap(t, body)["node_token"].(string)
}

func TestTerminalThousandNodeInventoryPagination(t *testing.T) {
	f := newAPIFixture(t)
	for i := 0; i < 1000; i++ {
		id := fmt.Sprintf("terminal-fleet-%04d", i)
		f.server.fleet.Register(&fleet.Node{ID: id, Hostname: id, LastSeen: time.Now(), Status: fleet.StatusOnline})
	}
	cursor := ""
	seen := map[string]bool{}
	for page := 0; page < 12; page++ {
		resp, data := f.request("GET", "/api/v1/terminal/nodes?cursor="+cursor, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("inventory %d %s", resp.StatusCode, data)
		}
		out := decodeMap(t, data)
		items := out["items"].([]any)
		if len(items) > 100 {
			t.Fatal("unbounded inventory page")
		}
		for _, value := range items {
			id := value.(map[string]any)["id"].(string)
			if seen[id] {
				t.Fatal("duplicate node", id)
			}
			seen[id] = true
		}
		cursor = out["next_cursor"].(string)
		if cursor == "" {
			break
		}
	}
	if len(seen) != 1001 {
		t.Fatalf("inventory lost nodes: %d", len(seen))
	}
}
func terminalTestExchange(t *testing.T, f *apiFixture, node, token string, in protocol.TerminalExchangeRequest) (int, protocol.TerminalExchangeResponse) {
	t.Helper()
	in.NodeID = node
	data, _ := json.Marshal(in)
	req, _ := http.NewRequest(http.MethodPost, f.http.URL+"/api/v1/node/terminal/exchange", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out protocol.TerminalExchangeResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}
func TestTerminalRemoteSessionLifecycleAndNodeIsolation(t *testing.T) {
	f := newAPIFixture(t)
	token := terminalTestEnroll(t, f, "terminal-node")
	status := protocol.TerminalStatus{Supported: true, Enabled: true, PrivilegeMode: "operator", Generation: "first-generation", MaxSessions: 4, IdleTimeoutSeconds: 300, LifetimeSeconds: 1800}
	code, _ := terminalTestExchange(t, f, "terminal-node", token, protocol.TerminalExchangeRequest{Terminal: status})
	if code != 200 {
		t.Fatal(code)
	}
	open := map[string]any{"node_id": "terminal-node", "cols": 80, "rows": 24, "password": "wrong", "reason": "demo input and output"}
	resp, _ := f.request("POST", "/api/v1/terminal/sessions", open)
	if resp.StatusCode != 403 {
		t.Fatal("step-up password not enforced", resp.StatusCode)
	}
	open["password"] = "Admin-password-12345!"
	resp, data := f.request("POST", "/api/v1/terminal/sessions", open)
	if resp.StatusCode != 200 {
		t.Fatalf("open %d %s", resp.StatusCode, data)
	}
	id := decodeMap(t, data)["session"].(map[string]any)["id"].(string)
	f.server.terminal.mu.Lock()
	for i := 0; i < 3; i++ {
		copy := *f.server.terminal.sessions[id]
		copy.ID = fmt.Sprintf("term-capacity-test-%d", i)
		copy.NodeID = fmt.Sprintf("other-terminal-node-%d", i)
		copy.owner[0] = byte(i + 1)
		f.server.terminal.sessions[copy.ID] = &copy
	}
	f.server.terminal.mu.Unlock()
	resp, _ = f.request("POST", "/api/v1/terminal/sessions", open)
	if resp.StatusCode != 409 {
		t.Fatal("per-user capacity across nodes and separate login owners not enforced", resp.StatusCode)
	}
	f.server.terminal.mu.Lock()
	for i := 0; i < 3; i++ {
		delete(f.server.terminal.sessions, fmt.Sprintf("term-capacity-test-%d", i))
	}
	f.server.terminal.mu.Unlock()
	code, directives := terminalTestExchange(t, f, "terminal-node", token, protocol.TerminalExchangeRequest{Terminal: status})
	if code != 200 || len(directives.Sessions) != 1 || directives.Sessions[0].ID != id {
		t.Fatal("session not routed", code, directives)
	}
	input := map[string]any{"sequence": 1, "data": "printf demo\\n\r"}
	for i := 0; i < 2; i++ {
		resp, _ = f.request("POST", "/api/v1/terminal/sessions/"+id+"/input", input)
		if resp.StatusCode != 200 {
			t.Fatal("duplicate input rejected", resp.StatusCode)
		}
	}
	input["data"] = "different"
	resp, _ = f.request("POST", "/api/v1/terminal/sessions/"+id+"/input", input)
	if resp.StatusCode != 409 {
		t.Fatal("changed duplicate accepted")
	}
	code, directives = terminalTestExchange(t, f, "terminal-node", token, protocol.TerminalExchangeRequest{Terminal: status})
	if code != 200 || len(directives.Sessions[0].Inputs) != 1 {
		t.Fatal("queued duplicate commands")
	}

	f.server.terminal.mu.Lock()
	queued := f.server.terminal.sessions[id]
	original := append([]protocol.TerminalInput(nil), queued.inputs...)
	for i := 2; i <= 32; i++ {
		queued.inputs = append(queued.inputs, protocol.TerminalInput{Sequence: uint64(i), Data: bytes.Repeat([]byte("x"), 8192)})
	}
	f.server.terminal.mu.Unlock()
	code, bounded := terminalTestExchange(t, f, "terminal-node", token, protocol.TerminalExchangeRequest{Terminal: status})
	if code != 200 || len(bounded.Sessions) != 1 || len(bounded.Sessions[0].Inputs) != 4 {
		t.Fatal("queued terminal stdin exceeded a bounded response window")
	}
	f.server.terminal.mu.Lock()
	queued.inputs = original
	f.server.terminal.mu.Unlock()
	frame := protocol.TerminalSessionUpdate{ID: id, Status: "running", Start: 0, Next: 4, Data: []byte("demo"), AckedInput: 1}
	for i := 0; i < 2; i++ {
		code, _ = terminalTestExchange(t, f, "terminal-node", token, protocol.TerminalExchangeRequest{Terminal: status, Sessions: []protocol.TerminalSessionUpdate{frame}})
		if code != 200 {
			t.Fatal(code)
		}
	}
	f.server.terminal.mu.Lock()
	session := f.server.terminal.sessions[id]
	if string(session.data) != "demo" || len(session.inputs) != 0 {
		t.Error("output duplicated or inputs unacknowledged")
	}
	f.server.terminal.mu.Unlock()
	bad := frame
	bad.Next = 99
	code, _ = terminalTestExchange(t, f, "terminal-node", token, protocol.TerminalExchangeRequest{Terminal: status, Sessions: []protocol.TerminalSessionUpdate{bad}})
	if code != 400 {
		t.Fatal("malformed output accepted")
	}
	code, _ = terminalTestExchange(t, f, "unrelated-node", token, protocol.TerminalExchangeRequest{Terminal: status})
	if code != 401 {
		t.Fatal("token crossed node identity")
	}
	if _, err := f.server.auth.CreateUser("admin", "terminal-other-admin", "other@example.test", "admin", "Other-admin-password-12345!"); err != nil {
		t.Fatal(err)
	}
	f.login("terminal-other-admin", "Other-admin-password-12345!")
	f.refreshCSRF()
	resp, _ = f.request("GET", "/api/v1/terminal/sessions/"+id+"?after=0", nil)
	if resp.StatusCode != 404 {
		t.Fatal("other administrator read another login's terminal", resp.StatusCode)
	}
	if _, err := f.server.auth.CreateUser("admin", "terminal-viewer", "viewer@example.test", "viewer", "Viewer-password-12345!"); err != nil {
		t.Fatal(err)
	}
	f.login("terminal-viewer", "Viewer-password-12345!")
	f.refreshCSRF()
	resp, _ = f.request("GET", "/api/v1/terminal/nodes", nil)
	if resp.StatusCode != 403 {
		t.Fatal("viewer received terminal access", resp.StatusCode)
	}
	status.Generation = "restarted-generation"
	code, directives = terminalTestExchange(t, f, "terminal-node", token, protocol.TerminalExchangeRequest{Terminal: status})
	if code != 200 || len(directives.Sessions) != 0 {
		t.Fatal("restart respawned previous shell")
	}
	f.server.terminal.mu.Lock()
	if terminalActive(session) {
		t.Error("generation mismatch session active")
	}
	f.server.terminal.mu.Unlock()
}
func TestTerminalOutputMergeBoundsAndReplay(t *testing.T) {
	relay := &terminalRelay{}
	session := &terminalSession{Status: "pending", ExpiresAt: time.Now().Add(time.Minute)}
	for i := 0; i < 1000; i++ {
		start := uint64(i * 1024)
		frame := protocol.TerminalSessionUpdate{Status: "running", Start: start, Next: start + 1024, Data: bytes.Repeat([]byte("x"), 1024)}
		relay.mergeLocked(session, frame)
		relay.mergeLocked(session, frame)
	}
	if len(session.data) != terminalBuffer || session.next != 1024000 || session.start != session.next-terminalBuffer {
		t.Fatal("output buffering not bounded or replay duplicated")
	}
	relay.mergeLocked(session, protocol.TerminalSessionUpdate{Start: 0, Next: 1, Data: []byte("x")})
	if session.next != 1024000 {
		t.Fatal("old output rewound cursor")
	}
}
