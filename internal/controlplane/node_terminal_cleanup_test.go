package controlplane

import (
	"context"
	"errors"
	"nexora.local/nli-v20/internal/protocol"
	"nexora.local/nli-v20/internal/terminalrpc"
	"sync/atomic"
	"testing"
	"time"
)

type terminalCleanupProbe struct {
	terminalBroker
	calls atomic.Int32
}

func (p *terminalCleanupProbe) Status(context.Context) (terminalrpc.Status, error) {
	return terminalrpc.Status{}, errors.New("fixture broker disabled")
}

func (p *terminalCleanupProbe) Close(context.Context, string, string) error {
	p.calls.Add(1)
	return nil
}
func TestTerminalClosedSessionCleanupIsNotRepeated(t *testing.T) {
	f := newAPIFixture(t)
	probe := &terminalCleanupProbe{}
	relay := f.server.terminal
	relay.mu.Lock()
	relay.broker = probe
	relay.sessions["closed-terminal-test"] = &terminalSession{ID: "closed-terminal-test", NodeID: "@controller", Status: "closed", closedAt: time.Now()}
	relay.mu.Unlock()
	deadline := time.Now().Add(4 * time.Second)
	for probe.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if probe.calls.Load() != 1 {
		t.Fatal("closed session was not cleaned once")
	}
	time.Sleep(1200 * time.Millisecond)
	if probe.calls.Load() != 1 {
		t.Fatal("retained closed sessions repeatedly consume broker cleanup calls")
	}
}

func TestTerminalTransportLeaseCannotBeRenewedByBrowserOrHeartbeat(t *testing.T) {
	f := newAPIFixture(t)
	token := terminalTestEnroll(t, f, "transport-lease-node")
	status := protocol.TerminalStatus{Supported: true, Enabled: true, PrivilegeMode: "operator", Generation: "same-broker-generation", MaxSessions: 4, LifetimeSeconds: 1800, IdleTimeoutSeconds: 300}
	terminalTestExchange(t, f, "transport-lease-node", token, protocol.TerminalExchangeRequest{Terminal: status})
	response, data := f.request("POST", "/api/v1/terminal/sessions", map[string]any{"node_id": "transport-lease-node", "cols": 80, "rows": 24, "password": "Admin-password-12345!", "reason": "Lost worker must not replay queued commands"})
	if response.StatusCode != 200 {
		t.Fatalf("open status %d", response.StatusCode)
	}
	id := decodeMap(t, data)["session"].(map[string]any)["id"].(string)
	f.server.terminal.mu.Lock()
	session := f.server.terminal.sessions[id]
	session.transportUntil = time.Now().Add(-time.Second)
	session.lease = time.Now().Add(time.Minute)
	session.inputs = []protocol.TerminalInput{{Sequence: 1, Data: []byte("must-never-replay\r")}}
	f.server.terminal.mu.Unlock()
	// A generic status/heartbeat must never grant a new terminal transport lease.
	f.server.terminal.observe("transport-lease-node", status)
	code, out := terminalTestExchange(t, f, "transport-lease-node", token, protocol.TerminalExchangeRequest{Terminal: status})
	if code != 200 || len(out.Sessions) != 0 {
		t.Fatal("late worker exchange revived an expired shell or queued stdin")
	}
	response, _ = f.request("POST", "/api/v1/terminal/sessions/"+id+"/input", map[string]any{"sequence": 1, "data": "echo replay\r"})
	if response.StatusCode != 409 {
		t.Fatal("expired transport accepted input")
	}
	f.server.terminal.mu.Lock()
	defer f.server.terminal.mu.Unlock()
	if terminalActive(session) || len(session.inputs) != 0 {
		t.Fatal("expired terminal retained active commands")
	}
}
