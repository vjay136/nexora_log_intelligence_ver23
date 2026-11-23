package controlclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"nexora.local/nli-v20/internal/nodeterminal"
	"nexora.local/nli-v20/internal/protocol"
	"nexora.local/nli-v20/internal/terminalrpc"
)

func TestTerminalRelayEndedHistoryExpiresAfterSafeHour(t *testing.T) {
	f := &fakeTerminalBroker{states: map[string]nodeterminal.State{}}
	relay := newTerminalRelay(f)
	now := time.Now()
	for i := 0; i < 4096; i++ {
		id := fmt.Sprintf("ended-terminal-%04d", i)
		relay.markDead(id)
		relay.deadAt[id] = now.Add(-59 * time.Minute)
	}
	response := protocol.TerminalExchangeResponse{Sessions: []protocol.TerminalSessionDirective{{ID: "fresh-terminal-session", Cols: 80, Rows: 24}}}
	relay.apply(context.Background(), response)
	if len(relay.owned) != 0 {
		t.Fatal("recent ended-session history cap did not fail closed")
	}
	for id := range relay.deadAt {
		relay.deadAt[id] = now.Add(-time.Hour - time.Second)
	}
	relay.apply(context.Background(), response)
	if len(relay.dead) != 0 || len(relay.owned) != 1 {
		t.Fatal("expired history blocked fresh session")
	}
	if _, ok := relay.owned["fresh-terminal-session"]; !ok {
		t.Fatal("fresh session requires service restart")
	}
}

func TestTerminalHeartbeatFallbackPreservesExistingCapabilities(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/node/heartbeat" {
			t.Error("unexpected endpoint", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		calls++
		if calls == 1 {
			if body["terminal"] == nil {
				t.Error("terminal not advertised")
			}
			w.WriteHeader(400)
			return
		}
		if body["terminal"] != nil {
			t.Error("unsupported terminal advertisement repeated")
		}
		if body["release_id"] == nil {
			t.Error("R9 capabilities stripped because only terminal was unsupported")
		}
		_, _ = w.Write([]byte(`{"terminal_supported":false}`))
	}))
	defer server.Close()
	dir := t.TempDir()
	c := &Client{http: server.Client(), nodeID: "test-node", token: "node-token", cfg: Config{ControllerURL: server.URL, ParserDir: dir, AssetDir: dir, AgentConfigPath: dir + "/missing", MetricsURL: "http://127.0.0.1:1/metrics"}}
	if err := c.heartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.heartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 3 || c.terminalSupported.Load() || !c.terminalNegotiated.Load() {
		t.Fatal("old controller capability negotiation failed")
	}
}

type fakeTerminalBroker struct {
	states             map[string]nodeterminal.State
	writes, closed     []string
	readErr, resizeErr error
}

func (f *fakeTerminalBroker) Status(context.Context) (terminalrpc.Status, error) {
	return terminalrpc.Status{Enabled: true, Generation: "one"}, nil
}
func (f *fakeTerminalBroker) Open(_ context.Context, id string, _, _ uint16) (nodeterminal.State, error) {
	s := f.states[id]
	s.ID = id
	f.states[id] = s
	return s, nil
}
func (f *fakeTerminalBroker) Input(_ context.Context, id string, seq uint64, data []byte) (uint64, error) {
	s := f.states[id]
	if seq != s.InputAck+1 {
		return s.InputAck, errors.New("sequence")
	}
	s.InputAck = seq
	f.states[id] = s
	f.writes = append(f.writes, string(data))
	return seq, nil
}
func (f *fakeTerminalBroker) Resize(context.Context, string, uint16, uint16) error {
	return f.resizeErr
}
func (f *fakeTerminalBroker) Read(_ context.Context, id string, after uint64, _ int) (nodeterminal.Output, error) {
	if f.readErr != nil {
		return nodeterminal.Output{}, f.readErr
	}
	return nodeterminal.Output{State: f.states[id], Start: after, Next: after + 3, Data: []byte("out")}, nil
}
func (f *fakeTerminalBroker) Close(_ context.Context, id, _ string) error {
	f.closed = append(f.closed, id)
	return nil
}
func TestTerminalRelayDoesNotReplayInputOrCloseLocalSessions(t *testing.T) {
	ctx := context.Background()
	f := &fakeTerminalBroker{states: map[string]nodeterminal.State{"controller-local-session": {}}}
	r := newTerminalRelay(f)
	d := protocol.TerminalSessionDirective{ID: "client-session-0001", Cols: 80, Rows: 24, Inputs: []protocol.TerminalInput{{Sequence: 1, Data: []byte("dangerous-command\r")}}}
	response := protocol.TerminalExchangeResponse{Sessions: []protocol.TerminalSessionDirective{d}}
	r.apply(ctx, response)
	r.apply(ctx, response)
	if len(f.writes) != 1 {
		t.Fatalf("input replayed %d times", len(f.writes))
	}
	r.apply(ctx, protocol.TerminalExchangeResponse{})
	if len(f.closed) != 1 || f.closed[0] != d.ID {
		t.Fatalf("closed non-owned sessions: %v", f.closed)
	}
	r.apply(ctx, response)
	if len(f.writes) != 1 || len(r.owned) != 0 {
		t.Fatal("ended session reopened")
	}
}
func TestTerminalRelayGenerationAndCursor(t *testing.T) {
	f := &fakeTerminalBroker{states: map[string]nodeterminal.State{}}
	r := newTerminalRelay(f)
	ctx := context.Background()
	r.snapshot(ctx, terminalrpc.Status{Generation: "first"})
	r.apply(ctx, protocol.TerminalExchangeResponse{Sessions: []protocol.TerminalSessionDirective{{ID: "client-session-0001", After: 17}}})
	out := r.snapshot(ctx, terminalrpc.Status{Generation: "first"})
	if len(out) != 1 || out[0].Start != 17 {
		t.Fatal("output acknowledgement not honored")
	}
	r.snapshot(ctx, terminalrpc.Status{Generation: "restarted"})
	if len(r.owned) != 0 || len(f.closed) != 1 {
		t.Fatal("broker restart retained shell")
	}
}
func TestTerminalExchangeUsesAuthenticatedNodeAndBounds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/node/terminal/exchange" || r.Header.Get("Authorization") != "Bearer secret-node-token" || r.Header.Get("X-NLI-Node-ID") != "node-a" {
			t.Error("node authentication missing")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sessions":[],"poll_after_ms":250}`))
	}))
	defer server.Close()
	c := &Client{cfg: Config{ControllerURL: server.URL}, http: server.Client(), nodeID: "node-a", token: "secret-node-token"}
	if _, err := c.exchangeTerminal(context.Background(), terminalrpc.Status{}, nil); err != nil {
		t.Fatal(err)
	}
	c.token = ""
	if _, err := c.exchangeTerminal(context.Background(), terminalrpc.Status{}, nil); err == nil {
		t.Fatal("missing enrollment accepted")
	}
}

func TestTerminalTransientStatusProbeKeepsExistingSessionWithoutOpeningOrReplaying(t *testing.T) {
	ctx := context.Background()
	f := &fakeTerminalBroker{states: map[string]nodeterminal.State{}}
	r := newTerminalRelay(f)
	r.owned["existing"] = protocol.TerminalSessionDirective{ID: "existing"}
	r.lastSuccess = time.Now()
	if r.brokerReady(ctx, terminalrpc.Status{}, context.DeadlineExceeded, true) {
		t.Fatal("unverified broker status must not admit operations")
	}
	if len(r.owned) != 1 || len(f.closed) != 0 || len(f.writes) != 0 || len(f.states) != 0 {
		t.Fatal("one transient status timeout changed the session or replayed input")
	}
	if !r.brokerReady(ctx, terminalrpc.Status{Enabled: true}, nil, true) {
		t.Fatal("healthy broker did not recover inside the existing grace")
	}
	r.lastSuccess = time.Now().Add(-11 * time.Second)
	if r.brokerReady(ctx, terminalrpc.Status{}, context.DeadlineExceeded, true) || len(r.owned) != 0 || len(f.closed) != 1 {
		t.Fatal("persistent broker failure did not close the session within the transport grace")
	}
}

func TestTerminalExplicitDisableAndCapabilityRevocationBypassProbeGrace(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    terminalrpc.Status
		err       error
		supported bool
	}{
		{"host disabled", terminalrpc.Status{Enabled: false}, nil, true},
		{"capability revoked", terminalrpc.Status{Enabled: true}, nil, false},
		{"capability revoked with probe failure", terminalrpc.Status{}, context.DeadlineExceeded, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeTerminalBroker{states: map[string]nodeterminal.State{}}
			r := newTerminalRelay(f)
			r.owned["existing"] = protocol.TerminalSessionDirective{ID: "existing"}
			r.lastSuccess = time.Now()
			if r.brokerReady(context.Background(), tc.status, tc.err, tc.supported) || len(r.owned) != 0 || len(f.closed) != 1 {
				t.Fatal("explicit disable/revocation must close without waiting for transient-error grace")
			}
		})
	}
}

func TestTerminalTransientReadAndResizeDoNotReplayOrReopen(t *testing.T) {
	for _, operation := range []string{"read", "resize"} {
		t.Run(operation, func(t *testing.T) {
			ctx := context.Background()
			f := &fakeTerminalBroker{states: map[string]nodeterminal.State{}}
			r := newTerminalRelay(f)
			d := protocol.TerminalSessionDirective{ID: "existing", Cols: 80, Rows: 24, Inputs: []protocol.TerminalInput{{Sequence: 1, Data: []byte("once\n")}}}
			r.owned[d.ID] = d
			if operation == "read" {
				f.readErr = context.DeadlineExceeded
			} else {
				f.resizeErr = context.DeadlineExceeded
			}
			response := protocol.TerminalExchangeResponse{Sessions: []protocol.TerminalSessionDirective{d}}
			r.apply(ctx, response)
			if len(r.owned) != 1 || len(f.writes) != 0 || len(f.closed) != 0 || len(f.states) != 0 || r.dead[d.ID] {
				t.Fatal("transient probe executed input, reopened or closed an existing shell")
			}
			f.readErr, f.resizeErr = nil, nil
			r.apply(ctx, response)
			r.apply(ctx, response)
			if len(f.writes) != 1 || len(r.probeFailed) != 0 {
				t.Fatal("recovery did not deliver exactly once and clear the probe failure")
			}
			if operation == "read" {
				f.readErr = context.DeadlineExceeded
			} else {
				f.resizeErr = context.DeadlineExceeded
			}
			r.probeFailed[d.ID] = time.Now().Add(-11 * time.Second)
			r.snapshot(ctx, terminalrpc.Status{})
			r.apply(ctx, response)
			if len(r.owned) != 0 || !r.dead[d.ID] || len(f.closed) != 1 {
				t.Fatal("persistent probe failure did not close and tombstone the session")
			}
		})
	}
}

func TestTerminalAmbiguousStdinStillClosesWithoutProbeGrace(t *testing.T) {
	f := &fakeTerminalBroker{states: map[string]nodeterminal.State{}}
	r := newTerminalRelay(f)
	d := protocol.TerminalSessionDirective{ID: "existing", Cols: 80, Rows: 24, Inputs: []protocol.TerminalInput{{Sequence: 2, Data: []byte("never-retry\n")}}}
	r.owned[d.ID] = d
	r.apply(context.Background(), protocol.TerminalExchangeResponse{Sessions: []protocol.TerminalSessionDirective{d}})
	if len(r.owned) != 0 || !r.dead[d.ID] || len(f.closed) != 1 || len(f.writes) != 0 {
		t.Fatal("stdin failure incorrectly received read-only probe grace")
	}
}
