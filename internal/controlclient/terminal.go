package controlclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"nexora.local/nli-v20/internal/nodeterminal"
	"nexora.local/nli-v20/internal/protocol"
	"nexora.local/nli-v20/internal/terminalrpc"
)

type terminalBroker interface {
	Status(context.Context) (terminalrpc.Status, error)
	Open(context.Context, string, uint16, uint16) (nodeterminal.State, error)
	Input(context.Context, string, uint64, []byte) (uint64, error)
	Resize(context.Context, string, uint16, uint16) error
	Read(context.Context, string, uint64, int) (nodeterminal.Output, error)
	Close(context.Context, string, string) error
}

func terminalStatus(s terminalrpc.Status) protocol.TerminalStatus {
	return protocol.TerminalStatus{Supported: s.Supported, Enabled: s.Enabled, PrivilegeMode: s.PrivilegeMode, Generation: s.Generation, Reason: s.Reason, MaxSessions: s.MaxSessions, IdleTimeoutSeconds: s.IdleTimeoutSeconds, LifetimeSeconds: s.LifetimeSeconds}
}
func (c *Client) localTerminalStatus(ctx context.Context) protocol.TerminalStatus {
	ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	status, err := terminalrpc.NewClient("").Status(ctx)
	if err != nil {
		return protocol.TerminalStatus{Supported: true, Reason: "Host terminal broker disabled or unavailable"}
	}
	return terminalStatus(status)
}

// relay holds only ephemeral state. It owns exactly its remote client sessions,
// never controller-local sessions sharing the same host broker.
type terminalRelay struct {
	broker      terminalBroker
	generation  string
	owned       map[string]protocol.TerminalSessionDirective
	dead        map[string]bool
	deadAt      map[string]time.Time
	pending     []protocol.TerminalSessionUpdate
	lastSuccess time.Time
}

func newTerminalRelay(b terminalBroker) *terminalRelay {
	return &terminalRelay{broker: b, owned: map[string]protocol.TerminalSessionDirective{}, dead: map[string]bool{}, deadAt: map[string]time.Time{}}
}

// The controller expires sessions within thirty minutes. An hour of replay
// tombstones outlives every valid session and transport retry while allowing a
// long-running sidecar to reclaim ended-session IDs without persisting history.
func (r *terminalRelay) markDead(id string) { r.dead[id] = true; r.deadAt[id] = time.Now() }
func (r *terminalRelay) pruneDead(now time.Time) {
	for id, at := range r.deadAt {
		if now.Sub(at) > time.Hour {
			delete(r.dead, id)
			delete(r.deadAt, id)
		}
	}
}
func (r *terminalRelay) closeAll(ctx context.Context) {
	for id := range r.owned {
		_ = r.broker.Close(ctx, id, "terminal connection ended")
		r.markDead(id)
		delete(r.owned, id)
	}
}
func (r *terminalRelay) snapshot(ctx context.Context, status terminalrpc.Status) []protocol.TerminalSessionUpdate {
	r.pruneDead(time.Now())
	if r.generation != "" && r.generation != status.Generation {
		r.closeAll(ctx)
	}
	r.generation = status.Generation
	updates := append([]protocol.TerminalSessionUpdate(nil), r.pending...)
	for id, d := range r.owned {
		out, err := r.broker.Read(ctx, id, d.After, 64<<10)
		if err != nil {
			updates = append(updates, protocol.TerminalSessionUpdate{ID: id, Status: "closed", Reason: "Local terminal became unavailable"})
			r.markDead(id)
			delete(r.owned, id)
			continue
		}
		state := "running"
		if out.Closed || out.Closing {
			state = "closed"
		}
		updates = append(updates, protocol.TerminalSessionUpdate{ID: id, Status: state, Reason: out.Reason, Start: out.Start, Next: out.Next, Data: out.Data, Truncated: out.Truncated, AckedInput: out.InputAck, ExitCode: out.ExitCode})
	}
	return updates
}
func (r *terminalRelay) apply(ctx context.Context, response protocol.TerminalExchangeResponse) {
	r.pruneDead(time.Now())
	r.pending = nil
	desired := map[string]bool{}
	for _, d := range response.Sessions {
		desired[d.ID] = true
		if d.Close {
			_ = r.broker.Close(ctx, d.ID, "remote session closed")
			delete(r.owned, d.ID)
			r.markDead(d.ID)
			continue
		}
		if r.dead[d.ID] {
			r.pending = append(r.pending, protocol.TerminalSessionUpdate{ID: d.ID, Status: "closed", Reason: "Terminal session ended; reconnect with a new session"})
			continue
		}
		if _, owned := r.owned[d.ID]; !owned && len(r.dead) >= 4096 {
			r.pending = append(r.pending, protocol.TerminalSessionUpdate{ID: d.ID, Status: "closed", Reason: "Terminal relay session history limit reached; retry after older sessions expire"})
			continue
		}
		var state nodeterminal.State
		var err error
		if _, owned := r.owned[d.ID]; owned {
			var output nodeterminal.Output
			output, err = r.broker.Read(ctx, d.ID, d.After, 1)
			state = output.State
		} else {
			state, err = r.broker.Open(ctx, d.ID, d.Cols, d.Rows)
		}
		if err == nil && !state.Closed && !state.Closing {
			err = r.broker.Resize(ctx, d.ID, d.Cols, d.Rows)
		}
		if err == nil && !state.Closed && !state.Closing {
			for _, input := range d.Inputs {
				if input.Sequence <= state.InputAck {
					continue
				}
				state.InputAck, err = r.broker.Input(ctx, d.ID, input.Sequence, input.Data)
				if err != nil {
					break
				}
			}
		}
		if err != nil {
			_ = r.broker.Close(ctx, d.ID, "terminal operation rejected")
			delete(r.owned, d.ID)
			r.markDead(d.ID)
			r.pending = append(r.pending, protocol.TerminalSessionUpdate{ID: d.ID, Status: "closed", Reason: "Terminal operation rejected by host policy"})
			continue
		}
		r.owned[d.ID] = d
	}
	for id := range r.owned {
		if !desired[id] {
			_ = r.broker.Close(ctx, id, "remote session removed")
			delete(r.owned, id)
			r.markDead(id)
		}
	}
	r.lastSuccess = time.Now()
}

func (c *Client) exchangeTerminal(ctx context.Context, status terminalrpc.Status, updates []protocol.TerminalSessionUpdate) (protocol.TerminalExchangeResponse, error) {
	var result protocol.TerminalExchangeResponse
	c.mu.Lock()
	nodeID, token := c.nodeID, c.token
	c.mu.Unlock()
	if nodeID == "" || token == "" {
		return result, errors.New("node enrollment pending")
	}
	data, err := json.Marshal(protocol.TerminalExchangeRequest{NodeID: nodeID, Terminal: terminalStatus(status), Sessions: updates})
	if err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.ControllerURL+"/api/v1/node/terminal/exchange", bytes.NewReader(data))
	if err != nil {
		return result, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return result, errors.New("terminal relay unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return result, errors.New("terminal relay request rejected")
	}
	reader := io.LimitReader(response.Body, 1<<20)
	if err = json.NewDecoder(reader).Decode(&result); err != nil {
		return result, errors.New("invalid terminal relay response")
	}
	if len(result.Sessions) > 16 {
		return result, errors.New("terminal relay session limit exceeded")
	}
	return result, nil
}
func (c *Client) runTerminalWorker(ctx context.Context) {
	broker := terminalrpc.NewClient("")
	relay := newTerminalRelay(broker)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		relay.closeAll(cleanup)
	}()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		delay := telemetryJitter(15 * time.Second)
		statusCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		status, err := broker.Status(statusCtx)
		cancel()
		if !c.terminalSupported.Load() || err != nil || !status.Enabled {
			if len(relay.owned) > 0 {
				relay.closeAll(ctx)
			}
			timer.Reset(delay)
			continue
		}
		updates := relay.snapshot(ctx, status)
		response, err := c.exchangeTerminal(ctx, status, updates)
		if err == nil {
			relay.apply(ctx, response)
		} else if !relay.lastSuccess.IsZero() && time.Since(relay.lastSuccess) >= 10*time.Second {
			relay.closeAll(ctx)
		}
		if len(relay.owned) > 0 || len(relay.pending) > 0 {
			delay = 350 * time.Millisecond
			if response.PollAfterMS >= 350 && response.PollAfterMS <= 1000 {
				delay = time.Duration(response.PollAfterMS) * time.Millisecond
			}
		}
		timer.Reset(delay)
	}
}
