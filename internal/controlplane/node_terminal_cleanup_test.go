package controlplane

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

type terminalCleanupProbe struct {
	terminalBroker
	calls atomic.Int32
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
