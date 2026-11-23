package controlplane

import (
	"nexora.local/nli-v20/internal/fleet"
	"nexora.local/nli-v20/internal/protocol"
	"testing"
	"time"
)

func TestTerminalUnknownObservationPreservesExistingLeasesAndBlocksNewAvailability(t *testing.T) {
	f := newAPIFixture(t)
	const node = "unknown-probe-node"
	f.server.fleet.Register(&fleet.Node{ID: node, Hostname: node, LastSeen: time.Now(), Status: fleet.StatusOnline})
	// This relay has no background sweeper, so the assertions isolate observation
	// semantics. Production lease expiry remains independently covered.
	relay := &terminalRelay{s: f.server, sessions: map[string]*terminalSession{}, nodes: map[string]terminalObservation{}, access: newTerminalAccessStore(t.TempDir())}
	lease, transport := time.Now().Add(15*time.Second), time.Now().Add(15*time.Second)
	session := &terminalSession{ID: "existing", NodeID: node, Status: "running", generation: "verified-generation", lease: lease, transportUntil: transport, token: "unchanged-owner-token"}
	relay.sessions[session.ID] = session
	for _, status := range []protocol.TerminalStatus{
		{Supported: true, Reason: "Host terminal broker disabled or unavailable"},
		{Supported: true, Enabled: true}, // malformed availability is not trusted
	} {
		relay.observe(node, status)
		if session.Status != "running" || !session.lease.Equal(lease) || !session.transportUntil.Equal(transport) || session.token != "unchanged-owner-token" {
			t.Fatal("unknown probe closed the existing terminal or renewed an unverified lease")
		}
		if relay.nodes[node].status.Enabled {
			t.Fatal("unknown generation was advertised as available for a new terminal")
		}
	}
	relay.observe(node, protocol.TerminalStatus{Supported: true, Enabled: true, Generation: "verified-generation"})
	if session.Status != "running" || !relay.nodes[node].status.Enabled {
		t.Fatal("healthy observation did not recover availability")
	}
	relay.observe(node, protocol.TerminalStatus{Supported: true, Enabled: false, Generation: "verified-generation"})
	if session.Status != "closed" {
		t.Fatal("verified host disable must close immediately")
	}
	restarted := &terminalSession{ID: "restarted", NodeID: node, Status: "running", generation: "verified-generation"}
	relay.sessions[restarted.ID] = restarted
	relay.observe(node, protocol.TerminalStatus{Supported: true, Enabled: true, Generation: "new-generation"})
	if restarted.Status != "closed" {
		t.Fatal("verified broker generation change must close the old terminal")
	}
}
