package controlplane

import (
	"context"
	metastore "nexora.local/nli-v20/internal/store"
	"strings"
	"testing"
	"time"
)

type terminalUnavailableLabels struct{ metastore.Store }

func (s terminalUnavailableLabels) Get(ctx context.Context, c, id string, r int) (metastore.Document, error) {
	if c == clientDirectoryLabelsCollection {
		<-ctx.Done()
		return metastore.Document{}, ctx.Err()
	}
	return s.Store.Get(ctx, c, id, r)
}
func TestTerminalInventoryCloudLabelsCannotBlockNodeSelection(t *testing.T) {
	f := newAPIFixture(t)
	f.server.metadata = terminalUnavailableLabels{f.server.metadata}
	started := time.Now()
	resp, data := f.request("GET", "/api/v1/terminal/nodes", nil)
	if resp.StatusCode != 200 || !strings.Contains(string(data), `"labels_available":false`) || !strings.Contains(string(data), `"@controller"`) {
		t.Fatalf("inventory lost live identities during label outage: %d %s", resp.StatusCode, data)
	}
	if time.Since(started) > 1800*time.Millisecond {
		t.Fatal("cloud display labels blocked terminal inventory")
	}
}
