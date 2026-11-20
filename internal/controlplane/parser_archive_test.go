package controlplane

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestControllerRetainsVerifiedPriorBundleAcrossApprovedEmptyGeneration(t *testing.T) {
	f := newAPIFixture(t)
	previous, err := f.server.buildActiveParserBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.server.materializeParserBundle(previous); err != nil {
		t.Fatal(err)
	}
	empty := parserAssetBundle{SchemaVersion: 1, Assets: []parserBundleAsset{}}
	empty.BundleHash, _, err = bundleDigest(empty)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.server.materializeParserBundle(empty); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(f.state, "parser-assets-history", previous.BundleHash+".json")
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := verifyArchivedControllerBundle(data)
	if err != nil || hash != previous.BundleHash {
		t.Fatalf("archive %s %v", hash, err)
	}
	if err := os.WriteFile(archive, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = f.server.materializeParserBundle(previous); err == nil {
		t.Fatal("unsafe archive did not prevent replacement")
	}
	current, err := f.server.readMaterializedParserBundleHash()
	if err != nil || current != empty.BundleHash {
		t.Fatal("failed archive modified active generation")
	}
}

func TestCanonicalSSEKeepsControllerInstanceOnHeartbeat(t *testing.T) {
	f := newAPIFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, f.http.URL+"/api/v1/sync/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := f.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal(response.Status)
	}
	scanner := bufio.NewScanner(response.Body)
	instance, event := "", ""
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "event:") {
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		}
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		var value map[string]any
		if err := json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "data:"))), &value); err != nil {
			t.Fatal(err)
		}
		if event == "sync_snapshot" {
			instance, _ = value["controller_instance_id"].(string)
			if instance == "" {
				t.Fatal("snapshot missing controller instance")
			}
		}
		if event == "sync_heartbeat" {
			if instance == "" || value["controller_instance_id"] != instance {
				t.Fatal("heartbeat lost revision epoch")
			}
			return
		}
	}
	t.Fatalf("heartbeat not observed: %v", scanner.Err())
}

func TestControllerSyncInstanceChangesAcrossRestart(t *testing.T) {
	first := newAPIFixture(t)
	second := newAPIFixture(t)
	a := first.server.canonicalSyncSnapshot(context.Background())
	again := first.server.canonicalSyncSnapshot(context.Background())
	b := second.server.canonicalSyncSnapshot(context.Background())
	if a["controller_instance_id"] == "" || a["controller_instance_id"] != again["controller_instance_id"] || a["controller_instance_id"] == b["controller_instance_id"] {
		t.Fatal("controller revision epoch is not stable per process and unique across restarts")
	}
}
