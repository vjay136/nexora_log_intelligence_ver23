package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"nexora.local/nli-v20/internal/fleet"
	metastore "nexora.local/nli-v20/internal/store"
)

// Reproduce the user's post-login catalogue fan-out with bounded concurrent
// clients. Each response must complete and retain its real JSON contract.
func TestR7PostLoginCatalogFanout(t *testing.T) {
	f := newAPIFixture(t)
	paths := []string{"/api/v1/artifacts", "/api/v1/rollouts", "/api/v1/fleet/sync", "/api/v1/parser-sync", "/api/v1/assurance/parsers", "/api/v1/parser-packs", "/api/v1/config/templates", "/api/v1/config/kv", "/api/v1/config/known-keys", "/api/v1/assurance/cases", "/api/v1/assurance/plans", "/api/v1/assurance/runs", "/api/v1/assurance/history", "/api/v1/assurance/ai-proposals", "/api/v1/bundle-backups", "/api/v1/bundle-restores"}
	const workers, rounds = 4, 4
	start := time.Now()
	errors := make(chan string, workers*rounds*len(paths))
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for round := 0; round < rounds; round++ {
				for _, path := range paths {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					req, _ := http.NewRequestWithContext(ctx, http.MethodGet, f.http.URL+path, nil)
					response, err := f.client.Do(req)
					if err != nil {
						errors <- fmt.Sprintf("worker %d %s: %v", worker, path, err)
						cancel()
						continue
					}
					data, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
					response.Body.Close()
					cancel()
					if err != nil || response.StatusCode != http.StatusOK || !json.Valid(data) {
						errors <- fmt.Sprintf("worker %d %s status=%d JSON=%t error=%v", worker, path, response.StatusCode, json.Valid(data), err)
					}
					if response.Header.Get("X-Request-ID") == "" {
						errors <- fmt.Sprintf("missing request ID on %s", path)
					}
				}
			}
		}(worker)
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	t.Logf("%d catalog requests across %d workers completed in %s", workers*rounds*len(paths), workers, time.Since(start))
}

func TestR7APIErrorCarriesStatusAndRequestID(t *testing.T) {
	f := newAPIFixture(t)
	response, data := f.request(http.MethodPost, "/api/v1/assurance/run", map[string]any{"raw": 42})
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid request status %d: %s", response.StatusCode, data)
	}
	result := decodeMap(t, data)
	if result["http_status"] != float64(http.StatusBadRequest) || result["request_id"] == "" || result["request_id"] != response.Header.Get("X-Request-ID") || result["retryable"] != false {
		t.Fatalf("error is not correlated or is wrongly retryable: %s", data)
	}
}

// This is controller projection/pagination load, not 1,005 live Linux agents.
// Reports past the first metadata page must remain visible and stale reports
// must never become acknowledgements of a newly published generation.
func TestR7ThousandClientAcknowledgementProjection(t *testing.T) {
	f := newAPIFixture(t)
	ctx := context.Background()
	bundle, err := f.server.buildActiveParserBundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	const count = 1005
	start := time.Now()
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("r7-client-%04d", i)
		f.server.fleet.Register(&fleet.Node{ID: id, Hostname: id, Version: "23.0.0"})
		active, status := bundle.BundleHash, "applied"
		switch i % 3 {
		case 1:
			active = strings.Repeat("a", 64)
		case 2:
			status = "failed"
		}
		payload, _ := json.Marshal(map[string]any{"node_id": id, "desired_asset_bundle_hash": bundle.BundleHash,
			"active_asset_bundle_hash": active, "asset_sync_status": status, "asset_drifted": false})
		if _, err := f.server.metadata.Put(ctx, metastore.Document{Collection: "fleet-sync", ID: id, State: "reported", CreatedBy: "load-fixture", Payload: payload}); err != nil {
			t.Fatal(err)
		}
	}
	verify := func(expected int) {
		t.Helper()
		response, data := f.request(http.MethodGet, "/api/v1/parser-sync/runtime", nil)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("large fleet runtime %d: %s", response.StatusCode, data)
		}
		body := decodeMap(t, data)
		clients, _ := body["clients"].([]any)
		if len(clients) != count {
			t.Fatalf("fleet page was truncated: %d of %d", len(clients), count)
		}
		seen, exact := map[string]bool{}, 0
		for _, item := range clients {
			client := item.(map[string]any)
			id := client["node_id"].(string)
			if seen[id] {
				t.Fatalf("duplicate client projection: %s", id)
			}
			seen[id] = true
			if client["exact_acknowledgement"] == true {
				exact++
			}
		}
		if exact != expected {
			t.Fatalf("exact acknowledgements %d, expected %d", exact, expected)
		}
	}
	verify(count / 3)
	payload := json.RawMessage(`{"name":"generation rollover","config":{"keys":["r7_new_key"]},"review_state":"active"}`)
	if _, err := f.server.metadata.Put(ctx, metastore.Document{Collection: "known-keys", ID: "r7-generation", State: "active", CreatedBy: "load-fixture", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	verify(0)
	t.Logf("%d simulated fleet records retained across pagination; new generation invalidates prior acknowledgements (%s)", count, time.Since(start))
}
