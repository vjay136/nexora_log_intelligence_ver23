package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
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
