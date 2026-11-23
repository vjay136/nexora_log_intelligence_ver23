package routing

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"nexora.local/nli-v20/internal/logpolicy"
	"nexora.local/nli-v20/internal/output"
	"nexora.local/nli-v20/telemetry"
)

func TestOutputPolicyAllCustomerDestinationsAndEmptyResult(t *testing.T) {
	var mu sync.Mutex
	var lokiRecords, clickRecords, controllerRecords []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/loki/api/v1/push" {
			var payload struct {
				Streams []struct {
					Values [][]string `json:"values"`
				} `json:"streams"`
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Error(err)
			}
			for _, s := range payload.Streams {
				for _, v := range s.Values {
					lokiRecords = append(lokiRecords, v[1])
				}
			}
		} else if r.URL.Path == "/api/v1/node/events" {
			var payload struct {
				Events []json.RawMessage `json:"events"`
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Error(err)
			}
			for _, event := range payload.Events {
				controllerRecords = append(controllerRecords, string(event))
			}
		} else if strings.HasPrefix(r.URL.Query().Get("query"), "INSERT") {
			for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
				var row map[string]any
				if err := json.Unmarshal([]byte(line), &row); err != nil {
					t.Error(err)
				}
				clickRecords = append(clickRecords, row["event_json"].(string))
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	root := t.TempDir()
	file := filepath.Join(root, "out.jsonl")
	meta := filepath.Join(root, "meta.jsonl")
	token := filepath.Join(root, "token")
	if err := os.WriteFile(token, []byte("test-local-token"), 0600); err != nil {
		t.Fatal(err)
	}
	router, err := NewV5Router([]output.Config{{Type: "file", Path: file}, {Type: "loki", URL: server.URL + "/loki/api/v1/push", BatchSize: 1, Required: true}, {Type: "clickhouse", URL: server.URL, Database: "default", Table: "logs", BatchSize: 1, Required: true}, {Type: "controller", URL: server.URL, NodeID: "node", TokenFile: token, BatchSize: 1, Required: true}}, []output.Config{{Type: "file", Path: meta}})
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	policy, err := logpolicy.Compile(nil, []logpolicy.OutputConfig{{Enabled: true, Fields: []string{"hostname", "id"}}})
	if err != nil {
		t.Fatal(err)
	}
	router.SetOutputPolicy(policy)
	for _, fields := range []map[string]any{{"hostname": "origin", "id": "secret", "event": "EHLO"}, {"hostname": "origin", "id": "secret"}} {
		metadata := telemetry.NewParseTelemetry("internal raw unchanged", "origin")
		if err := router.RouteV5(&V5ParseResult{EventPayload: &telemetry.EventPayload{Fields: fields}, ParseTelemetry: metadata, Success: true}); err != nil {
			t.Fatal(err)
		}
		if fields["hostname"] != "origin" || fields["id"] != "secret" {
			t.Fatal("policy mutated parser evidence")
		}
	}
	if err := router.Flush(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	records := strings.Split(strings.TrimSpace(string(data)), "\n")
	mu.Lock()
	defer mu.Unlock()
	for name, values := range map[string][]string{"file": records, "loki": lokiRecords, "clickhouse": clickRecords, "controller": controllerRecords} {
		if len(values) != 2 {
			t.Fatalf("%s received %d records", name, len(values))
		}
		for i, line := range values {
			var record map[string]any
			if json.Unmarshal([]byte(line), &record) != nil {
				t.Fatal("invalid output")
			}
			if _, ok := record["hostname"]; ok {
				t.Fatalf("%s leaked hostname", name)
			}
			if _, ok := record["id"]; ok {
				t.Fatalf("%s leaked id", name)
			}
			if i == 1 && len(record) != 0 {
				t.Fatalf("all-field removal failed %s", line)
			}
		}
	}
	metadata, _ := os.ReadFile(meta)
	if !strings.Contains(string(metadata), `"node_id":"origin"`) {
		t.Fatal("customer policy removed internal telemetry")
	}
}
