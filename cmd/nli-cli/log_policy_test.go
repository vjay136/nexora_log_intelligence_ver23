package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nexora.local/nli-v20/internal/adapter"
	"nexora.local/nli-v20/internal/canonicaljson"
	"nexora.local/nli-v20/internal/logpolicy"
	"nexora.local/nli-v20/internal/quarantine"
)

func cliPolicyBundle(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0750); err != nil {
		t.Fatal(err)
	}
	var assets []adapter.RuntimeTemplateAsset
	for class, payload := range map[string]string{"selective-input": `{"config":{"enabled":true,"match_mode":"any","rules":[{"field":"event","operator":"equals","values":["SmtpServerEHLO"]}]}}`, "output-fields": `{"config":{"enabled":true,"fields":["hostname","id"]}}`} {
		raw, err := canonicaljson.Normalize([]byte(payload))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(raw)
		assets = append(assets, adapter.RuntimeTemplateAsset{AssetClass: class, AssetID: class, Revision: 1, SHA256: fmt.Sprintf("%x", digest[:]), Payload: raw})
	}
	unsigned, _ := json.Marshal(struct {
		SchemaVersion int                            `json:"schema_version"`
		Assets        []adapter.RuntimeTemplateAsset `json:"assets"`
	}{1, assets})
	digest := sha256.Sum256(unsigned)
	body, _ := json.Marshal(map[string]any{"schema_version": 1, "assets": assets, "bundle_hash": fmt.Sprintf("%x", digest[:])})
	if err := os.WriteFile(filepath.Join(dir, "bundle.json"), body, 0640); err != nil {
		t.Fatal(err)
	}
}

func TestCLILivePoliciesParseFullEnvelopeAndExcludedReplay(t *testing.T) {
	root := t.TempDir()
	assets := filepath.Join(root, "assets")
	cliPolicyBundle(t, assets)
	ehlo := "20250812 130035121+0100 aaa-gmailrgo009 smtp 3609 0 140293780948736 Note;SmtpServerEHLO(2001/4) id=6864BD5E047384C4:domain=server035.mx.internal:host=11.22.33.44"
	tls := strings.Replace(ehlo, "SmtpServerEHLO(2001/4)", "SmtpServerSTARTTLSIn(2001/39)", 1)
	input := filepath.Join(root, "input")
	_ = os.WriteFile(input, []byte(tls+"\n"+ehlo+"\n"), 0600)
	for _, full := range []bool{false, true} {
		var out strings.Builder
		if err := parseCmdWithAssets("parse", input, "smtp", "", assets, false, full, &out); err != nil {
			t.Fatal(err)
		}
		if len(strings.Split(strings.TrimSpace(out.String()), "\n")) != 1 {
			t.Fatalf("excluded input parsed: %s", out.String())
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(out.String()), &record); err != nil {
			t.Fatal(err)
		}
		if full {
			record = record["data"].(map[string]any)
		}
		if _, ok := record["hostname"]; ok {
			t.Fatal("removed hostname emitted")
		}
		if _, ok := record["id"]; ok {
			t.Fatal("removed id emitted")
		}
	}
	queue := filepath.Join(root, "quarantine.jsonl")
	queued := quarantine.New("node", "smtp", input, 1, tls, "old", 1, []string{"old"}, time.Now())
	if err := quarantine.Append(queue, queued); err != nil {
		t.Fatal(err)
	}
	config := map[string]any{"version": 2, "inputs": []any{map[string]any{"path": input, "service": "smtp"}}, "parser_asset_dir": assets, "state_dir": filepath.Join(root, "state"), "poll_ms": 50, "outputs": []any{map[string]any{"type": "file", "path": filepath.Join(root, "output.jsonl")}}, "telemetry_outputs": []any{map[string]any{"type": "discard"}}}
	data, _ := json.Marshal(config)
	cfg := filepath.Join(root, "nli.json")
	_ = os.WriteFile(cfg, data, 0600)
	var summary strings.Builder
	if err := replayQueue(queue, cfg, "", nil, &summary); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(summary.String(), `"filtered_ids"`) || strings.Contains(summary.String(), `"resolved":1`) {
		t.Fatal(summary.String())
	}
	after, err := os.ReadFile(queue)
	if err != nil {
		t.Fatal(err)
	}
	var retained quarantine.Record
	if json.Unmarshal(after, &retained) != nil || retained.ID != queued.ID || retained.AttemptCount != queued.AttemptCount {
		t.Fatalf("excluded replay lost/reclassified record %s", after)
	}
}

func TestCLIReplayPolicyEvaluationErrorRetainsQueueWithoutAttempt(t *testing.T) {
	root := t.TempDir()
	assets := filepath.Join(root, "assets")
	cliPolicyBundle(t, assets)
	queue := filepath.Join(root, "queue.jsonl")
	raw := strings.Repeat("x", logpolicy.MaxRawBytes+8)
	queued := quarantine.New("node", "smtp", "/var/log/source", 1, raw, "old", 2, []string{"old"}, time.Now())
	if err := quarantine.Append(queue, queued); err != nil {
		t.Fatal(err)
	}
	config := map[string]any{"version": 2, "inputs": []any{map[string]any{"path": filepath.Join(root, "source"), "service": "smtp"}}, "parser_asset_dir": assets, "state_dir": filepath.Join(root, "state"), "poll_ms": 50, "outputs": []any{map[string]any{"type": "file", "path": filepath.Join(root, "out.jsonl")}}, "telemetry_outputs": []any{map[string]any{"type": "discard"}}}
	data, _ := json.Marshal(config)
	path := filepath.Join(root, "nli.json")
	_ = os.WriteFile(path, data, 0600)
	var output strings.Builder
	if err := replayQueue(queue, path, "", nil, &output); err != nil {
		t.Fatal(err)
	}
	var summary replaySummary
	if json.Unmarshal([]byte(output.String()), &summary) != nil || summary.PolicyErrors != 1 || len(summary.PolicyErrorIDs) != 1 || summary.PolicyErrorIDs[0] != queued.ID || len(summary.FilteredIDs) != 0 || summary.Resolved != 0 || summary.Replayed != 0 {
		t.Fatalf("policy error mislabeled: %s", output.String())
	}
	stored, _ := os.ReadFile(queue)
	var retained quarantine.Record
	if json.Unmarshal(stored, &retained) != nil || retained.ID != queued.ID || retained.AttemptCount != queued.AttemptCount || retained.Raw != raw {
		t.Fatal("policy evaluation error changed/lost queued record")
	}
	if data, _ := os.ReadFile(filepath.Join(root, "out.jsonl")); len(data) > 0 {
		t.Fatal("policy evaluation error emitted output")
	}
}
