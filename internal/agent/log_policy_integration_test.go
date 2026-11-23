package agent

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"nexora.local/nli-v20/internal/adapter"
	"nexora.local/nli-v20/internal/canonicaljson"
	"nexora.local/nli-v20/internal/logpolicy"
	"nexora.local/nli-v20/internal/multiline"
	"nexora.local/nli-v20/internal/output"
)

var policySamples = []string{
	"20250812 130035121+0100 aaa-gmailrgo009 smtp 3609 0 140293780948736 Note;SmtpServerSTARTTLSIn(2001/39) id=6864BD5E047384C4:tls=TLSv1.2:cipher=ECDHE-RSA-AES256-GCM-SHA384",
	"20250812 130035121+0100 aaa-gmailrgo009 smtp 3609 0 140293780948736 Note;SmtpServerEHLO(2001/4) id=6864BD5E047384C4:domain=server035.mx.internal:host=11.22.33.44",
	"20250812 130035122+0100 aaa-gmailrgo009 smtp 3609 0 140293768701696 Note;SmtpServerSTARTTLSIn(2001/39) id=6864BD5E047384C3:tls=TLSv1.2:cipher=ECDHE-RSA-AES256-GCM-SHA384",
}

func writePolicyBundle(t *testing.T, dir string, input logpolicy.InputConfig, outputConfig logpolicy.OutputConfig) {
	t.Helper()
	if err := os.MkdirAll(dir, 0750); err != nil {
		t.Fatal(err)
	}
	assets := []adapter.RuntimeTemplateAsset{}
	for i, entry := range []struct {
		class  string
		config any
	}{{"selective-input", input}, {"output-fields", outputConfig}} {
		payload, _ := json.Marshal(map[string]any{"config": entry.config})
		payload, _ = canonicaljson.Normalize(payload)
		sum := sha256.Sum256(payload)
		assets = append(assets, adapter.RuntimeTemplateAsset{AssetClass: entry.class, AssetID: entry.class, Name: entry.class, Revision: i + 1, SHA256: hex.EncodeToString(sum[:]), Payload: payload})
	}
	unsigned, _ := json.Marshal(struct {
		SchemaVersion int                            `json:"schema_version"`
		Assets        []adapter.RuntimeTemplateAsset `json:"assets"`
	}{1, assets})
	digest := sha256.Sum256(unsigned)
	encoded, _ := json.Marshal(map[string]any{"schema_version": 1, "assets": assets, "bundle_hash": hex.EncodeToString(digest[:])})
	if err := os.WriteFile(filepath.Join(dir, "bundle.json"), encoded, 0640); err != nil {
		t.Fatal(err)
	}
}
func policyInput() logpolicy.InputConfig {
	return logpolicy.InputConfig{Enabled: true, MatchMode: "all", Rules: []logpolicy.Rule{{Field: "event", Operator: "equals", Values: []string{"SmtpServerEHLO"}}}}
}
func TestAgentSelectiveInputBeforeParserAndOutputRemovalAfterParse(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "v5", true: "legacy-output"}[legacy], func(t *testing.T) {
			root := t.TempDir()
			input := filepath.Join(root, "input.log")
			events := filepath.Join(root, "events.jsonl")
			meta := filepath.Join(root, "meta.jsonl")
			if err := os.WriteFile(input, []byte(strings.Join(policySamples, "\n")+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			cfg := Config{Inputs: []InputConfig{{Path: input, Service: "smtp"}}, PollMS: 50, StateDir: filepath.Join(root, "state"), ParserAssetDir: filepath.Join(root, "assets"), EnableLegacyRouting: legacy, Outputs: []output.Config{{Type: "file", Path: events, Routes: []string{"normal", "warning"}}}, TelemetryOutputs: []output.Config{{Type: "file", Path: meta}}}
			writePolicyBundle(t, cfg.ParserAssetDir, policyInput(), logpolicy.OutputConfig{Enabled: true, Fields: []string{"id", "hostname"}})
			if err := Run(context.Background(), cfg, true); err != nil {
				t.Fatal(err)
			}
			encoded, err := os.ReadFile(events)
			if err != nil {
				t.Fatal(err)
			}
			if len(strings.Split(strings.TrimSpace(string(encoded)), "\n")) != 1 {
				t.Fatalf("nonmatches reached output: %s", encoded)
			}
			var actual map[string]any
			if json.Unmarshal(encoded, &actual) != nil {
				t.Fatal("notJSON")
			}
			if legacy {
				actual = actual["data"].(map[string]any)
			}
			if _, ok := actual["id"]; ok {
				t.Fatal("removed id leaked")
			}
			if _, ok := actual["hostname"]; ok {
				t.Fatal("removed hostname leaked")
			}
			if !strings.Contains(string(encoded), "SmtpServerEHLO") || strings.Contains(string(encoded), "STARTTLSIn") {
				t.Fatalf("wrongselectedrecord: %s", encoded)
			}
			before := string(encoded)
			if err := Run(context.Background(), cfg, true); err != nil {
				t.Fatal(err)
			}
			after, _ := os.ReadFile(events)
			if string(after) != before {
				t.Fatal("excluded/read cursor caused replay after restart")
			}
			if data, _ := os.ReadFile(filepath.Join(cfg.StateDir, "quarantine", "records.jsonl")); len(data) > 0 {
				t.Fatalf("selectively excluded records retained in quarantine: %s", data)
			}
			// A later disabled generation admits newly arriving records while
			// previously excluded cursor positions remain acknowledged.
			writePolicyBundle(t, cfg.ParserAssetDir, logpolicy.InputConfig{MatchMode: "any"}, logpolicy.OutputConfig{})
			appendFile, err := os.OpenFile(input, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			_, writeErr := appendFile.WriteString(policySamples[0] + "\n")
			closeErr := appendFile.Close()
			if writeErr != nil || closeErr != nil {
				t.Fatalf("append: %v %v", writeErr, closeErr)
			}
			if err := Run(context.Background(), cfg, true); err != nil {
				t.Fatal(err)
			}
			after, _ = os.ReadFile(events)
			lines := strings.Split(strings.TrimSpace(string(after)), "\n")
			if len(lines) != 2 || !strings.Contains(lines[1], "STARTTLSIn") || !strings.Contains(lines[1], `"id"`) {
				t.Fatalf("disabled generation did not restore R8 admission/output without replay: %s", after)
			}
		})
	}
}
func TestAgentPolicyDisableRestoresR8AndInvalidPolicyDoesNotConsumeInput(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "input.log")
	eventPath := filepath.Join(root, "out.jsonl")
	_ = os.WriteFile(path, []byte(strings.Join(policySamples, "\n")+"\n"), 0600)
	cfg := Config{Inputs: []InputConfig{{Path: path, Service: "smtp"}}, PollMS: 50, StateDir: filepath.Join(root, "state"), ParserAssetDir: filepath.Join(root, "assets"), Outputs: []output.Config{{Type: "file", Path: eventPath}}, TelemetryOutputs: []output.Config{{Type: "discard"}}}
	bad := policyInput()
	bad.Rules = nil
	writePolicyBundle(t, cfg.ParserAssetDir, bad, logpolicy.OutputConfig{})
	if err := Run(context.Background(), cfg, true); err == nil {
		t.Fatal("invalidpolicyaccepted")
	}
	if _, err := os.Stat(filepath.Join(cfg.StateDir, "offsets.json")); err == nil {
		t.Fatal("invalidpolicyconsumedinput")
	}
	writePolicyBundle(t, cfg.ParserAssetDir, logpolicy.InputConfig{MatchMode: "any"}, logpolicy.OutputConfig{})
	if err := Run(context.Background(), cfg, true); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(eventPath)
	if len(strings.Split(strings.TrimSpace(string(data)), "\n")) != 3 {
		t.Fatalf("disabledpolicychangedR8output: %s", data)
	}
}
func TestAgentMillionSelectiveFileReadAndCapturedCustomerOutputs(t *testing.T) {
	if os.Getenv("NLI_POLICY_MILLION") != "1" {
		t.Skip("opt-in million-record file framing/parser/captured-output stress")
	}
	root := t.TempDir()
	var inputs []InputConfig
	var files []*os.File
	var writers []*bufio.Writer
	for shard := 0; shard < 4; shard++ {
		path := filepath.Join(root, fmt.Sprintf("input-%d.log", shard))
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, InputConfig{Path: path, Service: "smtp"})
		files = append(files, f)
		writers = append(writers, bufio.NewWriterSize(f, 1<<20))
	}
	for i := 0; i < 1000000; i++ {
		if _, err := writers[i%4].WriteString(policySamples[i%3] + "\n"); err != nil {
			t.Fatal(err)
		}
	}
	for shard := range files {
		if err := writers[shard].Flush(); err != nil {
			t.Fatal(err)
		}
		if err := files[shard].Close(); err != nil {
			t.Fatal(err)
		}
	}
	captured := &policyCheckingWriter{}
	cfg := Config{Inputs: inputs, SourceWorkers: 4, PollMS: 50, StateDir: filepath.Join(root, "state"), ParserAssetDir: filepath.Join(root, "assets"), Outputs: []output.Config{{Type: "captured", Writer: captured, Routes: []string{"normal"}}}, TelemetryOutputs: []output.Config{{Type: "discard"}}, SourceBatchLines: 10000}
	writePolicyBundle(t, cfg.ParserAssetDir, policyInput(), logpolicy.OutputConfig{Enabled: true, Fields: []string{"id", "hostname"}})
	start := time.Now()
	if err := Run(context.Background(), cfg, true); err != nil {
		t.Fatal(err)
	}
	if captured.count.Load() != 333333 {
		t.Fatalf("outputs %d expected333333", captured.count.Load())
	}
	t.Logf("1000000 physical lines in four 250000-record input files with SourceWorkers=4 file-framed and selected; 333333 parsed customer JSON records verified by captured writer; 666667 excluded before parser; elapsed=%s (not durable sink throughput)", time.Since(start))
}

type policyCheckingWriter struct{ count atomic.Uint64 }

func (w *policyCheckingWriter) Close() error { return nil }
func (w *policyCheckingWriter) Write(record []byte, route string) error {
	var fields map[string]any
	if err := json.Unmarshal(record, &fields); err != nil {
		return err
	}
	if fields["event"] != "SmtpServerEHLO(2001/4)" && fields["event"] != "SmtpServerEHLO" {
		return fmt.Errorf("incorrect selected event %v", fields)
	}
	if _, ok := fields["id"]; ok {
		return fmt.Errorf("removed id leaked")
	}
	if _, ok := fields["hostname"]; ok {
		return fmt.Errorf("removed hostname leaked")
	}
	if fields["domain"] != "server035.mx.internal" || fields["host"] != "11.22.33.44" {
		return fmt.Errorf("customer values wrong %v", fields)
	}
	w.count.Add(1)
	return nil
}

func TestActiveInputPolicyOversizedRecordNeverReachesQuarantineOrCustomer(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "oversized.log")
	events := filepath.Join(root, "events.jsonl")
	if err := os.WriteFile(input, []byte(strings.Repeat("x", logpolicy.MaxRawBytes+128)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{PollMS: 50, Inputs: []InputConfig{{Path: input, Service: "smtp"}}, StateDir: filepath.Join(root, "state"), ParserAssetDir: filepath.Join(root, "assets"), Outputs: []output.Config{{Type: "file", Path: events}}, TelemetryOutputs: []output.Config{{Type: "discard"}}}
	writePolicyBundle(t, cfg.ParserAssetDir, policyInput(), logpolicy.OutputConfig{})
	for i := 0; i < 2; i++ {
		if err := Run(context.Background(), cfg, true); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{events, filepath.Join(cfg.StateDir, "quarantine", "records.jsonl")} {
		if data, _ := os.ReadFile(path); len(data) != 0 {
			t.Fatalf("unevaluated input leaked to %s", path)
		}
	}
	data, err := os.ReadFile(filepath.Join(cfg.StateDir, "offsets.json"))
	if err != nil {
		t.Fatal(err)
	}
	var states map[string]cursor
	if json.Unmarshal(data, &states) != nil || states[input].Line != 1 {
		t.Fatalf("excluded record not checkpointed: %s", data)
	}
}

func TestInputPolicyRunsAfterLogicalMultilineAssembly(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "pretty.jsonl")
	events := filepath.Join(root, "out.jsonl")
	raw := "{\n  \"hostname\":\"origin\",\n  \"event\":\"selected\",\n  \"message\":\"literal continuation marker\"\n }\n{\"event\":\"excluded\",\"message\":\"other\"}\n"
	if err := os.WriteFile(input, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{PollMS: 50, Inputs: []InputConfig{{Path: input, Service: "auto", Multiline: multiline.Config{Enabled: true, Rules: []string{"generic_continuation"}}}}, StateDir: filepath.Join(root, "state"), ParserAssetDir: filepath.Join(root, "assets"), Outputs: []output.Config{{Type: "file", Path: events}}, TelemetryOutputs: []output.Config{{Type: "discard"}}}
	policy := logpolicy.InputConfig{Enabled: true, MatchMode: "all", Rules: []logpolicy.Rule{{Field: "keyword", Operator: "contains", Values: []string{"literal continuation marker"}}}}
	writePolicyBundle(t, cfg.ParserAssetDir, policy, logpolicy.OutputConfig{Enabled: true, Fields: []string{"hostname"}})
	if err := Run(context.Background(), cfg, true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if json.Unmarshal(data, &fields) != nil || fields["event"] != "selected" || fields["message"] != "literal continuation marker" {
		t.Fatalf("logical record was not selected as a whole: %s", data)
	}
	if _, ok := fields["hostname"]; ok {
		t.Fatal("hostname reintroduced")
	}
}

func TestExcludedCompletedMultilinePrefixCheckpointsBeforePendingRecord(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "input.jsonl")
	events := filepath.Join(root, "out.jsonl")
	first := "{\"event\":\"excluded\"}\n"
	second := "{\"event\":\"pending\"}\n"
	if err := os.WriteFile(input, []byte(first+second), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{PollMS: 10, Inputs: []InputConfig{{Path: input, Service: "auto", Multiline: multiline.Config{Enabled: true, Rules: []string{"generic_continuation"}, FlushTimeoutMS: 4000}}}, StateDir: filepath.Join(root, "state"), ParserAssetDir: filepath.Join(root, "assets"), Outputs: []output.Config{{Type: "file", Path: events}}, TelemetryOutputs: []output.Config{{Type: "discard"}}}
	writePolicyBundle(t, cfg.ParserAssetDir, logpolicy.InputConfig{Enabled: true, MatchMode: "all", Rules: []logpolicy.Rule{{Field: "keyword", Operator: "contains", Values: []string{"pending"}}}}, logpolicy.OutputConfig{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- Run(ctx, cfg, false) }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		data, _ := os.ReadFile(filepath.Join(cfg.StateDir, "offsets.json"))
		var states map[string]cursor
		_ = json.Unmarshal(data, &states)
		if states[input].Offset == int64(len(first)) {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			runErr := <-result
			t.Fatalf("excluded prefix did not checkpoint before pending frame: %s run=%v", data, runErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if data, _ := os.ReadFile(events); len(data) > 0 {
		cancel()
		<-result
		t.Fatalf("pending/excluded records emitted early: %s", data)
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
