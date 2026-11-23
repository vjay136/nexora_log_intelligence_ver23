package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"nexora.local/nli-v20/internal/auditlog"
	"nexora.local/nli-v20/internal/fleet"
	"nexora.local/nli-v20/internal/logpolicy"
	"nexora.local/nli-v20/internal/protocol"
	metastore "nexora.local/nli-v20/internal/store"
)

func r9InputConfig(event string) map[string]any {
	return map[string]any{"enabled": true, "match_mode": "any", "rules": []any{map[string]any{"field": "event", "operator": "equals", "values": []string{event}, "case_sensitive": true}}}
}
func r9PutPolicy(t *testing.T, s *Server, kind, id string, config map[string]any) {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"name": id, "config": config})
	if _, err := s.metadata.Put(context.Background(), metastore.Document{Collection: kind, ID: id, State: "active", CreatedBy: "fixture", Payload: payload}); err != nil {
		t.Fatal(err)
	}
}
func TestR9PolicyRawPreviewAndOutputPreview(t *testing.T) {
	f := newAPIFixture(t)
	rows := []string{
		"20250812 130035121+0100 aaa-gmailrgo009 smtp 3609 0 140293780948736 Note;SmtpServerSTARTTLSIn(2001/39) id=6864BD5E047384C4:tls=TLSv1.2:cipher=ECDHE-RSA-AES256-GCM-SHA384",
		"20250812 130035121+0100 aaa-gmailrgo009 smtp 3609 0 140293780948736 Note;SmtpServerEHLO(2001/4) id=6864BD5E047384C4:domain=server035.mx.internal:host=11.22.33.44",
		"20250812 130035122+0100 aaa-gmailrgo009 smtp 3609 0 140293768701696 Note;SmtpServerSTARTTLSIn(2001/39) id=6864BD5E047384C3:tls=TLSv1.2:cipher=ECDHE-RSA-AES256-GCM-SHA384"}
	response, body := f.request(http.MethodPost, "/api/v1/policies/input/preview", map[string]any{"raw": strings.Join(rows, "\r\n"), "config": r9InputConfig("SmtpServerEHLO")})
	result := decodeMap(t, body)
	if response.StatusCode != 200 || result["accepted_count"] != float64(1) || result["excluded_count"] != float64(2) || result["parse_requested"] != false || result["persisted"] != false {
		t.Fatalf("raw preview %d %s", response.StatusCode, body)
	}
	matched := result["matched_raw"].([]any)
	if matched[0] != rows[1] || len(result["results"].([]any)) != 0 {
		t.Fatalf("preview parsed/changed raw: %s", body)
	}
	bundle, err := f.server.buildActiveParserBundle(context.Background())
	if err != nil || bundleRequiresLogPolicies(bundle) {
		t.Fatalf("draft preview leaked live: %v", err)
	}
	response, body = f.request(http.MethodPost, "/api/v1/policies/output/preview", map[string]any{"raw": `{"message":"hello","password":"private","count":3}`, "config": map[string]any{"enabled": true, "fields": []string{"password"}}})
	result = decodeMap(t, body)
	if response.StatusCode != 200 || result["parsed_count"] != float64(1) {
		t.Fatalf("output preview %d %s", response.StatusCode, body)
	}
	before := result["before"].([]any)[0].(map[string]any)
	after := result["after"].([]any)[0].(map[string]any)
	if before["password"] != "[REDACTED]" || after["password"] != nil || after["message"] != "hello" || after["count"] != float64(3) {
		t.Fatalf("wrong exact output %s", body)
	}
	for _, config := range []map[string]any{{"enabled": true, "fields": []string{}}, {"enabled": true, "fields": []string{"message"}, "metadata": map[string]any{"token": "unsafe"}}} {
		response, body = f.request(http.MethodPost, "/api/v1/policies/output/preview", map[string]any{"raw": "{}", "config": config})
		if response.StatusCode != 400 {
			t.Fatalf("invalid config accepted %d %s", response.StatusCode, body)
		}
	}
}
func TestR9PolicyLifecycleAndCapability(t *testing.T) {
	f := newAPIFixture(t)
	ctx := context.Background()
	path := "/api/v1/config/selective-input/ehlo-only"
	response, body := f.request(http.MethodPost, "/api/v1/config/selective-input", map[string]any{"id": "ehlo-only", "name": "EHLO only", "config": r9InputConfig("SmtpServerEHLO")})
	if response.StatusCode != 201 {
		t.Fatalf("create %d %s", response.StatusCode, body)
	}
	bundle, err := f.server.buildActiveParserBundle(ctx)
	if err != nil || bundleRequiresLogPolicies(bundle) {
		t.Fatal("unpublished draft affected live bundle", err)
	}
	for _, action := range []string{"submit", "approve", "publish"} {
		if action == "approve" {
			loginParserSyncApprover(t, f)
		}
		if action == "publish" {
			f.login("admin", "Admin-password-12345!")
			f.refreshCSRF()
		}
		response, body = f.request(http.MethodPost, path+"/"+action, map[string]any{"reason": "Verified optional policy"})
		if response.StatusCode != 200 {
			t.Fatalf("%s %d %s", action, response.StatusCode, body)
		}
	}
	bundle, err = f.server.buildActiveParserBundle(ctx)
	if err != nil || !bundleRequiresLogPolicies(bundle) {
		t.Fatal("published policy missing", err)
	}
	old := &fleet.Node{ID: "r8", Hostname: "r8", Version: "23.0.0", ReleaseID: "v23.0.0-8"}
	f.server.fleet.Register(old)
	f.server.updateSyncFromHeartbeat(protocol.HeartbeatRequest{NodeID: "r8", ActiveAssetBundleHash: bundle.BundleHash})
	doc, _ := f.server.metadata.Get(ctx, "fleet-sync", "r8", 0)
	var state map[string]any
	_ = json.Unmarshal(doc.Payload, &state)
	if state["asset_sync_status"] != "upgrade_required" || parserClientSupportsLogPolicies(old, bundle) {
		t.Fatalf("old agent falsely acknowledged: %s", doc.Payload)
	}
	capable := &fleet.Node{ID: "r9", Version: "23.0.0", FeatureCapabilities: []string{logpolicy.Capability}, ReleaseID: "v23.0.0-9"}
	if !parserClientSupportsLogPolicies(capable, bundle) {
		t.Fatal("capable runtime rejected")
	}
	response, body = f.request(http.MethodPost, path+"/revoke", map[string]any{"reason": "Disable verified policy"})
	if response.StatusCode != 200 {
		t.Fatalf("revoke %d %s", response.StatusCode, body)
	}
	bundle, err = f.server.buildActiveParserBundle(ctx)
	if err != nil || bundleRequiresLogPolicies(bundle) {
		t.Fatalf("revoked policy remained live %v", err)
	}
}
func TestR9PolicyLimitsAndAggregate(t *testing.T) {
	fields := make([]string, 10000)
	for i := range fields {
		fields[i] = fmt.Sprintf("key_%d", i)
	}
	if err := validateCatalogConfig("output-fields", map[string]any{"enabled": true, "fields": fields}); err != nil {
		t.Fatalf("10000 exact fields rejected: %v", err)
	}
	f := newAPIFixture(t)
	for i := 0; i < 128; i++ {
		r9PutPolicy(t, f.server, "output-fields", fmt.Sprintf("policy-%03d", i), map[string]any{"enabled": false, "fields": []string{}})
	}
	if err := f.server.validateProjectedLogPolicies(context.Background(), "output-fields", "policy-128", map[string]any{"config": map[string]any{"enabled": false, "fields": []string{}}}); err == nil {
		t.Fatal("aggregate 129 profiles accepted")
	}
	if err := f.server.validateProjectedLogPolicies(context.Background(), "output-fields", "policy-000", map[string]any{"config": map[string]any{"enabled": true, "fields": []string{"password"}}}); err != nil {
		t.Fatalf("same-id revision counted twice: %v", err)
	}
}
func TestR9PolicyBackupRoundTripAndLegacyScope(t *testing.T) {
	f := newAPIFixture(t)
	ctx := context.Background()
	legacy := createRecoveryTestBackup(t, f)
	_, snapshot, err := f.server.readBundleBackup(ctx, legacy.ID)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.SettingsScope = []string{"known-keys", "kv-config", "projections", "regex-patterns", "semantic-extraction", "static-patterns", "templates"}
	if _, err := verifyBundleBackupSnapshot(snapshot); err != nil {
		t.Fatalf("R8 scope rejected: %v", err)
	}
	r9PutPolicy(t, f.server, "selective-input", "ehlo-only", r9InputConfig("SmtpServerEHLO"))
	r9PutPolicy(t, f.server, "output-fields", "strip-symbolic", map[string]any{"enabled": true, "fields": []string{"password", "token", "api_key", "authorization", "host.name"}})
	backup := createRecoveryTestBackup(t, f)
	_, snapshot, err = f.server.readBundleBackup(ctx, backup.ID)
	if err != nil {
		t.Fatal(err)
	}
	if backup.AssetCounts["selective-input"] != 1 || backup.AssetCounts["output-fields"] != 1 {
		t.Fatalf("new classes missing %+v", backup)
	}
	if _, err := verifyBundleBackupSnapshot(snapshot); err != nil {
		t.Fatalf("symbolic keys treated as secrets %v", err)
	}
	r9PutPolicy(t, f.server, "output-fields", "strip-symbolic", map[string]any{"enabled": false, "fields": []string{}})
	restore := proposeRecoveryTestRestore(t, f, backup)
	loginParserSyncApprover(t, f)
	response, body := f.request(http.MethodPost, bundleRestoresRoute+"/"+restore.ID+"/approve", restoreTestApproval(restore))
	if response.StatusCode != 200 {
		t.Fatalf("restore %d %s", response.StatusCode, body)
	}
	current, err := f.server.buildActiveParserBundle(ctx)
	if err != nil || verifyRestoredBundle(current, snapshot.Bundle) != nil {
		t.Fatalf("restore changed policy contents %v", err)
	}
	set, err := logPoliciesFromBundle(current)
	if err != nil || !set.InputEnabled() || !set.OutputEnabled() {
		t.Fatalf("restored policies not usable %v", err)
	}
}
func TestR9FilteredAssuranceAndEmptyOutput(t *testing.T) {
	f := newAPIFixture(t)
	r9PutPolicy(t, f.server, "selective-input", "only-ehlo", r9InputConfig("SmtpServerEHLO"))
	result := f.server.runAssuranceContext(context.Background(), assuranceRequest{Raw: `{"event":"OTHER","message":"hello"}`})
	if result["filtered_out"] != true || result["parse_attempted"] != false || result["candidate"] != nil {
		t.Fatalf("excluded record parsed/failed %#v", result)
	}
	r9PutPolicy(t, f.server, "output-fields", "strip-all", map[string]any{"enabled": true, "fields": []string{"event", "message"}})
	result = f.server.runAssuranceContext(context.Background(), assuranceRequest{Raw: `{"event":"SmtpServerEHLO","message":"hello"}`})
	actual, _ := result["actual"].(map[string]any)
	if result["passed"] != true || len(actual) != 0 || result["output_policy"] == nil {
		t.Fatalf("intentional empty object failed %#v", result)
	}
	raw := f.server.runAssuranceContext(context.Background(), assuranceRequest{Raw: `{"event":"OTHER","message":"hello"}`, BypassLogPolicies: true})
	if raw["passed"] != true || len(raw["actual"].(map[string]any)) != 2 {
		t.Fatalf("authoring evidence lost %#v", raw)
	}
}
func TestR9PolicyAuthoringFailuresRemainInline(t *testing.T) {
	for _, path := range []string{"/api/v1/policies/input/preview", "/api/v1/policies/output/preview", "/api/v1/config/selective-input", "/api/v1/config/output-fields/strip/submit"} {
		for _, status := range []string{"400", "409", "413", "422", "401", "403", "500"} {
			event := auditlog.Event{Action: "POST", Resource: path, Outcome: "failure", Details: map[string]string{"detail": "status=" + status}}
			_, _, notify := classifyNotificationEvent(event)
			want := status == "401" || status == "403" || status == "500"
			if notify != want {
				t.Errorf("%s %s notify=%v", path, status, notify)
			}
		}
	}
	event := auditlog.Event{Action: "POST", Resource: "/api/v1/config/output-fields/not/a/valid/path", Outcome: "failure", Details: map[string]string{"detail": "status=400"}}
	if _, _, notify := classifyNotificationEvent(event); !notify {
		t.Fatal("unexpected route error suppressed")
	}
}

func TestR9FilteredReplayDoesNotConsumeRetryBudget(t *testing.T) {
	f := newAPIFixture(t)
	ctx := context.Background()
	if err := f.server.storeQuarantineRecord(ctx, quarantineRecordInput{ID: "q-filtered", NodeID: "node-1", Status: "reprocessing"}, false); err != nil {
		t.Fatal(err)
	}
	r, doc, err := f.server.getQuarantineRecord(ctx, "q-filtered")
	if err != nil {
		t.Fatal(err)
	}
	item, err := f.server.rollouts.Create(rolloutTypeReplay, "policy replay", "admin", []string{"node-1"}, map[string]any{"node_id": "node-1", "record_ids": []string{"q-filtered"}})
	if err != nil {
		t.Fatal(err)
	}
	r.ReplayRolloutID = item.ID
	r.ReplayAttemptCount = quarantineReplayLimit
	if err := f.server.putQuarantineRecord(ctx, r, doc.CreatedBy); err != nil {
		t.Fatal(err)
	}
	f.server.recordQuarantineReplayResult(ctx, item.ID, "node-1", rolloutStatusCompleted, `{"filtered_ids":["q-filtered"],"resolved_ids":["q-filtered"]}`)
	got, _, err := f.server.getQuarantineRecord(ctx, "q-filtered")
	if err != nil || got.Status != "waiting" || !got.FilteredByPolicy || got.ReplayAttemptCount != quarantineReplayLimit-1 || !got.RetryAfter.IsZero() {
		t.Fatalf("filtered replay counted as parser failure/resolved: %+v %v", got, err)
	}
	f.server.recordQuarantineReplayResult(ctx, item.ID, "node-1", rolloutStatusCompleted, `{"filtered_ids":["q-filtered"]}`)
	again, _, _ := f.server.getQuarantineRecord(ctx, "q-filtered")
	if again.ReplayAttemptCount != got.ReplayAttemptCount {
		t.Fatal("duplicate ACK modified retry budget")
	}
}

func TestR9PolicyAggregateTermsAndPublicationCompensation(t *testing.T) {
	f := newAPIFixture(t)
	ctx := context.Background()
	values := make([]string, 128)
	for i := range values {
		values[i] = fmt.Sprintf("term-%d", i)
	}
	rules := make([]any, 64)
	for i := range rules {
		rules[i] = map[string]any{"field": "keyword", "operator": "contains", "values": values, "case_sensitive": true}
	}
	r9PutPolicy(t, f.server, "selective-input", "terms-limit", map[string]any{"enabled": true, "match_mode": "any", "rules": rules})
	if err := f.server.validateProjectedLogPolicies(ctx, "selective-input", "one-more", map[string]any{"config": r9InputConfig("SmtpServerEHLO")}); err == nil {
		t.Fatal("aggregate 8193 terms accepted")
	}
	g := newAPIFixture(t)
	before, err := g.server.buildActiveParserBundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"name": "Failed publication", "config": map[string]any{"enabled": true, "fields": []string{"password"}}})
	if _, err := g.server.metadata.Put(ctx, metastore.Document{Collection: "output-fields", ID: "compensate", State: "approved", CreatedBy: "fixture", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	g.server.metadata = &bundleRecoveryWriteFailure{Store: g.server.metadata, collection: "rollout-proposals"}
	response, body := g.request(http.MethodPost, "/api/v1/config/output-fields/compensate/publish", map[string]any{})
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("failure injection did not fail %d %s", response.StatusCode, body)
	}
	after, err := g.server.buildActiveParserBundle(ctx)
	if err != nil || after.BundleHash != before.BundleHash {
		t.Fatalf("failed publication became live %v", err)
	}
	persisted, err := g.server.persistedLogPolicies()
	if err != nil || persisted.OutputEnabled() {
		t.Fatalf("failed publication left active persisted policy %v", err)
	}
}

func TestR9PolicyExclusionAcrossScenariosAndAI(t *testing.T) {
	f := newAPIFixture(t)
	r9PutPolicy(t, f.server, "selective-input", "ehlo-only", r9InputConfig("SmtpServerEHLO"))
	for scenario := range assuranceRunScenarios {
		evidence := f.server.executeAssuranceRunScenario(scenario, assuranceRequest{Raw: `{"event":"OTHER","message":"hello"}`})
		if evidence["filtered_out"] != true || evidence["passed"] == true || evidence["parse_attempted"] != false {
			t.Errorf("%s manufactured parser result %#v", scenario, evidence)
		}
	}
	response, body := f.request(http.MethodPost, "/api/v1/assurance/ai-proposal", map[string]any{"raw": `{"event":"OTHER","message":"hello"}`})
	if response.StatusCode != http.StatusConflict || !strings.Contains(string(body), "excluded") {
		t.Fatalf("filtered record entered AI repair %d %s", response.StatusCode, body)
	}
	result := f.server.runAssuranceContext(context.Background(), assuranceRequest{Raw: strings.Repeat("x", (1<<20)+1), PreserveSource: true})
	if result["filtered_out"] == true || result["policy_error"] != true || result["parse_attempted"] != false {
		t.Fatalf("oversized policy error presented as ordinary exclusion %#v", result)
	}
	summary := resultSummary([]map[string]any{policyAssuranceSkipped(assuranceRequest{Raw: "other"}, "filtered_out", "")})
	if summary["excluded"] != 1 || summary["parsed"] != 0 || summary["quarantined"] != 0 || summary["errors"] != 0 {
		t.Fatalf("incorrect excluded summary %#v", summary)
	}
}

func TestR9PolicyAcknowledgementRequiresCapabilityAndInventory(t *testing.T) {
	f := newAPIFixture(t)
	ctx := context.Background()
	r9PutPolicy(t, f.server, "output-fields", "strip", map[string]any{"enabled": true, "fields": []string{"password"}})
	bundle, err := f.server.buildActiveParserBundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.server.fleet.Register(&fleet.Node{ID: "old-runtime", Version: "23.0.0"})
	if item, err := f.server.startParserBundleRollout(ctx, "fixture", "must reject", bundle, []string{"old-runtime"}); err == nil || item != nil {
		t.Fatal("old agent received policy rollout")
	}
	item, err := f.server.rollouts.Create(rolloutTypeParserSync, "ACK test", "fixture", []string{"old-runtime"}, map[string]any{"asset_bundle": bundle, "bundle_hash": bundle.BundleHash})
	if err != nil {
		t.Fatal(err)
	}
	report := func(inventory *protocol.ParserRuntimeInventory) map[string]any {
		f.server.recordParserSyncRolloutResult(ctx, item.ID, protocol.CommandResult{NodeID: "old-runtime", Status: rolloutStatusCompleted, ActiveAssetBundleHash: bundle.BundleHash, RuntimeInventory: inventory})
		doc, err := f.server.metadata.Get(ctx, "fleet-sync", "old-runtime", 0)
		if err != nil {
			t.Fatal(err)
		}
		var state map[string]any
		_ = json.Unmarshal(doc.Payload, &state)
		return state
	}
	if state := report(nil); state["asset_sync_status"] != "upgrade_required" {
		t.Fatalf("old agent falsely ACKed %#v", state)
	}
	if err := f.server.fleet.UpdateFeatureCapabilities("old-runtime", "v23.0.0-9", []string{logpolicy.Capability}); err != nil {
		t.Fatal(err)
	}
	if state := report(nil); state["asset_sync_status"] == "applied" {
		t.Fatal("capability without inventory falsely ACKed")
	}
	files := []protocol.ParserFileDigest{}
	for _, asset := range bundle.Assets {
		if asset.AssetClass == "parser-packs" {
			files = append(files, protocol.ParserFileDigest{ID: asset.AssetID, SHA256: asset.SHA256})
		}
	}
	inventory := &protocol.ParserRuntimeInventory{BundleHash: bundle.BundleHash, ManagedFilesDigest: protocol.ManagedParserFilesDigest(files)}
	if state := report(inventory); !parserBundleAcknowledged(state, bundle.BundleHash) {
		t.Fatalf("exact capable ACK rejected %#v", state)
	}
	f.server.updateSyncFromHeartbeat(protocol.HeartbeatRequest{NodeID: "old-runtime", ActiveAssetBundleHash: bundle.BundleHash})
	doc, _ := f.server.metadata.Get(ctx, "fleet-sync", "old-runtime", 0)
	var state map[string]any
	_ = json.Unmarshal(doc.Payload, &state)
	if parserBundleAcknowledged(state, bundle.BundleHash) {
		t.Fatal("heartbeat without inventory resurrected ACK")
	}
}

func TestR9ReplayPolicyErrorIsNotIntentionalExclusion(t *testing.T) {
	f := newAPIFixture(t)
	ctx := context.Background()
	if err := f.server.storeQuarantineRecord(ctx, quarantineRecordInput{ID: "q-policy-error", NodeID: "node-1", Status: "reprocessing"}, false); err != nil {
		t.Fatal(err)
	}
	r, doc, err := f.server.getQuarantineRecord(ctx, "q-policy-error")
	if err != nil {
		t.Fatal(err)
	}
	item, err := f.server.rollouts.Create(rolloutTypeReplay, "blocked policy replay", "admin", []string{"node-1"}, map[string]any{"node_id": "node-1", "record_ids": []string{"q-policy-error"}})
	if err != nil {
		t.Fatal(err)
	}
	r.ReplayRolloutID = item.ID
	r.ReplayAttemptCount = 1
	if err := f.server.putQuarantineRecord(ctx, r, doc.CreatedBy); err != nil {
		t.Fatal(err)
	}
	f.server.recordQuarantineReplayResult(ctx, item.ID, "node-1", rolloutStatusCompleted, `{"policy_error_ids":["q-policy-error"],"filtered_ids":["q-policy-error"],"resolved_ids":["q-policy-error"]}`)
	got, _, err := f.server.getQuarantineRecord(ctx, "q-policy-error")
	if err != nil || got.Status != "waiting" || !got.InputPolicyError || got.FilteredByPolicy || got.ReplayAttemptCount != 0 || !got.RetryAfter.IsZero() {
		t.Fatalf("policy error misrepresented: %+v %v", got, err)
	}
}
