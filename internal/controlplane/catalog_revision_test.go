package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	parsercatalog "nexora.local/nli-v20/configs/catalog"
	"nexora.local/nli-v20/internal/adapter"
	"nexora.local/nli-v20/internal/engine"
	"nexora.local/nli-v20/internal/familyprofile"
	"nexora.local/nli-v20/internal/fleet"
	"nexora.local/nli-v20/internal/protocol"
	"nexora.local/nli-v20/internal/rollout"
	metastore "nexora.local/nli-v20/internal/store"
)

func TestCatalogRevisionKeepsPublishedBundleUntilPublication(t *testing.T) {
	f := newAPIFixture(t)
	ctx := context.Background()
	const id = "catalog-revision-header"
	const route = "/api/v1/config/templates/" + id
	published, err := f.server.metadata.Put(ctx, metastore.Document{
		Collection: "templates", ID: id, State: "active", CreatedBy: "admin",
		Payload: json.RawMessage(`{"name":"Published header","config":{"pattern":"^(?P<extra_tag1>[a-z]+)(?: |$)","fields":{"extra_tag1":"extra_tag1"}}}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	current := func() metastore.Document {
		t.Helper()
		doc, err := f.server.metadata.Get(ctx, "templates", id, 0)
		if err != nil {
			t.Fatal(err)
		}
		return doc
	}
	bundleHash := func() string {
		t.Helper()
		bundle, err := f.server.buildActiveParserBundle(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return bundle.BundleHash
	}
	firstBundle := bundleHash()
	edit := func(revision, wantStatus int) {
		t.Helper()
		response, data := f.request(http.MethodPut, route, map[string]any{
			"name": "Revised header", "expected_revision": revision,
			"config": map[string]any{"pattern": `^(?P<extra_tag1>[a-z]+)(?: |$)`, "fields": map[string]string{"extra_tag1": "tenant_code"}},
		})
		if response.StatusCode != wantStatus {
			t.Fatalf("revision edit: %d %s", response.StatusCode, data)
		}
	}
	edit(published.Revision, http.StatusOK)
	edit(published.Revision, http.StatusConflict)
	if got := bundleHash(); got != firstBundle {
		t.Fatal("draft replaced the published bundle")
	}
	response, data := f.request(http.MethodDelete, route, map[string]any{})
	if response.StatusCode != http.StatusOK || bundleHash() != firstBundle || current().State != "discarded" {
		t.Fatalf("discard did not retain the published bundle: %d %s", response.StatusCode, data)
	}
	edit(current().Revision, http.StatusOK)
	for _, action := range []string{"submit", "approve", "publish"} {
		response, data := f.request(http.MethodPost, route+"/"+action, map[string]any{})
		if response.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d %s", action, response.StatusCode, data)
		}
		if action != "publish" && bundleHash() != firstBundle {
			t.Fatalf("%s replaced the published bundle before publication", action)
		}
	}
	if bundleHash() == firstBundle || current().State != "active" {
		t.Fatal("approved field rename did not become a live publication")
	}
}

func TestCatalogEmbeddedStageReferencesRetainBundleWithoutRuntimeWarnings(t *testing.T) {
	f := newAPIFixture(t)
	ctx := context.Background()
	bundle, err := f.server.buildActiveParserBundle(ctx)
	if err != nil || !isBuiltinEnrollmentBundle(bundle) {
		t.Fatalf("initial enrollment bundle is not the verified release snapshot: %v", err)
	}
	var profileAssets []adapter.RuntimeTemplateAsset
	var original adapter.RuntimeTemplateAsset
	for _, asset := range bundle.Assets {
		if asset.AssetClass == "templates" || asset.AssetClass == "kv-config" || asset.AssetClass == "known-keys" {
			template := adapter.RuntimeTemplateAsset{
				AssetClass: asset.AssetClass, AssetID: asset.AssetID, Revision: asset.Revision, Payload: asset.Payload,
			}
			profileAssets = append(profileAssets, template)
			if asset.AssetID == "sample-imap-event-template" {
				original = template
			}
		}
	}
	if original.Revision != 1 {
		t.Fatal("missing original embedded stage reference")
	}
	runtime, err := adapter.NewParserPackAdapter()
	if err != nil {
		t.Fatal(err)
	}
	if _, diagnostics, err := runtime.WithRuntimeTemplates(ctx, profileAssets); err != nil || len(diagnostics) != 0 {
		t.Fatalf("exact original references generated standalone runtime errors: %v (%v)", diagnostics, err)
	}
	modified := original
	modified.Revision++
	var payload map[string]any
	if err := json.Unmarshal(modified.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	payload["name"] = "Altered name for the protected recipe"
	modified.Payload, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	invalidRevision := original
	invalidRevision.Revision = 0
	for _, candidate := range []adapter.RuntimeTemplateAsset{modified, invalidRevision} {
		if _, diagnostics, err := runtime.WithRuntimeTemplates(ctx, []adapter.RuntimeTemplateAsset{candidate}); err != nil ||
			len(diagnostics) != 1 || diagnostics[0] != "Inactive in runtime: invalid or excess templates/sample-imap-event-template" {
			t.Errorf("modified reference evaded diagnostics: %+v, %v", diagnostics, err)
		}
	}
	response, body := f.request(http.MethodGet, "/api/v1/parser-sync/runtime", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("sync inventory: %d %s", response.StatusCode, body)
	}
	var inventory struct {
		Assets []struct {
			Disposition string `json:"runtime_disposition"`
			ParserPack  string `json:"parser_pack_id"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &inventory); err != nil {
		t.Fatal(err)
	}
	totalReferences := 0
	for _, asset := range inventory.Assets {
		if asset.Disposition == "embedded_reference" {
			totalReferences++
			if !familyprofile.IsBuiltinPackID(asset.ParserPack) {
				t.Errorf("reference linked to non-embedded parser %q", asset.ParserPack)
			}
		}
	}
	if totalReferences != 16 {
		t.Fatalf("expected 16 exact linked seed stage references, got %d", totalReferences)
	}
	response, body = f.request(http.MethodGet, "/api/v1/config/kv/sample-imap-mixed-kv", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("KV catalog: %d %s", response.StatusCode, body)
	}
	row := decodeMap(t, body)
	if row["runtime_disposition"] != "embedded_reference" || row["parser_pack_id"] != "nli_reviewed_imap" {
		t.Fatalf("KV catalog omitted runtime provenance: %s", body)
	}
}

func TestCatalogRestorePreservesEmbeddedStageReferences(t *testing.T) {
	f := newAPIFixture(t)
	ctx := context.Background()
	initial, err := f.server.buildActiveParserBundle(ctx)
	if err != nil || !isBuiltinEnrollmentBundle(initial) {
		t.Fatalf("initial catalog did not verify for first enrollment: %v", err)
	}
	originalOwners := map[string]string{}
	for _, asset := range initial.Assets {
		if owner := parsercatalog.EmbeddedReferencePackID(asset.AssetClass, asset.AssetID, asset.Revision, asset.Payload); owner != "" {
			originalOwners[asset.AssetClass+"/"+asset.AssetID] = owner
		}
	}
	if len(originalOwners) != 16 {
		t.Fatalf("expected 16 linked release references, got %d", len(originalOwners))
	}

	backup := createRecoveryTestBackup(t, f)
	putRecoveryTestSetting(t, f.server, "restore-reference-check", `{"pattern":"^history$"}`)
	restore := proposeRecoveryTestRestore(t, f, backup)
	loginParserSyncApprover(t, f)
	response, body := f.request(http.MethodPost, bundleRestoresRoute+"/"+restore.ID+"/approve", restoreTestApproval(restore))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("approve catalog restore: %d %s", response.StatusCode, body)
	}
	current, err := f.server.buildActiveParserBundle(ctx)
	if err != nil || len(current.Assets) != len(initial.Assets) || isBuiltinEnrollmentBundle(current) {
		t.Fatalf("restore failed to produce a new approval-gated generation: %v", err)
	}
	assets, err := adapter.TemplateAssetsFromBundleFile(filepath.Join(f.state, "parser-assets", "bundle.json"))
	if err != nil {
		t.Fatalf("read verified restored bundle: %v", err)
	}
	verified := 0
	for _, asset := range assets {
		id := asset.AssetClass + "/" + asset.AssetID
		want, exists := originalOwners[id]
		if !exists {
			continue
		}
		if owner := parsercatalog.EmbeddedReferencePackID(asset.AssetClass, asset.AssetID, asset.Revision, asset.Payload); owner != want || asset.Revision <= 1 {
			t.Errorf("restored reference %s r%d owner=%q, want %q at a new revision", id, asset.Revision, owner, want)
		}
		verified++
	}
	if verified != len(originalOwners) {
		t.Fatalf("restored materialized bundle has %d embedded references, expected %d", verified, len(originalOwners))
	}
	runtime, err := adapter.NewParserPackAdapter()
	if err != nil {
		t.Fatal(err)
	}
	if _, diagnostics, err := runtime.WithRuntimeTemplates(ctx, assets); err != nil || len(diagnostics) != 0 {
		t.Fatalf("restored references generated standalone runtime errors: %v (%v)", diagnostics, err)
	}
	response, body = f.request(http.MethodGet, "/api/v1/config/templates/sample-imap-event-template", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("read restored catalog reference: %d %s", response.StatusCode, body)
	}
	row := decodeMap(t, body)
	if row["runtime_disposition"] != "embedded_reference" || row["parser_pack_id"] != "nli_reviewed_imap" {
		t.Fatalf("new catalog revision lost embedded provenance: %s", body)
	}
}

func TestApprovedCatalogAssetsLoadAndAllowExactRetryAcknowledgement(t *testing.T) {
	f := newAPIFixture(t)
	ctx := context.Background()
	const nodeID = "catalog-client"
	f.server.fleet.Register(&fleet.Node{ID: nodeID, Hostname: nodeID, Version: "v23.0.0-7"})
	const smtpHeader = `^(?P<date>[0-9]{8})[ \t]+(?P<timestamp>\S+)[ \t]+(?P<hostname>\S+)[ \t]+(?P<service>smtp)[ \t]+` +
		`(?P<pid>[0-9]+)[ \t]+(?P<minor_pid>[0-9]+)[ \t]+(?P<thread_id>[0-9]+)(?:[ \t]*\r?\n[ \t]*|[ \t]+)` +
		`(?P<random_number>[0-9]+);(?P<event_type>[^;\s]+);(?:(?P<extra_tag1>[^;\s]+);)?(?:(?P<extra_tag2>[^;\s]+);)?` +
		`(?:(?P<extra_tag3>[^;\s]+);)?(?:(?P<extra_tag4>[^;\s]+);)?(?P<event>[^;\s]+)(?:[ \t]+|$)`
	captures := map[string]string{}
	for _, field := range []string{"date", "timestamp", "hostname", "service", "pid", "minor_pid", "thread_id", "random_number", "event_type", "extra_tag1", "extra_tag2", "extra_tag3", "extra_tag4", "event"} {
		captures[field] = field
	}
	assets := []struct {
		route, class, id string
		config           map[string]any
	}{
		{"templates", "templates", "r7-header", map[string]any{
			"engine": "re2", "pattern": smtpHeader, "fields": captures,
			"optional_fields": []string{"extra_tag1", "extra_tag2", "extra_tag3", "extra_tag4"},
		}},
		{"kv", "kv-config", "aaa-r7-kv", map[string]any{
			"pair_separators": []string{";"}, "assignment_separators": []string{"="},
			"literal_boundaries": true, "duplicate_policy": "error",
		}},
		{"known-keys", "known-keys", "r7-known-keys", map[string]any{"keys": []string{"status", "reason"}}},
	}
	post := func(path string, payload map[string]any, wantStatus int) map[string]any {
		t.Helper()
		response, body := f.request(http.MethodPost, path, payload)
		if response.StatusCode != wantStatus {
			t.Fatalf("%s: HTTP %d, want %d: %s", path, response.StatusCode, wantStatus, body)
		}
		return decodeMap(t, body)
	}
	var publication map[string]any
	for _, asset := range assets {
		base := "/api/v1/config/" + asset.route
		post(base, map[string]any{"id": asset.id, "name": asset.id, "config": asset.config}, http.StatusCreated)
		for _, action := range []string{"submit", "approve"} {
			post(base+"/"+asset.id+"/"+action, map[string]any{"reason": "Reviewed exact catalog configuration"}, http.StatusOK)
		}
		publication = post(base+"/"+asset.id+"/publish", map[string]any{}, http.StatusOK)
	}
	bundle, err := f.server.buildActiveParserBundle(ctx)
	if err != nil || publication["bundle_hash"] != bundle.BundleHash || publication["controller_applied_hash"] != bundle.BundleHash || publication["auto_rollout_status"] != "pending_approval" {
		t.Fatalf("published assets failed the controller handoff: %+v %+v (%v)", publication, bundle, err)
	}
	revisions := bundleRevisionMap(bundle)
	for _, asset := range assets {
		if revisions[asset.class+"/"+asset.id] != 4 {
			t.Errorf("bundle lacks published revision of %s/%s", asset.class, asset.id)
		}
	}
	runtime, err := adapter.NewParserPackAdapterFromSynchronizedDirectories(ctx, "", filepath.Join(f.state, "parser-assets"))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("Concurrent SMTP runtime and Assurance API", func(t *testing.T) {
		verifyPublishedSMTP(t, f, runtime)
	})

	verify := func(want bool) {
		t.Helper()
		response := post("/api/v1/parser-sync/verify", map[string]any{"node_ids": []string{nodeID}, "bundle_hash": bundle.BundleHash}, http.StatusOK)
		ack := response["client_acknowledgements"].([]any)[0].(map[string]any)
		if ack["exact_acknowledgement"] != want {
			t.Fatalf("acknowledgement = %+v, want %v", ack, want)
		}
	}
	verify(false)
	loginParserSyncApprover(t, f)
	approve := func(proposal string) string {
		t.Helper()
		data := post("/api/v1/rollouts/"+proposal+"/approve", map[string]any{"reason": "Reviewed exact published parser asset bundle"}, http.StatusOK)
		return data["payload"].(map[string]any)["live_rollout_id"].(string)
	}
	report := func(id, status string) {
		t.Helper()
		if err := f.server.rollouts.RecordNodeResult(id, nodeID, status, "catalog test delivery"); err != nil {
			t.Fatal(err)
		}
		f.server.recordParserSyncRolloutResult(ctx, id, protocol.CommandResult{
			CommandID: id, NodeID: nodeID, Status: status, Message: "catalog test delivery",
			ActiveAssetBundleHash: bundle.BundleHash, ActiveAssetRevisions: revisions,
			RuntimeInventory: &protocol.ParserRuntimeInventory{
				BundleHash: bundle.BundleHash, ManagedFilesDigest: protocol.ManagedParserFilesDigest(nil),
			},
		})
	}
	first := approve(publication["rollout_proposal"].(map[string]any)["id"].(string))
	report(first, rollout.StatusFailed)
	verify(false)
	retry := post("/api/v1/parser-sync/retry", map[string]any{"node_ids": []string{nodeID}, "bundle_hash": bundle.BundleHash}, http.StatusCreated)
	if retry["bundle_hash"] != bundle.BundleHash || retry["approval_gate"] != "pending_approval" {
		t.Fatalf("retry lost the exact bundle or its approval gate: %+v", retry)
	}
	verify(false)
	second := approve(retry["proposal"].(map[string]any)["id"].(string))
	report(second, rollout.StatusCompleted)
	verify(true)
}

func verifyPublishedSMTP(t *testing.T, f *apiFixture, runtime *adapter.ParserPackAdapter) {
	t.Helper()
	const prefix = "20250811 080053105+0100 aaa-gmailrgi009 smtp 3692 0 140026854221568"
	const message = "123456;Note;"
	const event = "SieveRuleMsg"
	const parserID = "template/r7-header"
	common := map[string]any{
		"date": "20250811", "timestamp": "080053105+0100", "hostname": "aaa-gmailrgi009",
		"service": "smtp", "pid": "3692", "minor_pid": "0", "thread_id": "140026854221568",
		"random_number": "123456", "event_type": "Note", "event": event,
	}
	tags := []string{"efgh", "ijkl", "mnop", "qrst"}
	type sample struct {
		name, raw string
		expected  map[string]any
	}
	makeSample := func(name, separator, tail string, count int, wantTail map[string]any) sample {
		head := prefix + separator + message
		var fields map[string]any
		if wantTail != nil {
			fields = maps.Clone(common)
			maps.Copy(fields, wantTail)
		}
		for i, tag := range tags[:count] {
			head += tag + ";"
			if fields != nil {
				fields[fmt.Sprintf("extra_tag%d", i+1)] = tag
			}
		}
		return sample{name: name, raw: head + event + tail, expected: fields}
	}
	exactTail := " status=failed;reason=not needed"
	exactFields := map[string]any{"status": "failed", "reason": "not needed"}
	samples := []sample{
		makeSample("exact reported SMTP", " ", exactTail, 3, exactFields),
		makeSample("no extra tag", " ", exactTail, 0, exactFields),
		makeSample("one extra tag", " ", exactTail, 1, exactFields),
		makeSample("two extra tags", " ", exactTail, 2, exactFields),
		makeSample("four tags and unknown named keys", " ", exactTail+";reply=done;application=imap;vjay=vjay", 4,
			map[string]any{"status": "failed", "reason": "not needed", "reply": "done", "application": "imap", "vjay": "vjay"}),
		makeSample("wrapped header", "\r\n ", exactTail+"\r\n", 3, exactFields),
		makeSample("pipe-delimited", " ", " |status=failed|reason=not needed|tenant-id=mx|", 2,
			map[string]any{"status": "failed", "reason": "not needed", "tenant-id": "mx"}),
		makeSample("bracketed mixed assignments", " ", " [status:failed][reason;not needed][service.name=cloud]", 1,
			map[string]any{"status": "failed", "reason": "not needed", "service.name": "cloud"}),
		makeSample("quoted delimiter", " ", ` status=failed;reason="retry; eventually";internal_id=401`, 4,
			map[string]any{"status": "failed", "reason": "retry; eventually", "internal_id": "401"}),
		makeSample("header only", " ", "", 0, map[string]any{}),
		makeSample("missing assignment", " ", " status=failed;reason", 3, nil),
		makeSample("header collision", " ", " event=duplicate;status=failed", 4, nil),
	}

	first := runtime.TryParseV5Production(samples[0].raw, engine.Source{Service: "auto"})
	if !first.Success || len(first.ParseTelemetry.OrderedAttempts) == 0 {
		t.Fatalf("published header and KV configuration failed in the runtime: %+v", first)
	}
	stages := first.ParseTelemetry.OrderedAttempts[0].StageResults
	if len(stages) != 1 || stages[0].StageName != "Published header template + KV template aaa-r7-kv" {
		t.Fatalf("published KV configuration was skipped: %+v", stages)
	}
	for _, item := range samples {
		response, body := f.request(http.MethodPost, "/api/v1/assurance/run", map[string]any{
			"raw": item.raw, "service": "auto", "preserve_source": true,
		})
		if response.StatusCode != http.StatusOK {
			t.Fatalf("Assurance %s: HTTP %d: %s", item.name, response.StatusCode, body)
		}
		result := decodeMap(t, body)
		actual, _ := result["actual"].(map[string]any)
		if item.expected == nil {
			if result["passed"] == true || len(actual) != 0 {
				t.Errorf("Assurance accepted %s: %v", item.name, result)
			}
		} else if result["passed"] != true || result["parser"].(map[string]any)["name"] != parserID || !reflect.DeepEqual(actual, item.expected) {
			t.Errorf("Assurance %s: got %v, want %v", item.name, actual, item.expected)
		}
	}
	response, body := f.request(http.MethodPost, "/api/v1/assurance/run", map[string]any{"raw": []string{samples[0].raw}})
	if response.StatusCode != http.StatusBadRequest || decodeMap(t, body)["error"] == "" {
		t.Fatalf("Assurance accepted a malformed request shape: HTTP %d: %s", response.StatusCode, body)
	}

	const workers, defaultCycles, maxCycles = 4, 256, 25000
	cycles := defaultCycles
	deadline := 30 * time.Second
	if raw, supplied := os.LookupEnv("NLI_R7_STRESS_CYCLES"); supplied {
		var err error
		cycles, err = strconv.Atoi(raw)
		if err != nil || cycles < 1 || cycles > maxCycles {
			t.Fatalf("NLI_R7_STRESS_CYCLES must be an integer from 1 to %d", maxCycles)
		}
		if cycles > defaultCycles {
			deadline += time.Duration(cycles) * 25 * time.Millisecond
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	type workerReport struct {
		mismatches     int
		firstError     string
		headerTimeouts int
		kvTimeouts     int
	}
	reports := make(chan workerReport, workers)
	started := time.Now()
	for worker := 0; worker < workers; worker++ {
		go func(offset int) {
			report := workerReport{}
			for i := 0; i < cycles*len(samples); i++ {
				item := samples[(i+offset)%len(samples)]
				parsed := runtime.TryParseV5ProductionContext(ctx, item.raw, engine.Source{Service: "auto"})
				metadata := parsed.ParseTelemetry
				if metadata != nil {
					for _, attempt := range metadata.OrderedAttempts {
						switch attempt.FailureReason {
						case "template_header_timeout":
							report.headerTimeouts++
						case "template_kv_timeout":
							report.kvTimeouts++
						}
					}
				}
				var actual map[string]any
				if parsed.EventPayload != nil {
					actual = parsed.EventPayload.Fields
				}
				if item.expected == nil {
					if parsed.Quarantined && !parsed.Success && len(actual) == 0 {
						continue
					}
				} else if parsed.Success && !parsed.Quarantined && metadata != nil && metadata.ParserID == parserID && reflect.DeepEqual(actual, item.expected) {
					continue
				}
				report.mismatches++
				if report.firstError == "" {
					report.firstError = fmt.Sprintf("%s: success=%v quarantined=%v actual=%v want=%v", item.name, parsed.Success, parsed.Quarantined, actual, item.expected)
					if metadata != nil {
						attempts := make([]string, 0, len(metadata.OrderedAttempts))
						for _, attempt := range metadata.OrderedAttempts {
							attempts = append(attempts, fmt.Sprintf("%s/%s/%s(%vms)", attempt.ParserID, attempt.Outcome, attempt.FailureReason, attempt.LatencyMs))
						}
						report.firstError += fmt.Sprintf(" parser=%q codes=%v attempts=%v", metadata.ParserID, metadata.ErrorCodes, attempts)
					}
				}
			}
			reports <- report
		}(worker)
	}
	headerTimeouts, kvTimeouts := 0, 0
	for worker := 0; worker < workers; worker++ {
		report := <-reports
		headerTimeouts += report.headerTimeouts
		kvTimeouts += report.kvTimeouts
		if report.mismatches != 0 {
			t.Errorf("worker got %d incorrect results, first %s", report.mismatches, report.firstError)
		}
	}
	total := workers * cycles * len(samples)
	elapsed := time.Since(started)
	t.Logf("checked %d concurrent runtime parses across %d workers in %s (%.0f records/sec) and validated %d Assurance API responses; template timeout attempts: header=%d KV=%d",
		total, workers, elapsed, float64(total)/elapsed.Seconds(), len(samples)+1, headerTimeouts, kvTimeouts)
}
