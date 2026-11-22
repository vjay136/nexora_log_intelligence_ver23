package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"nexora.local/nli-v20/internal/engine"
	"nexora.local/nli-v20/internal/fleet"
	"nexora.local/nli-v20/internal/protocol"
	"nexora.local/nli-v20/internal/rollout"
	metastore "nexora.local/nli-v20/internal/store"
)

func putRecoveryTestSetting(t *testing.T, s *Server, id, config string) metastore.Document {
	t.Helper()
	doc, err := s.metadata.Put(context.Background(), metastore.Document{
		Collection: "regex-patterns", ID: id, State: "active", CreatedBy: "test",
		Payload: json.RawMessage(`{"name":"Recovery test","config":` + config + `}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func createRecoveryTestBackup(t *testing.T, f *apiFixture) bundleBackupRecord {
	t.Helper()
	response, body := f.request(http.MethodPost, bundleBackupsRoute, struct{}{})
	var record bundleBackupRecord
	if response.StatusCode != http.StatusCreated || json.Unmarshal(body, &record) != nil || !validBundleRecoverySHA(record.SnapshotHash) {
		t.Fatalf("backup creation %d: %s", response.StatusCode, body)
	}
	return record
}

func proposeRecoveryTestRestore(t *testing.T, f *apiFixture, backup bundleBackupRecord) bundleRestoreRecord {
	t.Helper()
	response, body := f.request(http.MethodPost, bundleRestoresRoute, proposeBundleRestoreRequest{BackupID: backup.ID, ExpectedSnapshotHash: backup.SnapshotHash, Reason: "Restore approved parser changes"})
	var record bundleRestoreRecord
	if response.StatusCode != http.StatusCreated || json.Unmarshal(body, &record) != nil || record.State != bundleRestorePending {
		t.Fatalf("restore proposal %d: %s", response.StatusCode, body)
	}
	return record
}

func restoreTestApproval(record bundleRestoreRecord) approveBundleRestoreRequest {
	return approveBundleRestoreRequest{ExpectedSnapshotHash: record.SnapshotHash, ExpectedBaseRevision: record.BaseRevision}
}

func TestBundleRecoveryExactRestoreAndFleetAcknowledgement(t *testing.T) {
	f := newAPIFixture(t)
	s := f.server
	ctx := context.Background()
	const node = "restore-fleet-client"
	s.fleet.Register(&fleet.Node{ID: node, Hostname: node, Version: "99.0.0"})
	original := putRecoveryTestSetting(t, s, "restore-existing", `{"weight":1.0,"keys":["api_key"]}`)
	definition := map[string]any{"pattern_type": "regex", "pattern": `status=(?P<status>\w+)`, "fields": []any{map[string]any{"name": "status", "source": "group:status", "type": "string"}}}
	pack, err := assuranceRuntimePack("bundle-recovery-demo", "1.2.0", "test", definition, []assuranceRequest{{Raw: "status=FIXTURE_OK", Service: "mail", Desired: map[string]any{"status": "FIXTURE_OK"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.putBundleRecoveryDocument(ctx, "parser-packs", pack.ID, "published", "test", map[string]any{"name": "Recovery pack", "runtime_pack": pack}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.metadata.Put(ctx, metastore.Document{Collection: "assurance-cases", ID: "unrelated", State: "retained", Payload: json.RawMessage(`{"raw":"unrelated-customer-evidence"}`)}); err != nil {
		t.Fatal(err)
	}
	backup := createRecoveryTestBackup(t, f)
	duplicate := createRecoveryTestBackup(t, f)
	if backup.ID != duplicate.ID || !backup.CreatedAt.Equal(duplicate.CreatedAt) || backup.AssetCounts["parser-packs"] != 1 || backup.EmbeddedParserCount == 0 || backup.Release != engine.ReleaseID || !backup.Scope.IncludesEmbeddedValidationExamples {
		t.Fatalf("backup identity or scope changed: %+v %+v", backup, duplicate)
	}
	response, body := f.request(http.MethodGet, bundleBackupsRoute+"/"+backup.ID+"/export", nil)
	var exported bundleBackupExport
	if response.StatusCode != http.StatusOK || !strings.Contains(response.Header.Get("Content-Disposition"), backup.ID) ||
		json.Unmarshal(body, &exported) != nil || !bytes.Contains(body, []byte("FIXTURE_OK")) || bytes.Contains(body, []byte("unrelated-customer-evidence")) {
		t.Fatalf("export status=%d missing expected content or contains unrelated source data", response.StatusCode)
	}
	canonical, err := canonicalBundleRecoveryData(exported.Snapshot)
	if err != nil || bundleRecoverySHA(canonical) != backup.SnapshotHash || exported.Snapshot.Bundle.BundleHash != backup.BundleHash {
		t.Fatalf("downloaded backup failed verification: %+v %v", exported.Backup, err)
	}
	second := putRecoveryTestSetting(t, s, original.ID, `{"weight":2}`)
	added := putRecoveryTestSetting(t, s, "restore-new", `{"weight":3}`)
	before, err := s.buildActiveParserBundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	restore := proposeRecoveryTestRestore(t, f, backup)
	approvalRoute := bundleRestoresRoute + "/" + restore.ID + "/approve"
	if response, body := f.request(http.MethodPost, approvalRoute, restoreTestApproval(restore)); response.StatusCode != http.StatusConflict || !bytes.Contains(body, []byte("independent")) {
		t.Fatalf("self approval allowed %d: %s", response.StatusCode, body)
	}
	loginParserSyncApprover(t, f)
	mismatch := restoreTestApproval(restore)
	mismatch.ExpectedBaseRevision = strings.Repeat("f", 64)
	if response, body := f.request(http.MethodPost, approvalRoute, mismatch); response.StatusCode != http.StatusConflict {
		t.Fatalf("approval accepted an unrelated base %d: %s", response.StatusCode, body)
	}
	response, body = f.request(http.MethodPost, approvalRoute, restoreTestApproval(restore))
	var restored bundleRestoreRecord
	if response.StatusCode != http.StatusOK || json.Unmarshal(body, &restored) != nil || restored.State != bundleRestoreProposed || restored.RolloutProposalID == "" || restored.DesiredRevision <= 0 {
		t.Fatalf("restore approval %d: %s", response.StatusCode, body)
	}
	current, err := s.buildActiveParserBundle(ctx)
	if err != nil || current.BundleHash != restored.DesiredBundleHash || current.BundleHash == backup.BundleHash || current.BundleHash == before.BundleHash || verifyRestoredBundle(current, exported.Snapshot.Bundle) != nil {
		t.Fatalf("a new exact-content publication was not created: current=%s response=%+v error=%v", current.BundleHash, restored, err)
	}
	preBackup, _, err := s.readBundleBackup(ctx, restored.PreRestoreBackupID)
	if err != nil || preBackup.BundleHash != before.BundleHash || preBackup.Kind != "pre_restore" {
		t.Fatalf("previous publication was not retained: %+v %v", preBackup, err)
	}
	latest, err := s.metadata.Get(ctx, second.Collection, second.ID, 0)
	if err != nil || latest.Revision != second.Revision+1 {
		t.Fatalf("restored head revision: %+v %v", latest, err)
	}
	latest, err = s.metadata.Get(ctx, added.Collection, added.ID, 0)
	if err != nil || latest.State != "revoked" || latest.Revision != added.Revision+1 {
		t.Fatalf("extra publication should be revoked with history intact: %+v %v", latest, err)
	}
	if _, err := s.metadata.Get(ctx, added.Collection, added.ID, added.Revision); err != nil {
		t.Fatalf("former extra active revision was deleted: %v", err)
	}
	acknowledged := func() bool {
		t.Helper()
		response, body := f.request(http.MethodPost, "/api/v1/parser-sync/verify", map[string]any{"node_ids": []string{node}, "bundle_hash": current.BundleHash})
		var verification struct {
			ClientAcknowledgements []struct {
				Exact bool `json:"exact_acknowledgement"`
			} `json:"client_acknowledgements"`
		}
		if response.StatusCode != http.StatusOK || json.Unmarshal(body, &verification) != nil || len(verification.ClientAcknowledgements) != 1 {
			t.Fatalf("verify restore state %d: %s", response.StatusCode, body)
		}
		return verification.ClientAcknowledgements[0].Exact
	}
	if acknowledged() {
		t.Fatal("restore approval was mistaken for client application")
	}
	response, body = f.request(http.MethodPost, "/api/v1/rollouts/"+restored.RolloutProposalID+"/approve", approvalRequest{Reason: "reviewed restored parser bundle"})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("existing independent Fleet Sync approval %d: %s", response.StatusCode, body)
	}
	liveID := decodeMap(t, body)["payload"].(map[string]any)["live_rollout_id"].(string)
	if acknowledged() {
		t.Fatal("fleet rollout approval was mistaken for client application")
	}
	instance := protocol.CommandResult{NodeID: node, Status: rollout.StatusCompleted, ActiveAssetBundleHash: before.BundleHash}
	s.recordParserSyncRolloutResult(ctx, liveID, instance)
	if acknowledged() {
		t.Fatal("a stale bundle acknowledgement cleared the restore gate")
	}
	instance.ActiveAssetBundleHash = current.BundleHash
	s.recordParserSyncRolloutResult(ctx, liveID, instance)
	if !acknowledged() {
		t.Fatal("exact client application was not acknowledged")
	}
}

type interruptedBundleRestoreStore struct {
	metastore.Store
	mu      sync.Mutex
	writes  int
	reached chan struct{}
	release chan struct{}
}

func (s *interruptedBundleRestoreStore) Put(ctx context.Context, doc metastore.Document) (metastore.Document, error) {
	if !isParserAssetCollection(doc.Collection) || ctx.Value(bundleRecoveryBypass{}) != true {
		return s.Store.Put(ctx, doc)
	}
	s.mu.Lock()
	s.writes++
	count := s.writes
	s.mu.Unlock()
	if count == 2 {
		close(s.reached)
		<-s.release
		if _, err := s.Store.Put(ctx, doc); err != nil {
			return metastore.Document{}, err
		}
		// Reproduce a remote write that committed before its response was lost.
		return metastore.Document{}, errors.New("test metadata write interrupted")
	}
	return s.Store.Put(ctx, doc)
}

func TestBundleRecoveryInterruptedApplyKeepsPriorPublicationAndResumesOnRestart(t *testing.T) {
	f := newAPIFixture(t)
	s := f.server
	ctx := context.Background()
	backup := createRecoveryTestBackup(t, f)
	putRecoveryTestSetting(t, s, "restore-disappear", `{"weight":2}`)
	restore := proposeRecoveryTestRestore(t, f, backup)
	loginParserSyncApprover(t, f)
	store := &interruptedBundleRestoreStore{Store: s.metadata, reached: make(chan struct{}), release: make(chan struct{})}
	s.metadata = store
	type result struct {
		status int
		body   []byte
	}
	done := make(chan result, 1)
	go func() {
		response, body := f.request(http.MethodPost, bundleRestoresRoute+"/"+restore.ID+"/approve", restoreTestApproval(restore))
		done <- result{response.StatusCode, body}
	}()
	select {
	case <-store.reached:
	case early := <-done:
		t.Fatalf("restore exited before safe apply interruption %d: %s", early.status, early.body)
	case <-time.After(10 * time.Second):
		close(store.release)
		t.Fatal("restore did not reach the interruption point")
	}
	visible, err := s.buildActiveParserBundle(ctx)
	if err != nil || visible.BundleHash != restore.BaseBundleHash {
		t.Errorf("partially applied publication became visible: %+v %v", visible, err)
	}
	if _, err := s.metadata.Put(ctx, metastore.Document{Collection: "regex-patterns", ID: "concurrent", State: "active", Payload: json.RawMessage(`{"name":"concurrent"}`)}); !errors.Is(err, errBundleRecoveryUnavailable) {
		t.Errorf("catalog write bypassed restoration gate: %v", err)
	}
	close(store.release)
	interrupted := <-done
	if interrupted.status != http.StatusServiceUnavailable {
		t.Fatalf("expected interrupted restore to report retryable state %d: %s", interrupted.status, interrupted.body)
	}
	response, body := f.request(http.MethodGet, bundleRestoresRoute, nil)
	if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"state":"applying"`)) {
		t.Fatalf("interrupted approval not visible %d: %s", response.StatusCode, body)
	}
	restarted, err := New(s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	recovered, err := restarted.getBundleRestoreRecord(ctx, restore.ID)
	if err != nil || recovered.State != bundleRestoreProposed || recovered.DesiredBundleHash == restore.BaseBundleHash {
		t.Fatalf("startup failed to resume approved restore: %+v %v", recovered, err)
	}
	actual, err := restarted.buildActiveParserBundle(ctx)
	if err != nil || actual.BundleHash != recovered.DesiredBundleHash {
		t.Fatalf("startup did not use the committed recovery generation: %+v %v", actual, err)
	}
	_, snapshot, err := restarted.readBundleBackup(ctx, backup.ID)
	if err != nil || verifyRestoredBundle(actual, snapshot.Bundle) != nil {
		t.Fatalf("old backup did not survive restart: %v", err)
	}
	for i, asset := range actual.Assets {
		if asset.Revision != snapshot.Bundle.Assets[i].Revision+1 {
			t.Fatalf("resume created a duplicate parser revision for %s: %d", asset.AssetID, asset.Revision)
		}
	}
}

func TestBundleRecoveryStaleAndTamperedBackupsFailClosed(t *testing.T) {
	f := newAPIFixture(t)
	s := f.server
	ctx := context.Background()
	backup := createRecoveryTestBackup(t, f)
	stale := proposeRecoveryTestRestore(t, f, backup)
	putRecoveryTestSetting(t, s, "new-after-proposal", `{"weight":2}`)
	tampered := proposeRecoveryTestRestore(t, f, backup)
	loginParserSyncApprover(t, f)
	if response, body := f.request(http.MethodPost, bundleRestoresRoute+"/"+stale.ID+"/approve", restoreTestApproval(stale)); response.StatusCode != http.StatusConflict || !bytes.Contains(body, []byte("changed")) {
		t.Fatalf("stale approval %d: %s", response.StatusCode, body)
	}
	if _, err := s.metadata.Put(ctx, metastore.Document{Collection: bundleBackupContent, ID: backup.ID, State: "verified", Payload: json.RawMessage(`{"bundle":{"assets":[]}}`)}); err != nil {
		t.Fatal(err)
	}
	if response, body := f.request(http.MethodGet, bundleBackupsRoute+"/"+backup.ID+"/export", nil); response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("tampered snapshot downloadable %d: %s", response.StatusCode, body)
	}
	if response, body := f.request(http.MethodPost, bundleRestoresRoute+"/"+tampered.ID+"/approve", restoreTestApproval(tampered)); response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("tampered snapshot was restorable %d: %s", response.StatusCode, body)
	}
	entry, _, err := s.readBundleRestoreJournal(ctx)
	if err != nil || entry.Restore.ID != "" {
		t.Fatalf("unverified snapshot reserved the restore journal: %+v %v", entry, err)
	}
	putRecoveryTestSetting(t, s, "unsupported-settings-test", `{"api_key":"not-for-export"}`)
	if response, body := f.request(http.MethodPost, bundleBackupsRoute, struct{}{}); response.StatusCode != http.StatusUnprocessableEntity || bytes.Contains(body, []byte("not-for-export")) {
		t.Fatalf("credential-bearing parser settings were not safely refused (%d)", response.StatusCode)
	}
}

func TestBundleRecoveryDistinguishesParserFieldNamesFromCredentials(t *testing.T) {
	f := newAPIFixture(t)
	s := f.server
	ctx := context.Background()
	fixtures := []struct {
		collection string
		id         string
		config     string
	}{
		{"templates", "symbolic-template", `{"engine":"re2","pattern":"^(?P<password>[^ ]+) (?P<api_key>[^ ]+)","fields":{"password":"password","api_key":"api_key"}}`},
		{"known-keys", "symbolic-known-keys", `{"keys":["password","api_key"],"aliases":{"password":"credential_field","api_key":"api_key"}}`},
		{"kv-config", "symbolic-kv", `{"pair_separators":[" "],"assignment_separators":["="],"key_aliases":{},"value_types":{"password":"string","api_key":"string"}}`},
	}
	for _, fixture := range fixtures {
		var config map[string]any
		if err := json.Unmarshal([]byte(fixture.config), &config); err != nil {
			t.Fatal(err)
		}
		if err := validateCatalogConfig(fixture.collection, config); err != nil {
			t.Fatalf("invalid symbolic %s fixture: %v", fixture.collection, err)
		}
		if _, err := s.putBundleRecoveryDocument(ctx, fixture.collection, fixture.id, "active", "test", map[string]any{"name": fixture.id, "config": config}); err != nil {
			t.Fatal(err)
		}
	}
	definition := map[string]any{"pattern_type": "regex", "pattern": `^(?P<password>[^ ]+) (?P<api_key>[^ ]+)$`, "fields": []any{
		map[string]any{"name": "password", "source": "group:password", "type": "string"},
		map[string]any{"name": "api_key", "source": "group:api_key", "type": "string"},
	}}
	pack, err := assuranceRuntimePack("symbolic-regex-pack", "1.0.0", "test", definition, []assuranceRequest{
		{Raw: "REDACTED_PASS REDACTED_KEY", Desired: map[string]any{"password": "REDACTED_PASS", "api_key": "REDACTED_KEY"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.putBundleRecoveryDocument(ctx, "parser-packs", pack.ID, "published", "test", map[string]any{"name": pack.ID, "runtime_pack": pack}); err != nil {
		t.Fatal(err)
	}
	backup := createRecoveryTestBackup(t, f)
	response, data := f.request(http.MethodGet, bundleBackupsRoute+"/"+backup.ID+"/export", nil)
	if response.StatusCode != http.StatusOK || !bytes.Contains(data, []byte(`"fields":{"api_key":"api_key","password":"password"}`)) ||
		!bytes.Contains(data, []byte(`"aliases":{"api_key":"api_key","password":"credential_field"}`)) ||
		!bytes.Contains(data, []byte(`"value_types":{"api_key":"string","password":"string"}`)) ||
		!bytes.Contains(data, []byte(`"groups":{"api_key":"api_key","password":"password"}`)) {
		t.Fatalf("backup did not preserve the verified field mappings exactly (HTTP %d)", response.StatusCode)
	}
	putRecoveryTestSetting(t, s, "literal-credential", `{"api_key":"synthetic-do-not-export"}`)
	response, data = f.request(http.MethodPost, bundleBackupsRoute, struct{}{})
	if response.StatusCode != http.StatusUnprocessableEntity || bytes.Contains(data, []byte("synthetic-do-not-export")) {
		t.Fatalf("literal credential property was not safely refused (HTTP %d)", response.StatusCode)
	}
	if !unsupportedBundleBackupSettings(map[string]any{"fields": map[string]any{"api_key": "outside-known-grammar"}}) {
		t.Fatal("untyped fields object bypassed the credential filter")
	}
}

type bundleRecoveryWriteFailure struct {
	metastore.Store
	collection string
	commit     bool
	once       sync.Once
}

func (s *bundleRecoveryWriteFailure) Put(ctx context.Context, doc metastore.Document) (metastore.Document, error) {
	if doc.Collection != s.collection {
		return s.Store.Put(ctx, doc)
	}
	failed := false
	s.once.Do(func() { failed = true })
	if !failed {
		return s.Store.Put(ctx, doc)
	}
	if s.commit {
		if _, err := s.Store.Put(ctx, doc); err != nil {
			return metastore.Document{}, err
		}
	}
	return metastore.Document{}, errors.New("test metadata response lost")
}

func TestBundleRecoveryCapturePublishesOnlyAfterDurableContent(t *testing.T) {
	f := newAPIFixture(t)
	s := f.server
	ctx := context.Background()
	initial := s.bundleAutomaticBackupStatus()
	if initial.State != "captured" || initial.SnapshotHash == "" {
		t.Fatalf("controller startup did not capture prior publication: %+v", initial)
	}
	putRecoveryTestSetting(t, s, "automatic-backup-change", `{"weight":3}`)
	current, err := s.buildActiveParserBundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s.metadata = &bundleRecoveryWriteFailure{Store: s.metadata, collection: bundleBackupCollection}
	if _, err := s.materializeParserBundle(current); err != nil {
		t.Fatalf("valid publication failed because backup manifest could not be saved: %v", err)
	}
	if _, err := s.materializeParserBundle(current); err != nil || s.bundleAutomaticBackupStatus().State != "failed" {
		t.Fatalf("automatic failure status or backoff not retained: %v", err)
	}
	response, body := f.request(http.MethodGet, bundleBackupsRoute, nil)
	var listed struct {
		Backups          []bundleBackupRecord        `json:"backups"`
		AutomaticCapture automaticBundleBackupStatus `json:"automatic_capture"`
	}
	if response.StatusCode != http.StatusOK || json.Unmarshal(body, &listed) != nil || len(listed.Backups) != 1 || listed.Backups[0].ID != initial.SnapshotHash || listed.AutomaticCapture.State != "failed" {
		t.Fatalf("interrupted backup leaked into browser %d: %s", response.StatusCode, body)
	}
	contents, err := s.metadata.List(ctx, bundleBackupContent, metastore.Query{Limit: 2})
	if err != nil || len(contents) != 2 || contents[0].ID == initial.SnapshotHash {
		t.Fatalf("expected one durable unlisted snapshot and the prior backup, got %d: %v", len(contents), err)
	}
	retried := createRecoveryTestBackup(t, f)
	doc, err := s.metadata.Get(ctx, bundleBackupContent, retried.ID, 0)
	if err != nil || retried.ID != contents[0].ID || doc.Revision != contents[0].Revision {
		t.Fatalf("retry did not reuse verified content: %s %v", retried.ID, err)
	}
}

func TestBundleRecoveryResumeFindsPreviouslyApprovedFleetProposal(t *testing.T) {
	f := newAPIFixture(t)
	s := f.server
	ctx := context.Background()
	s.fleet.Register(&fleet.Node{ID: "restored-remote-client", Version: "99.0.0"})
	backup := createRecoveryTestBackup(t, f)
	putRecoveryTestSetting(t, s, "restored-before-lost-handoff", `{"weight":42}`)
	restore := proposeRecoveryTestRestore(t, f, backup)
	loginParserSyncApprover(t, f)
	s.metadata = &bundleRecoveryWriteFailure{Store: s.metadata, collection: "rollout-proposals", commit: true}
	response, body := f.request(http.MethodPost, bundleRestoresRoute+"/"+restore.ID+"/approve", restoreTestApproval(restore))
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("lost rollout handoff response %d: %s", response.StatusCode, body)
	}
	stored, err := s.getBundleRestoreRecord(ctx, restore.ID)
	if err != nil || stored.State != bundleRestorePublished || stored.DesiredBundleHash == "" {
		t.Fatalf("restore publication not durable after lost response: %+v %v", stored, err)
	}
	proposalID := "parser-sync-" + restore.ID
	response, body = f.request(http.MethodPost, "/api/v1/rollouts/"+proposalID+"/approve", approvalRequest{Reason: "Approve the restored parser generation"})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("approval of existing Fleet Sync proposal %d: %s", response.StatusCode, body)
	}
	response, body = f.request(http.MethodPost, bundleRestoresRoute+"/"+restore.ID+"/resume", struct{}{})
	var resumed bundleRestoreRecord
	if response.StatusCode != http.StatusOK || json.Unmarshal(body, &resumed) != nil || resumed.RolloutProposalID != proposalID || resumed.State != bundleRestoreProposed {
		t.Fatalf("resume did not find the previously approved proposal %d: %s", response.StatusCode, body)
	}
	docs, err := s.listParserSyncDocuments(ctx, "rollout-proposals", "", 5)
	if err != nil || len(docs) != 1 || docs[0].State != "active" {
		t.Fatalf("expected one active fleet proposal after resume, got %d: %v", len(docs), err)
	}
}
