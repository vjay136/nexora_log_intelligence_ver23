package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"nexora.local/nli-v20/internal/canonicaljson"
	"nexora.local/nli-v20/internal/familyprofile"
	metastore "nexora.local/nli-v20/internal/store"
)

const (
	bundleRestorePending   = "pending_approval"
	bundleRestoreApplying  = "applying"
	bundleRestorePublished = "controller_published"
	bundleRestoreProposed  = "rollout_proposed"
)

type bundleRestoreRecord struct {
	ID                 string     `json:"id"`
	State              string     `json:"state"`
	BackupID           string     `json:"backup_id"`
	SnapshotHash       string     `json:"snapshot_hash"`
	BaseRevision       string     `json:"base_revision"`
	BaseBundleHash     string     `json:"base_bundle_hash"`
	Reason             string     `json:"reason"`
	ProposedBy         string     `json:"proposed_by"`
	ApprovedBy         string     `json:"approved_by,omitempty"`
	PreRestoreBackupID string     `json:"pre_restore_backup_id,omitempty"`
	DesiredRevision    int        `json:"desired_revision,omitempty"`
	DesiredBundleHash  string     `json:"desired_bundle_hash,omitempty"`
	RolloutProposalID  string     `json:"rollout_proposal_id,omitempty"`
	TargetNodes        []string   `json:"target_nodes,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	ApprovedAt         *time.Time `json:"approved_at,omitempty"`
}

type bundleRestoreOperation struct {
	Collection     string `json:"collection"`
	ID             string `json:"id"`
	BeforeRevision int    `json:"before_revision"`
	Publish        bool   `json:"publish"`
}

type bundleRestorePlan struct {
	RestoreID    string                   `json:"restore_id"`
	SnapshotHash string                   `json:"snapshot_hash"`
	Operations   []bundleRestoreOperation `json:"operations"`
}

type bundleRestoreJournalEntry struct {
	Restore  bundleRestoreRecord `json:"restore"`
	PlanHash string              `json:"plan_hash"`
}

// One controller owns parser publication. The same parser mutation mutex used
// by catalog and rollout handlers serializes restores. This gate also covers
// metadata writers such as migration that do not participate in that mutex,
// and holds the last complete desired bundle while a restore is in progress.
type bundleRecoveryGate struct {
	mu              sync.RWMutex
	blocked         bool
	previous        *parserAssetBundle
	captureMu       sync.Mutex
	automaticBackup atomic.Pointer[automaticBundleBackupStatus]
}

type bundleRecoveryBypass struct{}

type bundleRecoveryStore struct {
	metastore.Store
	gate *bundleRecoveryGate
}

func bundleRecoveryRawContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, bundleRecoveryBypass{}, true)
}

func (s *bundleRecoveryStore) enter(ctx context.Context, collection string) (func(), error) {
	if !isParserAssetCollection(collection) || ctx.Value(bundleRecoveryBypass{}) == true {
		return func() {}, nil
	}
	s.gate.mu.RLock()
	if s.gate.blocked {
		s.gate.mu.RUnlock()
		return nil, errBundleRecoveryUnavailable
	}
	return s.gate.mu.RUnlock, nil
}

func (s *bundleRecoveryStore) Get(ctx context.Context, collection, id string, revision int) (metastore.Document, error) {
	done, err := s.enter(ctx, collection)
	if err != nil {
		return metastore.Document{}, err
	}
	defer done()
	return s.Store.Get(ctx, collection, id, revision)
}

func (s *bundleRecoveryStore) List(ctx context.Context, collection string, query metastore.Query) ([]metastore.Document, error) {
	done, err := s.enter(ctx, collection)
	if err != nil {
		return nil, err
	}
	defer done()
	return s.Store.List(ctx, collection, query)
}

func (s *bundleRecoveryStore) Put(ctx context.Context, doc metastore.Document) (metastore.Document, error) {
	done, err := s.enter(ctx, doc.Collection)
	if err != nil {
		return metastore.Document{}, err
	}
	defer done()
	return s.Store.Put(ctx, doc)
}

func (s *bundleRecoveryStore) Delete(ctx context.Context, collection, id string, purge bool, actor string) error {
	done, err := s.enter(ctx, collection)
	if err != nil {
		return err
	}
	defer done()
	return s.Store.Delete(ctx, collection, id, purge, actor)
}

func (s *Server) buildActiveParserBundle(ctx context.Context) (parserAssetBundle, error) {
	gate := s.bundleRecovery
	if gate == nil {
		return s.buildPublishedParserBundle(ctx)
	}
	gate.mu.RLock()
	defer gate.mu.RUnlock()
	if gate.blocked {
		if gate.previous == nil {
			return parserAssetBundle{}, errBundleRecoveryUnavailable
		}
		return *gate.previous, nil
	}
	return s.buildPublishedParserBundle(bundleRecoveryRawContext(ctx))
}

// Guard readers that assemble their own runtime view from multiple catalog
// collections so their snapshot cannot straddle a recovery commit.
func (s *Server) beginBundleRecoveryRead(ctx context.Context) (context.Context, func(), error) {
	gate := s.bundleRecovery
	if gate == nil {
		return ctx, func() {}, nil
	}
	gate.mu.RLock()
	if gate.blocked {
		gate.mu.RUnlock()
		return ctx, nil, errBundleRecoveryUnavailable
	}
	return bundleRecoveryRawContext(ctx), gate.mu.RUnlock, nil
}

func (s *Server) initializeBundleRecovery(ctx context.Context) error {
	gate := &bundleRecoveryGate{}
	s.bundleRecovery = gate
	s.metadata = &bundleRecoveryStore{Store: s.metadata, gate: gate}
	entry, _, err := s.readBundleRestoreJournal(ctx)
	if err != nil || entry.Restore.ID == "" {
		return err
	}
	if entry.Restore.State == bundleRestoreApplying {
		gate.blocked = true
		// Validate the verified prior backup as the restart fallback. In
		// particular, never read a partially rewritten catalog as published.
		_, snapshot, err := s.readBundleBackup(ctx, entry.Restore.PreRestoreBackupID)
		if err != nil || snapshot.Bundle.BundleHash != entry.Restore.BaseBundleHash {
			return fmt.Errorf("recover pre-restore bundle: %w", errors.Join(errBundleRecoveryIntegrity, err))
		}
		gate.previous = &snapshot.Bundle
		// Temporary metadata failures leave the previous publication available
		// and the approved restore resumable through its normal endpoint.
		_, _ = s.resumeBundleRestore(ctx, entry.Restore.ID)
		return nil
	}
	// The last durable controller publication may already be fully handed off.
	// Attempt an interrupted handoff once, without making startup depend on the
	// fleet proposal store beyond its ordinary metadata dependencies.
	_, _ = s.resumeBundleRestore(ctx, entry.Restore.ID)
	return nil
}

func (s *Server) readBundleRestoreJournal(ctx context.Context) (bundleRestoreJournalEntry, int, error) {
	var entry bundleRestoreJournalEntry
	doc, err := s.metadata.Get(ctx, bundleRestoreJournal, bundleJournalID, 0)
	if errors.Is(err, os.ErrNotExist) {
		return entry, 0, nil
	}
	if err != nil {
		return entry, 0, err
	}
	if json.Unmarshal(doc.Payload, &entry) != nil || !validRuntimeParserID(entry.Restore.ID) || !validBundleRecoverySHA(entry.PlanHash) ||
		doc.State != entry.Restore.State || (doc.State != bundleRestoreApplying && doc.State != bundleRestorePublished) ||
		entry.Restore.ApprovedBy == "" || entry.Restore.ApprovedAt == nil || entry.Restore.ApprovedBy == entry.Restore.ProposedBy ||
		!validBundleRecoverySHA(entry.Restore.PreRestoreBackupID) {
		return entry, 0, errBundleRecoveryIntegrity
	}
	if doc.State == bundleRestorePublished {
		if !validBundleRecoverySHA(entry.Restore.DesiredBundleHash) {
			return entry, 0, errBundleRecoveryIntegrity
		}
		entry.Restore.DesiredRevision = doc.Revision
	}
	return entry, doc.Revision, nil
}

// A failed write response may have committed remotely. Inspect the final
// journal before retrying the operation or releasing the publication gate.
func (s *Server) putBundleRestoreJournal(ctx context.Context, entry bundleRestoreJournalEntry) (int, error) {
	doc, err := s.putBundleRecoveryDocument(ctx, bundleRestoreJournal, bundleJournalID, entry.Restore.State, entry.Restore.ApprovedBy, entry)
	if err == nil {
		return doc.Revision, nil
	}
	observed, revision, readErr := s.readBundleRestoreJournal(ctx)
	if readErr == nil && observed.Restore.ID == entry.Restore.ID && observed.Restore.State == entry.Restore.State && observed.PlanHash == entry.PlanHash && observed.Restore.DesiredBundleHash == entry.Restore.DesiredBundleHash {
		return revision, nil
	}
	return 0, err
}

func bundleRestoreBase(bundle parserAssetBundle, journalRevision int) string {
	return bundleRecoverySHA([]byte(fmt.Sprintf("%s\n%d", bundle.BundleHash, journalRevision)))
}

func readBundleRestoreRecord(doc metastore.Document) (bundleRestoreRecord, error) {
	var record bundleRestoreRecord
	if json.Unmarshal(doc.Payload, &record) != nil || record.State != doc.State || record.ID != doc.ID ||
		record.ProposedBy == "" || record.ProposedBy != doc.CreatedBy || record.BackupID != record.SnapshotHash ||
		!validBundleRecoverySHA(record.BackupID) || !validBundleRecoverySHA(record.BaseRevision) || !validBundleRecoverySHA(record.BaseBundleHash) {
		return record, errBundleRecoveryIntegrity
	}
	return record, nil
}

func (s *Server) getBundleRestoreRecord(ctx context.Context, id string) (bundleRestoreRecord, error) {
	doc, err := s.metadata.Get(ctx, bundleRestoreRecords, id, 0)
	if err != nil {
		return bundleRestoreRecord{}, err
	}
	return readBundleRestoreRecord(doc)
}

func (s *Server) saveBundleRestoreRecord(ctx context.Context, record bundleRestoreRecord) error {
	_, err := s.putBundleRecoveryDocument(ctx, bundleRestoreRecords, record.ID, record.State, record.ProposedBy, record)
	return err
}

func (s *Server) prepareBundleRestorePlan(ctx context.Context, record bundleRestoreRecord, snapshot bundleBackupSnapshot) (bundleRestorePlan, error) {
	plan := bundleRestorePlan{RestoreID: record.ID, SnapshotHash: record.SnapshotHash, Operations: []bundleRestoreOperation{}}
	var operations = make(map[string]bundleRestoreOperation)
	for _, asset := range snapshot.Bundle.Assets {
		key := asset.AssetClass + "/" + asset.AssetID
		operations[key] = bundleRestoreOperation{Collection: asset.AssetClass, ID: asset.AssetID, Publish: true}
	}
	// Revoke each active catalog identity that will no longer be represented.
	// Imported packs can use a catalog ID distinct from their runtime pack ID.
	// Restore by the stable runtime ID and retain former alias histories.
	for _, collection := range parserAssetCollections {
		published, err := s.listEffectiveParserAssets(ctx, collection)
		if err != nil {
			return plan, err
		}
		for _, doc := range published {
			key := collection + "/" + doc.ID
			if _, willPublish := operations[key]; willPublish {
				continue
			}
			if collection == "parser-packs" {
				pack, _, err := runtimeParserPackForDocumentContext(ctx, doc)
				if ctx.Err() != nil {
					return plan, ctx.Err()
				}
				if err != nil || familyprofile.IsBuiltinPackID(pack.ID) {
					continue // A blocked record or embedded reference is outside the managed bundle.
				}
			}
			operations[key] = bundleRestoreOperation{Collection: collection, ID: doc.ID}
		}
	}
	if len(operations) == 0 {
		return plan, errors.New("an empty publication has no parser revisions to restore")
	}
	if len(operations) > bundleRestoreMaxAssets {
		return plan, errBundleBackupSize
	}
	keys := make([]string, 0, len(operations))
	for key := range operations {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		op := operations[key]
		current, err := s.metadata.Get(ctx, op.Collection, op.ID, 0)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return plan, err
		}
		op.BeforeRevision = current.Revision
		plan.Operations = append(plan.Operations, op)
	}
	return plan, nil
}

// Caller holds parserMutationMu. The gate excludes catalog access while the
// exact base is checked and the approved journal is persisted.
func (s *Server) beginBundleRestore(ctx context.Context, record bundleRestoreRecord, approver string) (bundleRestoreRecord, error) {
	gate := s.bundleRecovery
	gate.mu.Lock()
	rawCtx := bundleRecoveryRawContext(ctx)
	entry, revision, err := s.readBundleRestoreJournal(ctx)
	if err == nil {
		err = s.reserveBundleRestore(rawCtx, &record, entry, revision, approver)
	}
	gate.mu.Unlock()
	if err != nil {
		return record, err
	}
	return s.resumeBundleRestore(ctx, record.ID)
}

func (s *Server) reserveBundleRestore(ctx context.Context, record *bundleRestoreRecord, previous bundleRestoreJournalEntry, revision int, approver string) error {
	if previous.Restore.State == bundleRestoreApplying {
		return errBundleRecoveryUnavailable
	}
	if previous.Restore.ID != "" {
		if _, err := s.reconcileBundleRestoreLedger(ctx, previous.Restore); err != nil {
			return err
		}
		if previous.Restore.ID == record.ID {
			return errBundleRecoveryStale
		}
	}
	current, err := s.buildPublishedParserBundle(ctx)
	if err != nil {
		return err
	}
	if record.BaseRevision != bundleRestoreBase(current, revision) || record.BaseBundleHash != current.BundleHash {
		return errBundleRecoveryStale
	}
	_, snapshot, err := s.readBundleBackup(ctx, record.BackupID)
	if err != nil {
		return err
	}
	embedded, err := bundleRecoveryEmbeddedInventory()
	if err != nil {
		return err
	}
	if !slices.Equal(snapshot.EmbeddedParsers, embedded) {
		return errBundleBackupEmbedded
	}
	preRestore, err := s.captureBundleBackup(ctx, current, approver, "pre_restore")
	if err != nil {
		return err
	}
	plan, err := s.prepareBundleRestorePlan(ctx, *record, snapshot)
	if err != nil {
		return err
	}
	encoded, err := canonicalBundleRecoveryData(plan)
	if err != nil {
		return err
	}
	planHash := bundleRecoverySHA(encoded)
	if err := s.storeBundleRestorePlan(ctx, approver, planHash, encoded); err != nil {
		return err
	}
	now := time.Now().UTC()
	record.ApprovedBy, record.ApprovedAt = approver, &now
	record.PreRestoreBackupID, record.State = preRestore.ID, bundleRestoreApplying
	entry := bundleRestoreJournalEntry{Restore: *record, PlanHash: planHash}
	if _, err := s.putBundleRestoreJournal(ctx, entry); err != nil {
		// A timeout may have accepted approval. Fail closed until the durable
		// journal can be inspected on the next resume or startup.
		s.bundleRecovery.blocked, s.bundleRecovery.previous = true, &current
		return err
	}
	s.bundleRecovery.blocked, s.bundleRecovery.previous = true, &current
	return nil
}

func (s *Server) storeBundleRestorePlan(ctx context.Context, actor, planHash string, encoded []byte) error {
	doc, err := s.metadata.Get(ctx, bundleRestorePlans, planHash, 0)
	if errors.Is(err, os.ErrNotExist) {
		_, err = s.metadata.Put(ctx, metastore.Document{Collection: bundleRestorePlans, ID: planHash, State: "verified", CreatedBy: actor, Payload: encoded})
		return err
	}
	if err != nil {
		return err
	}
	canonical, err := canonicaljson.Normalize(doc.Payload)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return errBundleRecoveryIntegrity
	}
	return nil
}

func (s *Server) readBundleRestorePlan(ctx context.Context, entry bundleRestoreJournalEntry) (bundleRestorePlan, error) {
	var plan bundleRestorePlan
	doc, err := s.metadata.Get(ctx, bundleRestorePlans, entry.PlanHash, 0)
	if err != nil {
		return plan, err
	}
	canonical, err := canonicaljson.Normalize(doc.Payload)
	if err != nil || bundleRecoverySHA(canonical) != entry.PlanHash || json.Unmarshal(doc.Payload, &plan) != nil ||
		plan.RestoreID != entry.Restore.ID || plan.SnapshotHash != entry.Restore.SnapshotHash || len(plan.Operations) == 0 || len(plan.Operations) > bundleRestoreMaxAssets {
		return plan, errBundleRecoveryIntegrity
	}
	previous := ""
	for _, op := range plan.Operations {
		key := op.Collection + "/" + op.ID
		if key <= previous || !isParserAssetCollection(op.Collection) || !validRuntimeParserID(op.ID) || op.BeforeRevision < 0 {
			return plan, errBundleRecoveryIntegrity
		}
		previous = key
	}
	return plan, nil
}

func (s *Server) applyBundleRestore(ctx context.Context, entry bundleRestoreJournalEntry) (bundleRestoreRecord, error) {
	record := entry.Restore
	plan, err := s.readBundleRestorePlan(ctx, entry)
	if err != nil {
		return record, err
	}
	_, snapshot, err := s.readBundleBackup(ctx, record.BackupID)
	if err != nil {
		return record, err
	}
	assets := make(map[string]parserBundleAsset, len(snapshot.Bundle.Assets))
	for _, asset := range snapshot.Bundle.Assets {
		assets[asset.AssetClass+"/"+asset.AssetID] = asset
	}
	rawCtx := bundleRecoveryRawContext(ctx)
	for _, op := range plan.Operations {
		asset, publish := assets[op.Collection+"/"+op.ID]
		if op.Publish != publish {
			return record, errBundleRecoveryIntegrity
		}
		state, payload, err := bundleRestoreOperationPayload(op, asset, record.ID)
		if err != nil {
			return record, err
		}
		if err := s.applyBundleRestoreOperation(rawCtx, op, state, payload, record.ApprovedBy); err != nil {
			return record, err
		}
	}
	actual, err := s.buildPublishedParserBundle(rawCtx)
	if err != nil {
		return record, err
	}
	if err := verifyRestoredBundle(actual, snapshot.Bundle); err != nil {
		return record, err
	}
	if actual.BundleHash == record.BaseBundleHash {
		return record, fmt.Errorf("%w: restore did not create a new parser generation", errBundleRecoveryIntegrity)
	}
	entry.Restore.State, entry.Restore.DesiredBundleHash = bundleRestorePublished, actual.BundleHash
	gate := s.bundleRecovery
	gate.mu.Lock()
	revision, err := s.putBundleRestoreJournal(ctx, entry)
	if err == nil {
		gate.blocked, gate.previous = false, nil
	}
	gate.mu.Unlock()
	if err != nil {
		return record, err
	}
	entry.Restore.DesiredRevision = revision
	return entry.Restore, nil
}

func bundleRestoreOperationPayload(op bundleRestoreOperation, asset parserBundleAsset, restoreID string) (string, json.RawMessage, error) {
	if !op.Publish {
		payload, err := json.Marshal(map[string]string{"bundle_restore_id": restoreID})
		return "revoked", payload, err
	}
	if op.Collection != "parser-packs" {
		return "active", asset.Payload, nil
	}
	// Preserve the exact sealed runtime definition, including its author,
	// runtime identity, and embedded validated cases. The enclosing catalog
	// document receives a new storage revision for the restored publication.
	payload, err := json.Marshal(struct {
		Name        string          `json:"name"`
		RuntimePack json.RawMessage `json:"runtime_pack"`
	}{asset.Name, asset.Payload})
	return "published", payload, err
}

func (s *Server) applyBundleRestoreOperation(ctx context.Context, op bundleRestoreOperation, state string, payload json.RawMessage, actor string) error {
	current, err := s.metadata.Get(ctx, op.Collection, op.ID, 0)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if current.Revision > op.BeforeRevision && current.State == state {
		actual, actualErr := canonicaljson.Normalize(current.Payload)
		expected, expectedErr := canonicaljson.Normalize(payload)
		if actualErr == nil && expectedErr == nil && bytes.Equal(actual, expected) {
			return nil // The prior attempt committed this exact revision.
		}
	}
	if current.Revision != op.BeforeRevision {
		return fmt.Errorf("%w: parser catalog head changed during restore", errBundleRecoveryIntegrity)
	}
	_, err = s.metadata.Put(ctx, metastore.Document{Collection: op.Collection, ID: op.ID, State: state, Payload: payload, CreatedBy: actor})
	return err
}

func verifyRestoredBundle(actual, source parserAssetBundle) error {
	if len(actual.Assets) != len(source.Assets) {
		return fmt.Errorf("%w: restored parser asset count differs from snapshot", errBundleRecoveryIntegrity)
	}
	for i, expected := range source.Assets {
		asset := actual.Assets[i]
		if asset.AssetClass != expected.AssetClass || asset.AssetID != expected.AssetID || asset.Name != expected.Name || asset.SHA256 != expected.SHA256 {
			return fmt.Errorf("%w: restored parser asset differs from snapshot", errBundleRecoveryIntegrity)
		}
	}
	return nil
}

func (s *Server) reconcileBundleRestoreLedger(ctx context.Context, committed bundleRestoreRecord) (bundleRestoreRecord, error) {
	existing, err := s.getBundleRestoreRecord(ctx, committed.ID)
	if err != nil {
		return committed, err
	}
	if existing.State == bundleRestoreProposed || existing.State == bundleRestorePublished {
		if existing.DesiredBundleHash != committed.DesiredBundleHash || existing.DesiredRevision != committed.DesiredRevision {
			return committed, errBundleRecoveryIntegrity
		}
		return existing, nil
	}
	if existing.State != bundleRestorePending || existing.BaseRevision != committed.BaseRevision || existing.SnapshotHash != committed.SnapshotHash || existing.ProposedBy != committed.ProposedBy {
		return committed, errBundleRecoveryIntegrity
	}
	return committed, s.saveBundleRestoreRecord(ctx, committed)
}

// Caller holds parserMutationMu except during controller construction. Repeat
// only the journaled restore and hand the exact generation to Fleet Sync.
func (s *Server) resumeBundleRestore(ctx context.Context, id string) (bundleRestoreRecord, error) {
	record, err := s.getBundleRestoreRecord(ctx, id)
	if err != nil || record.State == bundleRestoreProposed {
		return record, err
	}
	entry, _, err := s.readBundleRestoreJournal(ctx)
	if err != nil {
		return record, err
	}
	if entry.Restore.ID != id {
		// A reported approval write failure may have left a local reservation
		// even though the metadata journal never accepted an approval.
		if entry.Restore.State != bundleRestoreApplying {
			s.releaseBundleRecoveryGate()
		}
		return record, errBundleRecoveryStale
	}
	if entry.Restore.State == bundleRestoreApplying {
		if _, err := s.applyBundleRestore(ctx, entry); err != nil {
			return entry.Restore, err
		}
		entry, _, err = s.readBundleRestoreJournal(ctx)
		if err != nil {
			return record, err
		}
	} else {
		s.releaseBundleRecoveryGate()
	}
	record, err = s.reconcileBundleRestoreLedger(ctx, entry.Restore)
	if err != nil || record.State == bundleRestoreProposed {
		return record, err
	}
	current, err := s.buildActiveParserBundle(ctx)
	if err != nil {
		return record, err
	}
	if current.BundleHash != record.DesiredBundleHash {
		return record, errBundleRecoveryStale
	}
	if _, err := s.materializeParserBundle(current); err != nil {
		return record, err
	}
	proposal, err := s.proposeParserBundleRolloutWithID(ctx, "parser-sync-"+record.ID, record.ProposedBy, "Roll out restored parser bundle", "Restored publication requires independent Fleet Sync approval and exact client acknowledgement.", "all_eligible", current, nil)
	if err != nil {
		return record, err
	}
	var targets struct {
		TargetNodes []string `json:"target_nodes"`
	}
	if err := json.Unmarshal(proposal.Payload, &targets); err != nil {
		return record, errBundleRecoveryIntegrity
	}
	record.RolloutProposalID = proposal.ID
	record.TargetNodes = targets.TargetNodes
	record.State = bundleRestoreProposed
	if err := s.saveBundleRestoreRecord(ctx, record); err != nil {
		return record, err
	}
	return record, nil
}

func (s *Server) releaseBundleRecoveryGate() {
	gate := s.bundleRecovery
	gate.mu.Lock()
	gate.blocked, gate.previous = false, nil
	gate.mu.Unlock()
}
