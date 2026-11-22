package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"nexora.local/nli-v20/internal/canonicaljson"
	"nexora.local/nli-v20/internal/engine"
	"nexora.local/nli-v20/internal/familyprofile"
	"nexora.local/nli-v20/internal/mixedkv"
	metastore "nexora.local/nli-v20/internal/store"
	parserpolicy "nexora.local/nli-v20/parser-policy"
)

const (
	bundleBackupCollection = "bundle-backups"
	bundleBackupContent    = "bundle-backup-content"
	bundleRestoreRecords   = "bundle-restores"
	bundleRestorePlans     = "bundle-restore-plans"
	bundleRestoreJournal   = "bundle-restore-journal"
	bundleJournalID        = "current"
	bundleBackupSchema     = 1
	// Leave room within the 4 MiB metadata limit for the fleet proposal and
	// its target set. Extreme target counts remain subject to fleet limits.
	bundleBackupMaxBytes   = 3 << 20
	bundleRestoreMaxAssets = 10000
)

var (
	bundleBackupSettings         = []string{"known-keys", "kv-config", "projections", "regex-patterns", "semantic-extraction", "static-patterns", "templates"}
	errBundleBackupSize          = errors.New("parser backup exceeds the 3 MiB or 10,000-asset limit")
	errBundleBackupUnsafe        = errors.New("published parser settings contain an unsupported credential or source-data field")
	errBundleBackupEmbedded      = errors.New("backup references a different embedded parser inventory; obtain its matching controller release before restoring")
	errBundleRecoveryUnavailable = errors.New("parser catalog is reserved by an approved restoration; resume the restore to finish publication")
	errBundleRecoveryStale       = errors.New("published parser bundle has changed; prepare a new restore proposal")
	errBundleRecoveryIntegrity   = errors.New("bundle recovery integrity verification failed")
)

type bundleBackupScope struct {
	IncludesEmbeddedValidationExamples bool `json:"includes_embedded_validation_examples"`
}

type bundleBackupSnapshot struct {
	SchemaVersion   int                             `json:"schema_version"`
	Release         string                          `json:"release"`
	SettingsScope   []string                        `json:"settings_scope"`
	Scope           bundleBackupScope               `json:"scope"`
	EmbeddedParsers []familyprofile.BuiltinPackInfo `json:"embedded_parsers"`
	Bundle          parserAssetBundle               `json:"bundle"`
}

type bundleBackupRecord struct {
	ID                  string            `json:"id"`
	SnapshotHash        string            `json:"snapshot_hash"`
	BundleHash          string            `json:"bundle_hash"`
	SchemaVersion       int               `json:"schema_version"`
	Version             int               `json:"version"`
	Release             string            `json:"release"`
	AssetCount          int               `json:"asset_count"`
	EmbeddedParserCount int               `json:"embedded_parser_count"`
	AssetCounts         map[string]int    `json:"asset_counts"`
	SettingsScope       []string          `json:"settings_scope"`
	Scope               bundleBackupScope `json:"scope"`
	CreatedAt           time.Time         `json:"created_at"`
	Kind                string            `json:"kind"`
}

type bundleBackupExport struct {
	Backup   bundleBackupRecord   `json:"backup"`
	Snapshot bundleBackupSnapshot `json:"snapshot"`
}

type automaticBundleBackupStatus struct {
	State        string     `json:"state"`
	BundleHash   string     `json:"bundle_hash,omitempty"`
	SnapshotHash string     `json:"snapshot_hash,omitempty"`
	CheckedAt    *time.Time `json:"checked_at,omitempty"`
	Error        string     `json:"error,omitempty"`
}

func bundleRecoveryEmbeddedInventory() ([]familyprofile.BuiltinPackInfo, error) {
	packs, err := familyprofile.BuiltinPackInventory()
	slices.SortFunc(packs, func(left, right familyprofile.BuiltinPackInfo) int { return strings.Compare(left.ID, right.ID) })
	return packs, err
}

func bundleRecoverySHA(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func validBundleRecoverySHA(hash string) bool {
	return len(hash) == 64 && strings.ToLower(hash) == hash && validLegacyBundleHash(hash)
}

func canonicalBundleRecoveryData(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return canonicaljson.Normalize(encoded)
}

// The snapshot contains only the published wire bundle. Its parser catalog
// settings are the seven enumerated classes, with embedded pack validation
// inputs preserved as part of the reviewed definition. Controller settings,
// users, logs, retained Assurance cases and credential stores are never read.
func (s *Server) captureBundleBackup(ctx context.Context, bundle parserAssetBundle, actor, kind string) (bundleBackupRecord, error) {
	if gate := s.bundleRecovery; gate != nil {
		gate.captureMu.Lock()
		defer gate.captureMu.Unlock()
	}
	embedded, err := bundleRecoveryEmbeddedInventory()
	if err != nil {
		return bundleBackupRecord{}, err
	}
	snapshot := bundleBackupSnapshot{
		SchemaVersion:   bundleBackupSchema,
		Release:         engine.ReleaseID,
		SettingsScope:   bundleBackupSettings,
		Scope:           bundleBackupScope{IncludesEmbeddedValidationExamples: true},
		EmbeddedParsers: embedded,
		Bundle:          bundle,
	}
	encoded, err := verifyBundleBackupSnapshot(snapshot)
	if err != nil {
		return bundleBackupRecord{}, err
	}
	id := bundleRecoverySHA(encoded)
	record, _, err := s.readBundleBackup(ctx, id)
	if err == nil {
		return record, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return bundleBackupRecord{}, err
	}
	// Publish the small browse record after the exact content is durable.
	// An interrupted capture leaves at most an unlisted content blob.
	content, err := s.metadata.Get(ctx, bundleBackupContent, id, 0)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if _, err = s.metadata.Put(ctx, metastore.Document{Collection: bundleBackupContent, ID: id, State: "verified", Payload: encoded, CreatedBy: actor}); err != nil {
			return bundleBackupRecord{}, err
		}
	case err != nil:
		return bundleBackupRecord{}, err
	default:
		canonical, canonicalErr := canonicaljson.Normalize(content.Payload)
		if canonicalErr != nil || !bytes.Equal(canonical, encoded) {
			return bundleBackupRecord{}, errBundleRecoveryIntegrity
		}
	}
	record = describeBundleBackup(snapshot, id, kind, time.Now().UTC())
	if _, err := s.putBundleRecoveryDocument(ctx, bundleBackupCollection, id, "verified", actor, record); err != nil {
		return bundleBackupRecord{}, err
	}
	return record, nil
}

// Materialization serializes this hook. Cache the successful digest and back
// off failures so ordinary reconciliation does not repeatedly hit the store.
func (s *Server) captureAutomaticBundleBackup(bundle parserAssetBundle) {
	gate := s.bundleRecovery
	if gate == nil {
		return
	}
	previous := gate.automaticBackup.Load()
	if previous != nil && previous.BundleHash == bundle.BundleHash &&
		(previous.State == "captured" || previous.CheckedAt != nil && time.Since(*previous.CheckedAt) < time.Minute) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	record, err := s.captureBundleBackup(ctx, bundle, "controller", "automatic")
	now := time.Now().UTC()
	status := &automaticBundleBackupStatus{State: "captured", BundleHash: bundle.BundleHash, SnapshotHash: record.SnapshotHash, CheckedAt: &now}
	if err != nil {
		status.State = "failed"
		status.Error = "Automatic backup could not be saved. Earlier backups are still available."
		if errors.Is(err, errBundleBackupUnsafe) || errors.Is(err, errBundleBackupSize) {
			status.Error = err.Error()
		}
	}
	gate.automaticBackup.Store(status)
}

func (s *Server) bundleAutomaticBackupStatus() automaticBundleBackupStatus {
	if gate := s.bundleRecovery; gate != nil {
		if status := gate.automaticBackup.Load(); status != nil {
			return *status
		}
	}
	return automaticBundleBackupStatus{State: "pending"}
}

func describeBundleBackup(snapshot bundleBackupSnapshot, id, kind string, createdAt time.Time) bundleBackupRecord {
	counts := make(map[string]int, len(parserAssetCollections))
	for _, collection := range parserAssetCollections {
		counts[collection] = 0
	}
	for _, asset := range snapshot.Bundle.Assets {
		counts[asset.AssetClass]++
	}
	return bundleBackupRecord{ID: id, SnapshotHash: id, BundleHash: snapshot.Bundle.BundleHash, SchemaVersion: snapshot.SchemaVersion,
		Version: snapshot.SchemaVersion, Release: snapshot.Release, AssetCount: len(snapshot.Bundle.Assets), EmbeddedParserCount: len(snapshot.EmbeddedParsers), AssetCounts: counts,
		SettingsScope: snapshot.SettingsScope, Scope: snapshot.Scope, CreatedAt: createdAt, Kind: kind}
}

func readBundleBackupRecord(doc metastore.Document) (bundleBackupRecord, error) {
	var record bundleBackupRecord
	if doc.State != "verified" || json.Unmarshal(doc.Payload, &record) != nil || !validBundleRecoverySHA(doc.ID) || doc.ID != record.ID || record.SnapshotHash != record.ID {
		return bundleBackupRecord{}, errBundleRecoveryIntegrity
	}
	return record, nil
}

func (s *Server) readBundleBackup(ctx context.Context, id string) (bundleBackupRecord, bundleBackupSnapshot, error) {
	var snapshot bundleBackupSnapshot
	doc, err := s.metadata.Get(ctx, bundleBackupCollection, id, 0)
	if err != nil {
		return bundleBackupRecord{}, snapshot, err
	}
	record, err := readBundleBackupRecord(doc)
	if err != nil {
		return record, snapshot, err
	}
	content, err := s.metadata.Get(ctx, bundleBackupContent, id, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			err = errBundleRecoveryIntegrity
		}
		return record, snapshot, err
	}
	// PostgreSQL jsonb and other stores can add insignificant whitespace to
	// the payload. Enforce the backup byte limit after canonicalization below.
	if len(content.Payload) > 4<<20 || content.State != "verified" || json.Unmarshal(content.Payload, &snapshot) != nil {
		return record, snapshot, errBundleRecoveryIntegrity
	}
	canonical, err := verifyBundleBackupSnapshot(snapshot)
	stored, storedErr := canonicaljson.Normalize(content.Payload)
	if err != nil || storedErr != nil || !bytes.Equal(canonical, stored) || bundleRecoverySHA(canonical) != id {
		return record, snapshot, errBundleRecoveryIntegrity
	}
	derived, _ := canonicalBundleRecoveryData(describeBundleBackup(snapshot, id, record.Kind, record.CreatedAt))
	manifest, manifestErr := canonicaljson.Normalize(doc.Payload)
	if manifestErr != nil || !bytes.Equal(derived, manifest) {
		return record, snapshot, errBundleRecoveryIntegrity
	}
	return record, snapshot, nil
}

func verifyBundleBackupSnapshot(snapshot bundleBackupSnapshot) ([]byte, error) {
	bundle := snapshot.Bundle
	if snapshot.SchemaVersion != bundleBackupSchema || bundle.SchemaVersion != 1 || snapshot.Release == "" || len(snapshot.Release) > 128 ||
		!slices.Equal(snapshot.SettingsScope, bundleBackupSettings) || !snapshot.Scope.IncludesEmbeddedValidationExamples || !validBundleRecoverySHA(bundle.BundleHash) {
		return nil, errBundleRecoveryIntegrity
	}
	if len(bundle.Assets) > bundleRestoreMaxAssets {
		return nil, errBundleBackupSize
	}
	if len(snapshot.EmbeddedParsers) == 0 || len(snapshot.EmbeddedParsers) > 256 {
		return nil, errBundleRecoveryIntegrity
	}
	for index, pack := range snapshot.EmbeddedParsers {
		if !validRuntimeParserID(pack.ID) || !validBundleRecoverySHA(pack.SHA256) || pack.Version == "" || pack.Revision <= 0 ||
			(index > 0 && snapshot.EmbeddedParsers[index-1].ID >= pack.ID) {
			return nil, errBundleRecoveryIntegrity
		}
	}
	previous := ""
	for _, asset := range bundle.Assets {
		key := asset.AssetClass + "/" + asset.AssetID
		if key <= previous || !isParserAssetCollection(asset.AssetClass) || !validRuntimeParserID(asset.AssetID) || asset.Revision <= 0 {
			return nil, errBundleRecoveryIntegrity
		}
		previous = key
		canonical, err := canonicaljson.Normalize(asset.Payload)
		if err != nil || bundleRecoverySHA(canonical) != asset.SHA256 {
			return nil, errBundleRecoveryIntegrity
		}
		if asset.AssetClass == "parser-packs" {
			pack, err := parserpolicy.LoadParserPackBytes(canonical)
			if err != nil || pack.ID != asset.AssetID || (pack.ReviewState != parserpolicy.ReviewStateApproved && pack.ReviewState != parserpolicy.ReviewStateActivated) {
				return nil, errBundleRecoveryIntegrity
			}
			for _, rule := range pack.Rules {
				for _, stage := range rule.Stages {
					if unsupportedBundleBackupStageSettings(stage) {
						return nil, fmt.Errorf("%w in %s", errBundleBackupUnsafe, key)
					}
				}
			}
			continue
		}
		var envelope map[string]any
		if err := json.Unmarshal(canonical, &envelope); err != nil || envelope == nil {
			return nil, errBundleRecoveryIntegrity
		}
		// Legacy catalog recipes are intentionally retained in the published
		// wire bundle even when they are ignored by the current runtime. A
		// snapshot of an existing publication preserves those exact settings.
		config, ok := envelope["config"].(map[string]any)
		if envelope["config"] != nil && !ok {
			return nil, fmt.Errorf("%w: invalid published settings %s", errBundleRecoveryIntegrity, key)
		}
		if unsupportedBundleBackupMap(envelope, "config") || unsupportedBundleBackupMap(config, bundleBackupSymbolicSetting(asset.AssetClass, config)) {
			return nil, fmt.Errorf("%w in %s", errBundleBackupUnsafe, key)
		}
	}
	digest, _, err := bundleDigest(bundle)
	if err != nil || digest != bundle.BundleHash {
		return nil, errBundleRecoveryIntegrity
	}
	encoded, err := canonicalBundleRecoveryData(snapshot)
	if err != nil {
		return nil, err
	}
	if len(encoded) > bundleBackupMaxBytes {
		return nil, errBundleBackupSize
	}
	return encoded, nil
}

// Exclude only a grammar-defined map at the current settings level. Keys
// such as password or api_key describe extracted fields in these maps.
func bundleBackupSymbolicSetting(collection string, config map[string]any) string {
	switch collection {
	case "templates":
		if config["fields"] != nil && validateCatalogConfig(collection, config) == nil {
			return "fields"
		}
	case "known-keys":
		aliases, ok := config["aliases"].(map[string]any)
		if !ok || validateCatalogConfig(collection, config) != nil {
			return ""
		}
		keys := make(map[string]bool)
		for _, key := range config["keys"].([]any) {
			keys[key.(string)] = true
		}
		for key, value := range aliases {
			alias, ok := value.(string)
			if !ok || !keys[key] || !knownCatalogKeyPattern.MatchString(alias) {
				return ""
			}
		}
		return "aliases"
	case "kv-config":
		if config["value_types"] != nil {
			encoded, err := json.Marshal(config)
			var profile mixedkv.Config
			if err == nil && strictJSON(encoded, &profile) == nil {
				if _, err := mixedkv.Compile(profile); err == nil {
					return "value_types"
				}
			}
		}
	}
	return ""
}

func unsupportedBundleBackupStageSettings(stage parserpolicy.Stage) bool {
	config, ok := stage.Config.(map[string]any)
	if !ok || stage.Type != parserpolicy.StageTypeRegex {
		return unsupportedBundleBackupSettings(stage.Config)
	}
	groups, ok := config["groups"].(map[string]any)
	if !ok {
		return unsupportedBundleBackupSettings(config)
	}
	pattern, _ := config["pattern"].(string)
	re, err := regexp.Compile(pattern)
	if err != nil {
		return unsupportedBundleBackupSettings(config)
	}
	for group, value := range groups {
		alias, ok := value.(string)
		if !ok || re.SubexpIndex(group) < 1 || (alias != "" && !knownCatalogKeyPattern.MatchString(alias)) {
			return unsupportedBundleBackupSettings(config)
		}
	}
	return unsupportedBundleBackupMap(config, "groups")
}

// A key name in a list, alias mapping, schema or projection is a parser
// field identifier. A literal credential or retained source-data property in
// the configuration envelope is outside the versioned settings scope.
func unsupportedBundleBackupSettings(value any) bool {
	switch item := value.(type) {
	case map[string]any:
		return unsupportedBundleBackupMap(item, "")
	case []any:
		for _, child := range item {
			if unsupportedBundleBackupSettings(child) {
				return true
			}
		}
	case string:
		if strings.Contains(item, "://") {
			parsed, err := url.Parse(item)
			return err == nil && parsed.Scheme != "" && parsed.Host != "" && parsed.User != nil
		}
	}
	return false
}

func unsupportedBundleBackupMap(item map[string]any, symbolicSetting string) bool {
	for key, child := range item {
		if symbolicSetting != "" && key == symbolicSetting {
			continue
		}
		switch strings.ToLower(key) {
		case "key_aliases", "field_schema", "field_aliases":
			continue
		case "password", "password_hash", "api_key", "authorization", "access_token", "refresh_token", "bearer_token", "auth_token", "session_token", "client_secret", "private_key", "secret", "credential", "credentials", "raw_log", "raw_logs", "raw_sample", "raw_samples":
			if child != nil && child != "" {
				return true
			}
		}
		if unsupportedBundleBackupSettings(child) {
			return true
		}
	}
	return false
}

func (s *Server) putBundleRecoveryDocument(ctx context.Context, collection, id, state, actor string, value any) (metastore.Document, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return metastore.Document{}, err
	}
	return s.metadata.Put(ctx, metastore.Document{Collection: collection, ID: id, State: state, Payload: payload, CreatedBy: actor})
}
