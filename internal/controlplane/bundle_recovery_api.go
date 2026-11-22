package controlplane

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"nexora.local/nli-v20/internal/middleware"
	metastore "nexora.local/nli-v20/internal/store"
)

const (
	bundleBackupsRoute  = "/api/v1/bundle-backups"
	bundleRestoresRoute = "/api/v1/bundle-restores"
)

type proposeBundleRestoreRequest struct {
	BackupID             string `json:"backup_id"`
	ExpectedSnapshotHash string `json:"expected_snapshot_hash"`
	Reason               string `json:"reason"`
}

type approveBundleRestoreRequest struct {
	ExpectedSnapshotHash string `json:"expected_snapshot_hash"`
	ExpectedBaseRevision string `json:"expected_base_revision"`
}

func (s *Server) handleBundleBackups(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	path := strings.TrimPrefix(r.URL.Path, bundleBackupsRoute)
	if path != "" {
		parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
		if len(parts) != 2 || parts[1] != "export" || !validBundleRecoverySHA(parts[0]) {
			jsonError(w, "backup resource not found", http.StatusNotFound)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			jsonError(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		principal := s.authorize(w, r, middleware.PermissionManageParsers)
		if principal == nil {
			return
		}
		record, snapshot, err := s.readBundleBackup(r.Context(), parts[0])
		if err != nil {
			replyBundleRecoveryError(w, err)
			return
		}
		s.auditAction(principal, "bundle_backup.export", bundleBackupCollection+"/"+record.ID, "success", map[string]string{"snapshot_hash": record.SnapshotHash})
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="nli-parser-bundle-%s.json"`, record.ID))
		jsonOK(w, bundleBackupExport{Backup: record, Snapshot: snapshot})
		return
	}
	switch r.Method {
	case http.MethodGet:
		if s.authorize(w, r, middleware.PermissionReadParsers) == nil {
			return
		}
		limit, offset, ok := bundleRecoveryPage(w, r)
		if !ok {
			return
		}
		docs, err := s.metadata.List(r.Context(), bundleBackupCollection, metastore.Query{State: "verified", Limit: limit + 1, Offset: offset})
		if err != nil {
			replyBundleRecoveryError(w, err)
			return
		}
		backups := make([]bundleBackupRecord, 0, min(limit, len(docs)))
		for _, doc := range docs[:min(limit, len(docs))] {
			backup, err := readBundleBackupRecord(doc)
			if err != nil {
				replyBundleRecoveryError(w, err)
				return
			}
			backups = append(backups, backup)
		}
		jsonOK(w, map[string]any{"backups": backups, "limit": limit, "offset": offset, "has_more": len(docs) > limit, "automatic_capture": s.bundleAutomaticBackupStatus()})
	case http.MethodPost:
		principal := s.authorize(w, r, middleware.PermissionManageParsers)
		if principal == nil || !bundleRecoveryEmptyBody(w, r) {
			return
		}
		s.parserMutationMu.Lock()
		defer s.parserMutationMu.Unlock()
		bundle, err := s.buildActiveParserBundle(r.Context())
		if err != nil {
			replyBundleRecoveryError(w, err)
			return
		}
		record, err := s.captureBundleBackup(r.Context(), bundle, principal.Username, "manual")
		if err != nil {
			replyBundleRecoveryError(w, err)
			return
		}
		s.auditAction(principal, "bundle_backup.create", bundleBackupCollection+"/"+record.ID, "success", map[string]string{"snapshot_hash": record.SnapshotHash})
		jsonCreated(w, record)
	default:
		w.Header().Set("Allow", "GET, POST")
		jsonError(w, "GET or POST required", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleBundleRestores(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	path := strings.TrimPrefix(r.URL.Path, bundleRestoresRoute)
	if path != "" {
		s.handleBundleRestoreAction(w, r, strings.Split(strings.TrimPrefix(path, "/"), "/"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.listBundleRestores(w, r)
	case http.MethodPost:
		s.proposeBundleRestore(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		jsonError(w, "GET or POST required", http.StatusMethodNotAllowed)
	}
}

func (s *Server) listBundleRestores(w http.ResponseWriter, r *http.Request) {
	if s.authorize(w, r, middleware.PermissionReadParsers) == nil {
		return
	}
	limit, offset, ok := bundleRecoveryPage(w, r)
	if !ok {
		return
	}
	docs, err := s.metadata.List(r.Context(), bundleRestoreRecords, metastore.Query{Limit: limit + 1, Offset: offset})
	if err != nil {
		replyBundleRecoveryError(w, err)
		return
	}
	entry, _, err := s.readBundleRestoreJournal(r.Context())
	if err != nil {
		replyBundleRecoveryError(w, err)
		return
	}
	restores := make([]bundleRestoreRecord, 0, min(limit, len(docs)))
	for _, doc := range docs[:min(limit, len(docs))] {
		record, err := readBundleRestoreRecord(doc)
		if err != nil {
			replyBundleRecoveryError(w, err)
			return
		}
		if record.ID == entry.Restore.ID && record.State == bundleRestorePending {
			record = entry.Restore
		}
		restores = append(restores, record)
	}
	jsonOK(w, map[string]any{"restores": restores, "limit": limit, "offset": offset, "has_more": len(docs) > limit})
}

func (s *Server) proposeBundleRestore(w http.ResponseWriter, r *http.Request) {
	principal := s.authorize(w, r, middleware.PermissionTriggerRollout)
	if principal == nil {
		return
	}
	var input proposeBundleRestoreRequest
	if decodeJSON(r, &input, 4<<10) != nil || !validBundleRecoverySHA(input.BackupID) || input.ExpectedSnapshotHash != input.BackupID {
		jsonError(w, "backup_id and its exact expected_snapshot_hash are required", http.StatusBadRequest)
		return
	}
	input.Reason = strings.TrimSpace(input.Reason)
	if input.Reason == "" || len(input.Reason) > 1000 {
		jsonError(w, "restore reason must contain 1 to 1000 bytes", http.StatusBadRequest)
		return
	}
	s.parserMutationMu.Lock()
	defer s.parserMutationMu.Unlock()
	ctx := r.Context()
	entry, revision, err := s.readBundleRestoreJournal(ctx)
	if err != nil || entry.Restore.State == bundleRestoreApplying {
		if err == nil {
			err = errBundleRecoveryUnavailable
		}
		replyBundleRecoveryError(w, err)
		return
	}
	if _, _, err := s.readBundleBackup(ctx, input.BackupID); err != nil {
		replyBundleRecoveryError(w, err)
		return
	}
	current, err := s.buildActiveParserBundle(ctx)
	if err != nil {
		replyBundleRecoveryError(w, err)
		return
	}
	now := time.Now().UTC()
	record := bundleRestoreRecord{
		ID: fmt.Sprintf("restore-%d", now.UnixNano()), State: bundleRestorePending, BackupID: input.BackupID, SnapshotHash: input.ExpectedSnapshotHash,
		BaseBundleHash: current.BundleHash, BaseRevision: bundleRestoreBase(current, revision), Reason: input.Reason, ProposedBy: principal.Username, CreatedAt: now,
	}
	if err := s.saveBundleRestoreRecord(ctx, record); err != nil {
		replyBundleRecoveryError(w, err)
		return
	}
	s.auditAction(principal, "bundle_restore.propose", bundleRestoreRecords+"/"+record.ID, "success", map[string]string{"snapshot_hash": record.SnapshotHash, "base_revision": record.BaseRevision})
	jsonCreated(w, record)
}

func (s *Server) handleBundleRestoreAction(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) != 2 || !validRuntimeParserID(parts[0]) || (parts[1] != "approve" && parts[1] != "resume") {
		jsonError(w, "restore resource not found", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		jsonError(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	id, action := parts[0], parts[1]
	permission := middleware.PermissionApproveRollout
	if action == "resume" {
		permission = middleware.PermissionReadParsers
	}
	principal := s.authorize(w, r, permission)
	if principal == nil {
		return
	}
	if action == "resume" {
		if !principalHasPermission(principal, middleware.PermissionTriggerRollout) && !principalHasPermission(principal, middleware.PermissionApproveRollout) {
			jsonError(w, "rollout trigger or approval permission is required to resume a restore", http.StatusForbidden)
			return
		}
		if !bundleRecoveryEmptyBody(w, r) {
			return
		}
		s.parserMutationMu.Lock()
		defer s.parserMutationMu.Unlock()
		record, err := s.resumeBundleRestore(r.Context(), id)
		if err != nil {
			replyBundleRecoveryError(w, err)
			return
		}
		s.auditAction(principal, "bundle_restore.resume", bundleRestoreRecords+"/"+id, "success", map[string]string{"desired_bundle_hash": record.DesiredBundleHash})
		jsonOK(w, record)
		return
	}
	var input approveBundleRestoreRequest
	if decodeJSON(r, &input, 4<<10) != nil || !validBundleRecoverySHA(input.ExpectedSnapshotHash) || !validBundleRecoverySHA(input.ExpectedBaseRevision) {
		jsonError(w, "expected_snapshot_hash and expected_base_revision are required", http.StatusBadRequest)
		return
	}
	s.parserMutationMu.Lock()
	defer s.parserMutationMu.Unlock()
	ctx := r.Context()
	record, err := s.getBundleRestoreRecord(ctx, id)
	if err != nil {
		replyBundleRecoveryError(w, err)
		return
	}
	if principal.Username == record.ProposedBy {
		jsonError(w, "restore requires an independent approver", http.StatusConflict)
		return
	}
	if input.ExpectedBaseRevision != record.BaseRevision || input.ExpectedSnapshotHash != record.SnapshotHash {
		jsonError(w, "restore approval does not match the exact snapshot and base revision", http.StatusConflict)
		return
	}
	if record.State != bundleRestorePending {
		jsonError(w, "restore is no longer awaiting approval; use its current state", http.StatusConflict)
		return
	}
	record, err = s.beginBundleRestore(ctx, record, principal.Username)
	if record.ApprovedBy == principal.Username {
		outcome := "success"
		if err != nil {
			outcome = "interrupted"
		}
		s.auditAction(principal, "bundle_restore.approve", bundleRestoreRecords+"/"+id, outcome, map[string]string{"snapshot_hash": record.SnapshotHash, "base_revision": record.BaseRevision, "desired_bundle_hash": record.DesiredBundleHash})
	}
	if err != nil {
		replyBundleRecoveryError(w, err)
		return
	}
	jsonOK(w, record)
}

func bundleRecoveryPage(w http.ResponseWriter, r *http.Request) (int, int, bool) {
	limit, offset := 25, 0
	var err error
	if value := r.URL.Query().Get("limit"); value != "" {
		limit, err = strconv.Atoi(value)
	}
	if err == nil {
		if value := r.URL.Query().Get("offset"); value != "" {
			offset, err = strconv.Atoi(value)
		}
	}
	if err != nil || limit < 1 || limit > 100 || offset < 0 || offset > 100000 {
		jsonError(w, "limit must be 1 to 100 and offset must be 0 to 100000", http.StatusBadRequest)
		return 0, 0, false
	}
	return limit, offset, true
}

func bundleRecoveryEmptyBody(w http.ResponseWriter, r *http.Request) bool {
	if r.ContentLength == 0 {
		return true
	}
	var input struct{}
	if decodeJSON(r, &input, 1024) != nil {
		jsonError(w, "request body must be an empty JSON object", http.StatusBadRequest)
		return false
	}
	return true
}

func replyBundleRecoveryError(w http.ResponseWriter, err error) {
	status, message := http.StatusServiceUnavailable, "bundle recovery metadata is unavailable; check the restore history before retrying"
	switch {
	case errors.Is(err, os.ErrNotExist):
		status, message = http.StatusNotFound, "backup or restore was not found"
	case errors.Is(err, errBundleBackupSize):
		status, message = http.StatusRequestEntityTooLarge, err.Error()
	case errors.Is(err, errBundleBackupUnsafe), errors.Is(err, errBundleRecoveryIntegrity):
		status, message = http.StatusUnprocessableEntity, err.Error()
	case errors.Is(err, errBundleRecoveryStale), errors.Is(err, errBundleRecoveryUnavailable), errors.Is(err, errBundleBackupEmbedded):
		status, message = http.StatusConflict, err.Error()
	}
	jsonError(w, message, status)
}
