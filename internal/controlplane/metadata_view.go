package controlplane

import (
	"encoding/json"
	"net/http"
	metastore "nexora.local/nli-v20/internal/store"
	"sync"
	"time"
)

const (
	metadataViewMaxAge     = 2 * time.Minute
	metadataViewReadBudget = 12 * time.Second
)

// recoverableMetadataView is a read-only display cache. Approval and deployment
// handlers must continue to read and verify authoritative metadata.
type recoverableMetadataView struct {
	mu      sync.RWMutex
	started time.Time
	at      time.Time
	value   map[string]any
}

func replyMetadataCurrent(w http.ResponseWriter, view *recoverableMetadataView, started time.Time, value map[string]any) {
	now := time.Now().UTC()
	value["snapshot_at"] = now
	value["snapshot_stale"] = false
	if view != nil {
		view.mu.Lock()
		if !started.Before(view.started) {
			view.started, view.at, view.value = started, now, value
		}
		view.mu.Unlock()
	}
	w.Header().Set("Cache-Control", "no-store")
	jsonOK(w, value)
}

func replyMetadataUnavailable(w http.ResponseWriter, r *http.Request, view *recoverableMetadataView, message string, causes ...error) {
	var cause error
	if len(causes) > 0 {
		cause = causes[0]
	}
	code, next, retryable := metastore.FailureDiagnostic(cause)
	w.Header().Set("Cache-Control", "no-store")
	if view != nil && r.Context().Err() == nil {
		view.mu.RLock()
		value, at := view.value, view.at
		view.mu.RUnlock()
		if value != nil && time.Since(at) <= metadataViewMaxAge {
			stale := make(map[string]any, len(value)+1)
			for key, item := range value {
				stale[key] = item
			}
			stale["snapshot_stale"] = true
			stale["snapshot_error"] = message
			stale["diagnostic"], stale["next_action"], stale["retryable"] = code, next, retryable
			jsonOK(w, stale)
			return
		}
	}
	metadataFailure(w, message, cause)
}

func metadataFailure(w http.ResponseWriter, message string, cause error) {
	code, next, retryable := metastore.FailureDiagnostic(cause)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": message, "diagnostic": code, "next_action": next, "retryable": retryable})
}
