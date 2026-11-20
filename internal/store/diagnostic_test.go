package store

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestSupabaseOwnershipDenialIsTypedAndNeverRetriedOrEmpty(t *testing.T) {
	const secret = "fixture-controller-private-01234567890123456789"
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"code":"42501","message":"NLI controller authentication failed"}`))
	}))
	defer upstream.Close()
	store, err := Open(Config{Provider: "supabase", SupabaseURL: upstream.URL, SupabaseAnonKey: "sb_publishable_fixture", SupabaseControllerSecret: []byte(secret), AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	docs, err := store.List(context.Background(), "parser-packs", Query{Limit: 100})
	if !errors.Is(err, ErrControllerAuthentication) || docs != nil || calls.Load() != 1 {
		t.Fatalf("denial became empty/retried: %v %v %d", docs, err, calls.Load())
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("controller secret leaked")
	}
	code, next, retry := FailureDiagnostic(err)
	if code != "controller_secret_mismatch_or_rpc_permission" || next == "" || retry {
		t.Fatalf("unsafe diagnostic %s %s %v", code, next, retry)
	}
}
