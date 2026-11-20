package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	metastore "nexora.local/nli-v20/internal/store"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type composeIOStore struct {
	metastore.Store
	delay         time.Duration
	failure       error
	entered       chan struct{}
	calls         atomic.Int64
	cancellations atomic.Int64
}

func (s *composeIOStore) Get(ctx context.Context, collection, id string, revision int) (metastore.Document, error) {
	s.calls.Add(1)
	if s.entered != nil {
		select {
		case s.entered <- struct{}{}:
		default:
		}
	}
	if s.delay > 0 {
		timer := time.NewTimer(s.delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			s.cancellations.Add(1)
			return metastore.Document{}, ctx.Err()
		case <-timer.C:
		}
	}
	if s.failure != nil {
		return metastore.Document{}, s.failure
	}
	if id == "missing" {
		return metastore.Document{}, os.ErrNotExist
	}
	payload := json.RawMessage(`{"config":{"engine":"re2","pattern":"^(?P<host>\\S+)[ \\t]+","fields":{"host":"host"}}}`)
	if collection == "kv-config" {
		payload = json.RawMessage(`{"config":{"pair_separators":[";"],"assignment_separators":["="],"literal_boundaries":true}}`)
	}
	return metastore.Document{Collection: collection, ID: id, Revision: revision, State: "draft", Payload: payload}, nil
}

const composeIOBody = `{"header":{"id":"header","revision":1},"kv":{"id":"tail","revision":1},"samples":["node status=failed;reason=not needed"]}`

func TestTemplateComposeSlowMetadataHasSeparateExtractionBudget(t *testing.T) {
	store := &composeIOStore{delay: 1100 * time.Millisecond}
	server := &Server{metadata: store}
	response := httptest.NewRecorder()
	started := time.Now()
	server.handleTemplateCompose(response, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(composeIOBody)))
	if time.Since(started) <= 2*time.Second {
		t.Fatal("fixture did not exceed original aggregate analysis budget")
	}
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"passed":true`) || !strings.Contains(response.Body.String(), `"host":"node","status":"failed","reason":"not needed"`) {
		t.Fatalf("slow exact revisions failed: %d %s", response.Code, response.Body)
	}
	if store.calls.Load() != 2 || server.fieldSenseAnalysis().timeout != 2*time.Second || len(server.fieldSenseAnalysis().slots) != 0 {
		t.Fatal("metadata lookup changed extraction budget or leaked capacity")
	}
}

func TestTemplateComposeLookupFailuresKeepCorrectStatus(t *testing.T) {
	for _, test := range []struct {
		name       string
		failure    error
		want       int
		diagnostic string
	}{
		{"missing", os.ErrNotExist, 400, ""},
		{"auth", fmt.Errorf("private-sensitive-value: %w", metastore.ErrControllerAuthentication), 503, "controller_secret_mismatch_or_rpc_permission"},
		{"schema", metastore.ErrRPCSchema, 503, "schema_missing_or_outdated"},
		{"deadline", context.DeadlineExceeded, 503, "metadata_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := &Server{metadata: &composeIOStore{failure: test.failure}}
			response := httptest.NewRecorder()
			server.handleTemplateCompose(response, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(composeIOBody)))
			if response.Code != test.want || test.diagnostic != "" && !strings.Contains(response.Body.String(), test.diagnostic) {
				t.Fatalf("%d %s", response.Code, response.Body)
			}
			if strings.Contains(response.Body.String(), "private-sensitive-value") {
				t.Fatal("upstream secret leaked")
			}
		})
	}
}

func TestTemplateComposeMetadataCancellationReleasesSharedSlot(t *testing.T) {
	store := &composeIOStore{delay: time.Second, entered: make(chan struct{}, 1)}
	server := &Server{metadata: store, cfg: Config{FieldSenseAnalysisConcurrency: 1}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.handleTemplateCompose(response, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(composeIOBody)).WithContext(ctx))
	}()
	select {
	case <-store.entered:
	case <-time.After(time.Second):
		t.Fatal("metadata lookup did not begin")
	}
	busy := httptest.NewRecorder()
	server.handleKVInspect(busy, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)))
	if busy.Code != 429 {
		t.Fatal("metadata I/O bypassed shared analysis capacity")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled metadata read did not return")
	}
	if response.Code != 503 || store.cancellations.Load() != 1 || len(server.fieldSenseAnalysis().slots) != 0 {
		t.Fatal("canceled compose leaked capacity or reported a missing revision")
	}
	// A caller deadline also interrupts the actual I/O, not an uncancellable read.
	deadline, cancelDeadline := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelDeadline()
	other := httptest.NewRecorder()
	server.handleTemplateCompose(other, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(composeIOBody)).WithContext(deadline))
	if other.Code != 503 || !errors.Is(deadline.Err(), context.DeadlineExceeded) {
		t.Fatalf("deadline: %d %s", other.Code, other.Body)
	}
}
