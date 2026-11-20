package controlplane

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"nexora.local/nli-v20/internal/auditlog"
	metastore "nexora.local/nli-v20/internal/store"
)

type ownershipFaultStore struct {
	metastore.Store
	denied atomic.Bool
	writes atomic.Int64
}

func (s *ownershipFaultStore) List(ctx context.Context, c string, q metastore.Query) ([]metastore.Document, error) {
	if s.denied.Load() {
		return nil, metastore.ErrControllerAuthentication
	}
	return s.Store.List(ctx, c, q)
}
func (s *ownershipFaultStore) Get(ctx context.Context, c, id string, r int) (metastore.Document, error) {
	if s.denied.Load() {
		return metastore.Document{}, metastore.ErrControllerAuthentication
	}
	return s.Store.Get(ctx, c, id, r)
}
func (s *ownershipFaultStore) Put(ctx context.Context, d metastore.Document) (metastore.Document, error) {
	s.writes.Add(1)
	if s.denied.Load() {
		return metastore.Document{}, metastore.ErrControllerAuthentication
	}
	return s.Store.Put(ctx, d)
}

func ownershipRequest(f *apiFixture, method, path, body string) *http.Request {
	request := httptest.NewRequest(method, f.http.URL+path, bytes.NewBufferString(body))
	origin, _ := url.Parse(f.http.URL)
	for _, cookie := range f.client.Jar.Cookies(origin) {
		request.AddCookie(cookie)
	}
	return request
}

func TestReportedCatalogOwnershipFailuresHaveActionableDiagnostics(t *testing.T) {
	f := newAPIFixture(t)
	fault := &ownershipFaultStore{Store: f.server.metadata}
	fault.denied.Store(true)
	// Dedicated handlers share only immutable service dependencies. The running
	// fixture's Store pointer never changes under its background readers.
	server := &Server{metadata: fault, security: f.server.security, audit: f.server.audit}
	handlers := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"parsers", server.handleParserPacks}, {"rollouts", server.handleRollouts}, {"fleet", server.handleFleetSync}, {"parser-sync", server.listParserSync},
	}
	for _, collection := range []string{"kv-config", "static-patterns", "projections", "templates", "regex-patterns", "known-keys", "semantic-extraction", "output-destinations", "input-paths"} {
		c := collection
		handlers = append(handlers, struct {
			name    string
			handler http.HandlerFunc
		}{c, func(w http.ResponseWriter, r *http.Request) { server.handleConfiguration(w, r, c) }})
	}
	for _, item := range handlers {
		t.Run(item.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			item.handler(response, ownershipRequest(f, http.MethodGet, "/api/v1/"+item.name, ""))
			if response.Code != 503 || !strings.Contains(response.Body.String(), "controller_secret_mismatch_or_rpc_permission") || !strings.Contains(response.Body.String(), "next_action") {
				t.Fatalf("%d %s", response.Code, response.Body)
			}
		})
	}
	if fault.writes.Load() != 0 {
		t.Fatal("failed reads attempted a metadata write")
	}
	if err := seedBuiltinCatalog(context.Background(), fault); err == nil {
		t.Fatal("failed authorization interpreted as missing catalog")
	}
	if fault.writes.Load() != 0 {
		t.Fatal("catalog seed overwrote unverifiable state")
	}
	fault.denied.Store(false)
	response := httptest.NewRecorder()
	server.handleConfiguration(response, ownershipRequest(f, http.MethodGet, "/api/v1/config/templates", ""), "templates")
	if response.Code != 200 {
		t.Fatalf("recovered read: %d %s", response.Code, response.Body)
	}
}

func TestNotificationOwnershipFailureDoesNotAcknowledgeThenRecovers(t *testing.T) {
	f := newAPIFixture(t)
	event, err := f.server.audit.Append(auditlog.Event{Action: http.MethodGet, Resource: "/api/v1/rollouts", Outcome: "failure", Actor: "admin", Details: map[string]string{"detail": "status=503 duration_ms=1"}})
	if err != nil {
		t.Fatal(err)
	}
	fault := &ownershipFaultStore{Store: f.server.metadata}
	fault.denied.Store(true)
	server := &Server{metadata: fault, security: f.server.security, audit: f.server.audit}
	path := fmt.Sprintf("/api/v1/notifications/audit-%d", event.Sequence)
	response := httptest.NewRecorder()
	server.handleNotificationAck(response, ownershipRequest(f, http.MethodPost, path, `{"action":"read"}`))
	if response.Code != 503 || !strings.Contains(response.Body.String(), "controller_secret_mismatch_or_rpc_permission") {
		t.Fatalf("%d %s", response.Code, response.Body)
	}
	fault.denied.Store(false)
	docs, err := fault.List(context.Background(), notificationAckCollection, metastore.Query{Limit: 1000})
	if err != nil || len(docs) != 0 {
		t.Fatal("failed action was acknowledged")
	}
	response = httptest.NewRecorder()
	server.handleNotificationAck(response, ownershipRequest(f, http.MethodPost, path, `{"action":"read"}`))
	if response.Code != 200 {
		t.Fatalf("recovered action: %d %s", response.Code, response.Body)
	}
	docs, err = fault.List(context.Background(), notificationAckCollection, metastore.Query{Limit: 1000})
	if err != nil || len(docs) != 1 {
		t.Fatal("successful action was not persisted")
	}
}
