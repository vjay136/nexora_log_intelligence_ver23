package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVerifiedTerminalNodesBehindSameNATKeepIndependentBudgets(t *testing.T) {
	security, _, _ := securityFixture(t)
	security.RateLimit = 2
	security.EnableAuditLogging = false
	security.TerminalNodeIdentity = func(r *http.Request) (string, bool) {
		id := r.Header.Get("X-NLI-Node-ID")
		return id, (id == "node-a" && r.Header.Get("Authorization") == "Bearer token-a") || (id == "node-b" && r.Header.Get("Authorization") == "Bearer token-b")
	}
	handler := security.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	request := func(path, id, token string) int {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		r.RemoteAddr = "198.51.100.20:45000"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-NLI-Node-ID", id)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code
	}
	for i := 0; i < 600; i++ {
		for _, node := range []struct{ id, token string }{{"node-a", "token-a"}, {"node-b", "token-b"}} {
			if code := request("/api/v1/node/terminal/exchange", node.id, node.token); code != 200 {
				t.Fatalf("shared NAT terminal %s request%d status%d", node.id, i, code)
			}
		}
	}
	if code := request("/api/v1/node/terminal/exchange", "node-a", "token-a"); code != 429 {
		t.Fatal("terminal per-node bound missing", code)
	}
	for i := 0; i < 2; i++ {
		if code := request("/api/v1/node/heartbeat", "node-a", "token-a"); code != 200 {
			t.Fatal("terminal traffic consumed ordinary heartbeat budget", code)
		}
	}
	if code := request("/api/v1/health", "", ""); code != 429 {
		t.Fatal("ordinary IP budget changed", code)
	}
}

func TestSpoofedTerminalNodeHeaderRetainsOrdinaryIPBudget(t *testing.T) {
	security, _, _ := securityFixture(t)
	security.RateLimit = 1
	security.EnableAuditLogging = false
	security.TerminalNodeIdentity = func(r *http.Request) (string, bool) { return r.Header.Get("X-NLI-Node-ID"), false }
	handler := security.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/node/terminal/exchange", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-NLI-Node-ID", []string{"victim-a", "victim-b"}[i])
		r.Header.Set("Authorization", "Bearer invalid")
		r.RemoteAddr = "198.51.100.30:45000"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		expected := 200
		if i == 1 {
			expected = 429
		}
		if w.Code != expected {
			t.Fatalf("spoofed identity escaped IP budget status%d", w.Code)
		}
	}
}
