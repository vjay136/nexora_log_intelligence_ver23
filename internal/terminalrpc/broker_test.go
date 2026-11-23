package terminalrpc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadAccessRefreshRequiresHostOptInAndNoArguments(t *testing.T) {
	server := &Server{}
	for _, item := range []struct {
		body string
		code int
	}{{`{}`, http.StatusForbidden}, {`{"path":"/etc/nli"}`, http.StatusBadRequest}} {
		request := httptest.NewRequest(http.MethodPost, "/v1/refresh-read-access", strings.NewReader(item.body))
		request = request.WithContext(context.WithValue(request.Context(), peerContextKey{}, true))
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		if response.Code != item.code {
			t.Fatalf("refresh body %s status=%d", item.body, response.Code)
		}
	}
}

func TestBrokerRejectsHTTPHeadersWithoutKernelPeer(t *testing.T) {
	s := &Server{}
	request := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	request.Header.Set("X-User", "root")
	request.Header.Set("Authorization", "Bearer anything")
	response := httptest.NewRecorder()
	s.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatal("untrusted peer accepted")
	}
}
func TestHostPolicyOperatorOnly(t *testing.T) {
	cfg, err := NormalizeHostConfig(HostConfig{})
	if err != nil || cfg.Enabled || cfg.PrivilegeMode != "operator" || cfg.AllowInputWrite == nil || !*cfg.AllowInputWrite {
		t.Fatal("invalid safe defaults", cfg, err)
	}
	for _, mode := range []string{"root", "admin", "nli"} {
		if _, err := NormalizeHostConfig(HostConfig{PrivilegeMode: mode}); err == nil {
			t.Fatalf("accepted privilege mode %q", mode)
		}
	}
	manager := cfg.ManagerConfig()
	if manager.Username != "nli-terminal" || manager.AllowRoot || !manager.Systemd {
		t.Fatal("host privilege policy weakened")
	}
}
