package controlclient

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyBundleInvalidAndOldAgentRetainPreviousGeneration(t *testing.T) {
	for _, invalid := range []bool{true, false} {
		t.Run(fmt.Sprint("invalid=", invalid), func(t *testing.T) {
			root := t.TempDir()
			assets := filepath.Join(root, "assets")
			parsers := filepath.Join(root, "parsers")
			for _, p := range []string{assets, parsers} {
				if err := os.MkdirAll(p, 0750); err != nil {
					t.Fatal(err)
				}
			}
			prior := synchronizedAssetBundle{SchemaVersion: 1}
			prior.BundleHash, _ = synchronizedBundleHash(prior)
			before, _ := json.Marshal(prior)
			if err := os.WriteFile(filepath.Join(assets, "bundle.json"), before, 0640); err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"status":"running","version":"23.0.0"}`))
			}))
			defer server.Close()
			executor := &fakeExecutor{}
			client, err := New(Config{ControllerURL: server.URL, AllowInsecureHTTP: true, NodeTokenFile: filepath.Join(root, "token"), InstallIDFile: filepath.Join(root, "id"), JournalFile: filepath.Join(root, "journal"), AgentConfigPath: filepath.Join(root, "config"), ParserDir: parsers, AssetDir: assets, PackageSpoolDir: filepath.Join(root, "spool"), PollSeconds: 5, MetricsURL: server.URL + "/metrics"}, executor)
			if err != nil {
				t.Fatal(err)
			}
			raw := `{"config":{"enabled":true,"match_mode":"any","rules":[{"field":"event","operator":"equals","values":["EHLO"]}]}}`
			if invalid {
				raw = `{"config":{"enabled":true,"match_mode":"any","rules":[]}}`
			}
			payload := json.RawMessage(raw)
			digest := sha256.Sum256(payload)
			next := synchronizedAssetBundle{SchemaVersion: 1, Assets: []synchronizedAsset{{AssetClass: "selective-input", AssetID: "admission", Revision: 1, SHA256: fmt.Sprintf("%x", digest[:]), Payload: payload}}}
			next.BundleHash, _ = synchronizedBundleHash(next)
			encoded, _ := json.Marshal(next)
			_, err = client.applyAssetBundle(context.Background(), encoded)
			if err == nil {
				t.Fatal("unsupported/invalid policy acknowledged")
			}
			if !invalid && !strings.Contains(err.Error(), "false policy acknowledgement") {
				t.Fatal(err)
			}
			after, _ := os.ReadFile(filepath.Join(assets, "bundle.json"))
			if string(after) != string(before) {
				t.Fatal("failed generation replaced previous approved bundle")
			}
			if invalid && executor.restarts != 0 {
				t.Fatal("invalid policy restarted healthy runtime")
			}
		})
	}
}

func TestPolicyCapabilitiesRequireRunningParsingAgent(t *testing.T) {
	for _, body := range []string{`{"status":"running","feature_capabilities":["log-policies-v1"]}`, `{"status":"running","version":"23.0.0"}`, `{"status":"stopped","feature_capabilities":["log-policies-v1"]}`} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
		client := &Client{cfg: Config{MetricsURL: server.URL + "/metrics"}}
		actual := client.agentPolicyCapabilities()
		server.Close()
		want := strings.Contains(body, `"status":"running","feature_capabilities"`)
		if (len(actual) > 0) != want {
			t.Fatalf("health %s caps %v", body, actual)
		}
	}
}
