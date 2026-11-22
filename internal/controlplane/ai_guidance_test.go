package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestAIGuidanceCatalogMatchesWebNavigationAndControls(t *testing.T) {
	web, err := os.ReadFile("../../web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	navigation := regexp.MustCompile(`\['[^']+', '([^']+)', '([^']+)', '[^']+'\]`).FindAllSubmatch(bytes.SplitN(web, []byte("const TITLES"), 2)[0], -1)
	if len(navigation) != len(aiGuidanceCatalog) {
		t.Fatalf("guidance catalog=%d navigation=%d", len(aiGuidanceCatalog), len(navigation))
	}
	for i, workspace := range aiGuidanceCatalog {
		if workspace.ID != string(navigation[i][1]) || workspace.Label != string(navigation[i][2]) {
			t.Errorf("guidance workspace differs from the web navigation: %+v", workspace)
		}
		actions := append([]aiGuidanceAction(nil), workspace.Actions...)
		for _, tab := range workspace.Tabs {
			if !bytes.Contains(web, []byte("['"+tab.ID+"','"+tab.Label+"']")) {
				t.Errorf("%s tab %s was not found in the UI", workspace.ID, tab.ID)
			}
			actions = append(actions, tab.Actions...)
		}
		for _, action := range actions {
			if !bytes.Contains(web, []byte(`data-action="`+action.ID+`"`)) {
				t.Errorf("%s action %s was not found in the UI", workspace.ID, action.ID)
			}
		}
	}
}

func TestAIGuidanceEvaluationAndRevisionProvenance(t *testing.T) {
	f := newAPIFixture(t)
	read, body := f.request(http.MethodGet, "/api/v1/ai/guidance", nil)
	if read.StatusCode != http.StatusOK {
		t.Fatalf("guidance catalog: %d %s", read.StatusCode, body)
	}
	snapshot := decodeMap(t, body)
	hash := snapshot["current"].(map[string]any)["sha256"].(string)
	if len(hash) != 64 || snapshot["can_record_revision"] != true {
		t.Fatalf("missing catalog provenance or revision permission: %s", body)
	}
	const question = "How can I verify applied state? pw=never-persist-this"
	response, body := f.request(http.MethodPost, "/api/v1/ai/guidance/evaluate", map[string]any{
		"workspace": "parser-sync", "question": question,
	})
	if response.StatusCode != http.StatusOK || bytes.Contains(body, []byte("never-persist-this")) {
		t.Fatalf("catalog evaluation: %d %s", response.StatusCode, body)
	}
	result := decodeMap(t, body)
	if result["selected"].(map[string]any)["id"] != "parser-sync-verify" ||
		result["provider_status"] != "not_requested" || result["persisted"] != true {
		t.Fatalf("expected deterministic fleet verification guidance: %s", body)
	}
	for _, invalid := range []map[string]any{
		{"workspace": "invented-navigation"},
		{"workspace": "parser-sync", "tab": "invented-tab"},
		{"workspace": "ai", "tab": "provider", "action": "rollout-approve"},
		{"workspace": "parser-sync", "raw": "an unsupported field"},
	} {
		response, body := f.request(http.MethodPost, "/api/v1/ai/guidance/evaluate", invalid)
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid scope was accepted: %d %s", response.StatusCode, body)
		}
	}

	revision := map[string]any{"workspace": "parser-sync", "action": "parser-sync-verify", "catalog_hash": hash, "note": "Inspect the client acknowledgement before retry."}
	response, body = f.request(http.MethodPost, "/api/v1/ai/guidance/revisions", revision)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("record revision: %d %s", response.StatusCode, body)
	}
	revision["catalog_hash"] = strings.Repeat("1", 64)
	response, body = f.request(http.MethodPost, "/api/v1/ai/guidance/revisions", revision)
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("stale catalog revision was accepted: %d %s", response.StatusCode, body)
	}
	revision["catalog_hash"], revision["note"] = hash, "password=private-note-password"
	response, body = f.request(http.MethodPost, "/api/v1/ai/guidance/revisions", revision)
	if response.StatusCode != http.StatusBadRequest || bytes.Contains(body, []byte("private-note-password")) {
		t.Fatalf("private note was accepted or echoed: %d %s", response.StatusCode, body)
	}
	response, body = f.request(http.MethodGet, "/api/v1/ai/guidance", nil)
	if response.StatusCode != http.StatusOK || bytes.Contains(body, []byte("never-persist-this")) || bytes.Contains(body, []byte("private-note-password")) {
		t.Fatalf("unsafe or unavailable history: %d %s", response.StatusCode, body)
	}
	snapshot = decodeMap(t, body)
	for _, key := range []string{"revisions", "evaluations"} {
		entries := snapshot[key].([]any)
		if len(entries) != 1 || entries[0].(map[string]any)["payload"].(map[string]any)["catalog"].(map[string]any)["sha256"] != hash {
			t.Errorf("%s lost exact catalog provenance: %v", key, entries)
		}
	}
}

func TestAIGuidanceProviderSelectionIsStrictAndMasked(t *testing.T) {
	const private = "private@example.test"
	for _, tt := range []struct {
		name, reply, status, selected string
	}{
		{"verified ID", `{"action_id":"parser-sync-retry"}`, "selected", "parser-sync-retry"},
		{"cross-workspace ID", `{"action_id":"rollout-approve"}`, "invalid", "parser-sync-verify"},
		{"invented label", `{"action_id":"parser-sync-retry","label":"Remove all clients"}`, "invalid", "parser-sync-verify"},
		{"non-JSON output", "Click the imaginary button", "invalid", "parser-sync-verify"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newAPIFixture(t)
			calls := mappingAIProviderFixture(t, f, tt.reply, func(req map[string]any) {
				wire, _ := json.Marshal(req)
				if bytes.Contains(wire, []byte(private)) || !bytes.Contains(wire, []byte("parser-sync-verify")) {
					t.Errorf("provider request lost verified choices or leaked private text")
				}
			})
			response, body := f.request(http.MethodPost, "/api/v1/ai/guidance/evaluate", map[string]any{
				"workspace": "parser-sync", "question": "Verify the acknowledgement for " + private, "use_provider": true,
			})
			if response.StatusCode != http.StatusOK || calls.Load() != 1 || bytes.Contains(body, []byte(private)) {
				t.Fatalf("provider evaluation: %d %s calls=%d", response.StatusCode, body, calls.Load())
			}
			result := decodeMap(t, body)
			if result["provider_status"] != tt.status || result["selected"].(map[string]any)["id"] != tt.selected {
				t.Fatalf("provider selection escaped its scope or fallback: %s", body)
			}
		})
	}
}

func TestAIGuidanceProviderNonresponsePreservesCatalogFallback(t *testing.T) {
	f := newAPIFixture(t)
	t.Setenv("NLI_AI_ALLOW_LOOPBACK", "true")
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	}))
	t.Cleanup(provider.Close)
	if err := f.server.storeAIProvider(context.Background(), aiProviderConfig{
		ID: "silent-provider", Provider: "openai_compatible", Model: "synthetic",
		BaseURL: provider.URL, Enabled: true, APIKey: "synthetic-provider-key", TimeoutSeconds: 1,
	}, "admin"); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	response, body := f.request(http.MethodPost, "/api/v1/ai/guidance/evaluate", map[string]any{
		"workspace": "parser-sync", "action": "parser-sync-verify", "use_provider": true,
	})
	if response.StatusCode != http.StatusOK || time.Since(started) > aiGuidanceProviderBudget+2*time.Second {
		t.Fatalf("provider nonresponse blocked guidance: %d %s", response.StatusCode, body)
	}
	result := decodeMap(t, body)
	if result["provider_status"] != "timeout" || result["selected"].(map[string]any)["id"] != "parser-sync-verify" {
		t.Fatalf("nonresponse status or deterministic fallback was lost: %s", body)
	}
}

func TestAIWorkspaceIncludesVerifiedGuidanceBesideProviderAnswer(t *testing.T) {
	f := newAPIFixture(t)
	const answer = "The connection test can help."
	mappingAIProviderFixture(t, f, answer, func(req map[string]any) {
		wire, _ := json.Marshal(req)
		if !bytes.Contains(wire, []byte("test-ai-provider")) {
			t.Error("existing workspace provider did not receive vetted action IDs")
		}
	})
	response, body := f.request(http.MethodPost, "/api/v1/ai/workspace", map[string]any{
		"workspace": "ai", "tab": "Provider", "mode": "ask", "question": "How do I test the connection?",
	})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("existing workspace response: %d %s", response.StatusCode, body)
	}
	result := decodeMap(t, body)
	guidance, ok := result["verified_guidance"].(map[string]any)
	if result["answer"] != answer || result["answer_origin"] != "provider" || !ok ||
		guidance["scope"].(map[string]any)["tab"] != "provider" ||
		guidance["selected"].(map[string]any)["id"] != "test-ai-provider" {
		t.Fatalf("catalog guidance was not separate from the reply: %s", body)
	}
}
