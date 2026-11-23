package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"nexora.local/nli-v20/internal/aiprovider"
	metastore "nexora.local/nli-v20/internal/store"
)

// Explicit operator opt-in only. Ordinary builds/tests never contact a provider.
// The launcher reads a private vault credential into this process environment;
// neither the credential nor provider replies are copied to release evidence.
func TestR9LiveGeminiPolicyGuidance(t *testing.T) {
	if os.Getenv("NLI_R9_LIVE_AI_TEST") != "1" {
		t.Skip("live provider access requires explicit NLI testing opt-in")
	}
	key := os.Getenv("NLI_R9_LIVE_GEMINI_KEY")
	if key == "" {
		t.Fatal("private NLI Gemini test credential unavailable")
	}
	f := newAPIFixture(t)
	if err := f.server.storeAIProvider(context.Background(), aiProviderConfig{
		ID: "r9-live-gemini-test", Name: "NLI live test only", Provider: "gemini",
		BaseURL: "https://generativelanguage.googleapis.com/v1beta", Model: "gemini-3.5-flash-lite",
		Enabled: true, TimeoutSeconds: 15, MaxResponseBytes: 65536,
		Credential: aiprovider.Credential{Source: aiprovider.CredentialEnvironment, Reference: "NLI_R9_LIVE_GEMINI_KEY"},
	}, "admin"); err != nil {
		t.Fatal("could not configure the isolated provider fixture")
	}
	configured, _, loadErr := f.server.loadAIProvider(context.Background())
	if loadErr != nil {
		t.Fatalf("isolated live provider routing failed before network access: %v", loadErr)
	}
	if !configured.Enabled || configured.ID != "r9-live-gemini-test" {
		t.Fatalf("isolated live provider route mismatch: id=%s enabled=%t", configured.ID, configured.Enabled)
	}
	if !f.server.aiProviderReady(configured) {
		t.Fatal("isolated live provider credential resolution failed")
	}
	_, _, _, connectionErr := f.server.callConfiguredAIWithSystem(context.Background(), configured, "Reply with the single JSON object requested.", `Return only one JSON object: {"ok":true}.`, nil)
	if connectionErr != nil {
		probe := aiprovider.NewSafeHTTPClient(providerPolicy(), 10*time.Second)
		response, diagnostic := probe.Get("https://generativelanguage.googleapis.com/")
		if response != nil {
			response.Body.Close()
		}
		t.Fatalf("isolated provider adapter preflight failed (sanitized adapter error): %v; unauthenticated fixed-host diagnostic: %v", connectionErr, diagnostic)
	}
	results := []map[string]any{}
	for _, example := range []struct{ workspace, question, action string }{
		{"selective-input", "My event filter is configured. I want to preview matched raw records only, without parsing or publishing. Which button do I press?", "policy-run-filter"},
		{"output-fields", "I already configured pid and thread_id for removal. Which button parses my sample and previews JSON field removal before I publish?", "policy-run-output"},
	} {
		start := time.Now()
		response, body := f.request(http.MethodPost, "/api/v1/ai/guidance/evaluate", map[string]any{
			"workspace": example.workspace, "question": example.question, "use_provider": true,
		})
		if response.StatusCode != http.StatusOK {
			t.Fatalf("live guidance returned HTTP %d", response.StatusCode)
		}
		result := decodeMap(t, body)
		selected, _ := result["selected"].(map[string]any)
		instructions, _ := result["instructions"].(map[string]any)
		steps, _ := instructions["steps"].([]any)
		if result["provider_status"] != "selected" || selected["id"] != example.action || len(steps) < 3 {
			t.Fatalf("live guidance verification failed: workspace=%s provider_status=%v selected=%v step_count=%d", example.workspace, result["provider_status"], selected["id"], len(steps))
		}
		if bytes.Contains(body, []byte(key)) {
			t.Fatal("credential leaked into guidance response")
		}
		results = append(results, map[string]any{"workspace": example.workspace, "selected_action": selected["id"],
			"provider_status": result["provider_status"], "numbered_step_count": len(steps), "elapsed_ms": time.Since(start).Milliseconds()})
	}
	for _, collection := range []string{"ai-provider", aiGuidanceEvaluationStore} {
		documents, err := f.server.metadata.List(context.Background(), collection, metastore.Query{Limit: 100})
		if err != nil {
			t.Fatal("could not inspect isolated guidance metadata")
		}
		for _, doc := range documents {
			if bytes.Contains(doc.Payload, []byte(key)) {
				t.Fatal("credential appeared in controller metadata")
			}
		}
	}
	proof := map[string]any{"provider": "gemini", "model": "gemini-3.5-flash-lite", "results": results,
		"private_credential_source": "Windows Credential Manager", "credentials_in_evidence": false,
		"synthetic_questions_only": true, "production_configuration_modified": false}
	if path := os.Getenv("NLI_R9_LIVE_AI_PROOF"); path != "" {
		encoded, _ := json.MarshalIndent(proof, "", "  ")
		if err := os.WriteFile(path, append(encoded, '\n'), 0600); err != nil {
			t.Fatal("could not write redacted live test evidence")
		}
	}
	t.Log("both live Gemini requests selected the expected verified policy actions and returned numbered guidance")
}
