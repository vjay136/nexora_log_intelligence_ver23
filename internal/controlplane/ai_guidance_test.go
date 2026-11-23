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

func TestR9PolicyGuidanceUsesRealControlsAndExplicitPreviewReviewSequence(t *testing.T) {
	for _, example := range []struct{ question, workspace, action string }{
		{"Please grep SmtpServerEHLO and only read those raw logs", "selective-input", "policy-run-filter"},
		{"Remove pid and thread_id from the JSON before Loki", "output-fields", "policy-run-output"},
		{"Hide these unwanted JSON fields", "output-fields", "policy-run-output"},
	} {
		scope := guidanceQuestionScope(example.question)
		if scope.Workspace != example.workspace {
			t.Fatalf("%q selected %s", example.question, scope.Workspace)
		}
		_, choices, err := scope.resolve()
		if err != nil {
			t.Fatal(err)
		}
		var selected aiGuidanceAction
		for _, action := range choices {
			if action.ID == example.action {
				selected = action
			}
		}
		if selected.ID == "" {
			t.Fatalf("missing actual policy control %s", example.action)
		}
		instructions := guidanceInstructions(scope, selected)
		joined := strings.Join(instructions.Steps, "\n")
		for _, marker := range []string{"Save draft revision", "Submit for review", "Approve", "Parser Fleet Sync"} {
			if !strings.Contains(joined, marker) {
				t.Fatalf("guidance omits %s: %s", marker, joined)
			}
		}
		if example.workspace == "selective-input" && (!strings.Contains(joined, "Run Filter") || !strings.Contains(joined, "Parse matched records") || !strings.Contains(joined, "one accepted raw record")) {
			t.Fatal("input guide lost raw-first selection semantics")
		}
		if example.workspace == "output-fields" && !strings.Contains(joined, "case-sensitive root JSON key") {
			t.Fatal("output guide implies unsupported recursive removal")
		}
	}
	if aiGuidanceCatalogVersion != 5 {
		t.Fatal("new policy guidance must have its own catalog revision")
	}
}

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

func TestAIGuidanceEverydayQuestionsReturnGroundedNumberedWorkflows(t *testing.T) {
	f := newAPIFixture(t)
	for _, tt := range []struct{ question, workspace, tab, required string }{
		{"how can i import 1000 known keys in one load pls", "knownkeys", "", "Create bulk known-key draft"},
		{"i have many keys at once", "knownkeys", "", "Preview import"},
		{"napi not submit it says 409", "assurance", "synthesis", "Save supplied redacted validation examples"},
		{"where add validation examples for parser review", "assurance", "synthesis", "Save approval-gated draft"},
		{"after login it is asking approval what should i do", "rollouts", "", "Do not approve unfamiliar proposals"},
		{"my client still old how to sync", "parser-sync", "", "applied hash equals"},
		{"i want restore last backup", "backup-restore", "", "Approve restore"},
		{"call my client mail01", "clients", "", "operating-system host"},
		{"group100IMAP servers", "clients", "", "10,000 enrolled members"},
		{"rollout to SMTP-IN group", "clients", "", "Preview group targets"},
		{"can you help me", "ai-guidance", "", "A vague question"},
	} {
		t.Run(tt.question, func(t *testing.T) {
			response, body := f.request(http.MethodPost, "/api/v1/ai/guidance/evaluate", map[string]any{"workspace": "auto", "question": tt.question})
			if response.StatusCode != http.StatusOK {
				t.Fatalf("%d %s", response.StatusCode, body)
			}
			result := decodeMap(t, body)
			scope := result["scope"].(map[string]any)
			if scope["workspace"] != tt.workspace || (tt.tab != "" && scope["tab"] != tt.tab) {
				t.Fatalf("wrong navigation: %s", body)
			}
			instructions := result["instructions"].(map[string]any)
			steps := instructions["steps"].([]any)
			wire, _ := json.Marshal(instructions)
			if len(steps) < 4 || !strings.Contains(string(wire), tt.required) || instructions["completion_check"] == "" || instructions["permission_note"] == "" {
				t.Fatalf("incomplete workflow: %s", body)
			}
			if result["provider_status"] != "not_requested" {
				t.Fatalf("unexpected provider access: %s", body)
			}
		})
	}
	// Explicit selected scopes remain authoritative even when the question
	// happens to mention another workflow, and actions cannot cross that scope.
	response, body := f.request(http.MethodPost, "/api/v1/ai/guidance/evaluate", map[string]any{"workspace": "parser-sync", "action": "parser-sync-verify", "question": "import known keys"})
	if response.StatusCode != http.StatusOK || decodeMap(t, body)["scope"].(map[string]any)["workspace"] != "parser-sync" {
		t.Fatalf("explicit scope changed: %d %s", response.StatusCode, body)
	}
	response, body = f.request(http.MethodPost, "/api/v1/ai/guidance/evaluate", map[string]any{"workspace": "auto", "action": "rollout-approve", "question": "help"})
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("automatic scope accepted injected action: %d %s", response.StatusCode, body)
	}
}

func TestAIGuidanceClientDirectoryActionsStayBoundToRealControls(t *testing.T) {
	for _, tt := range []struct{ question, action, completion string }{
		{"call my client mail01", "client-directory-save-name", "same immutable node ID"},
		{"group100IMAP servers", "client-directory-save-group", "original explicit targets"},
		{"rollout to SMTP-IN group", "client-group-preview", "canonical published bundle"},
	} {
		scope := guidanceQuestionScope(tt.question)
		if scope.Workspace != "clients" {
			t.Fatalf("wrong workspace for %q: %+v", tt.question, scope)
		}
		_, choices, err := scope.resolve()
		if err != nil {
			t.Fatal(err)
		}
		action := nativeGuidanceAction(tt.question, choices)
		if action.ID != tt.action {
			t.Fatalf("%q selected %+v", tt.question, action)
		}
		guide := guidanceInstructions(scope, action)
		if !strings.Contains(guide.CompletionCheck, tt.completion) {
			t.Fatalf("missing directory limits/gates: %+v", guide)
		}
	}
	// A group question cannot escape an explicitly chosen fleet-verification
	// action, and even a provider receives only that scope's available choices.
	_, choices, err := (aiGuidanceScope{Workspace: "parser-sync", Action: "parser-sync-verify"}).resolve()
	if err != nil {
		t.Fatal(err)
	}
	if nativeGuidanceAction("rollout to SMTP-IN group", choices).ID != "parser-sync-verify" {
		t.Fatal("group question bypassed explicit action scope")
	}
}

func TestAIGuidanceInstructionsNeverClaimApprovalOrLiveState(t *testing.T) {
	for _, workspace := range aiGuidanceCatalog {
		for _, action := range workspace.Actions {
			guide := guidanceInstructions(aiGuidanceScope{Workspace: workspace.ID}, action)
			if guide.Navigation != workspace.Label || len(guide.Steps) < 3 || guide.CompletionCheck == "" {
				t.Fatalf("incomplete %s/%s: %+v", workspace.ID, action.ID, guide)
			}
		}
	}
	if aiGuidanceIdentity.Version != 5 {
		t.Fatal("workflow instructions require a new catalog revision")
	}
}

func TestR10TerminalGuidanceIsPreciseAndTranscriptFree(t *testing.T) {
	for _, question := range []string{"How do I open a node terminal?", "I need Linux command line for my demo", "Can I read journalctl through webapp without SSH?"} {
		scope := guidanceQuestionScope(question)
		if scope.Workspace != "node-terminal" {
			t.Fatalf("wrong workspace for %q: %+v", question, scope)
		}
		_, choices, err := scope.resolve()
		if err != nil || len(choices) == 0 {
			t.Fatalf("terminal guidance unavailable: %v", err)
		}
		guide := guidanceInstructions(scope, choices[0])
		joined := strings.Join(guide.Steps, "\n")
		for _, marker := range []string{"COMMAND CENTER → Node Terminal", "NLI login password", "Session reason", "Connect terminal", "Paste example · no Enter", "Disconnect terminal", "not automatically retried", "not AI context"} {
			if !strings.Contains(joined, marker) {
				t.Errorf("terminal guidance missing %q", marker)
			}
		}
		if !strings.Contains(guide.PermissionNote, "not a root shell") {
			t.Fatal("terminal guidance must explain operator privilege boundary")
		}
	}
	if aiGuidanceCatalogVersion != 5 {
		t.Fatal("R11 terminal guidance needs catalog revision 5")
	}
}
