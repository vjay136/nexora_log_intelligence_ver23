package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	metastore "nexora.local/nli-v20/internal/store"
	parserpolicy "nexora.local/nli-v20/parser-policy"
)

func TestNAPISynthesisCreatesEvidenceBackedDraftWithoutRawSamples(t *testing.T) {
	f := newAPIFixture(t)
	discovery := []any{
		map[string]any{"raw": `{"level":"INFO","count":12}`, "desired": map[string]any{"level": "INFO", "count": 12}},
		map[string]any{"raw": `{"level":"WARN","count":19}`, "desired": map[string]any{"level": "WARN", "count": 19}},
	}
	heldOut := []any{map[string]any{"raw": `{"level":"ERROR","count":42}`, "desired": map[string]any{"level": "ERROR", "count": 42}}}
	response, data := f.request(http.MethodPost, "/api/v1/assurance/napi/synthesize", map[string]any{
		"id": "napi-json", "name": "NAPI JSON", "version": "0.1.0",
		"discovery": discovery, "held_out": heldOut,
		"negative": []string{`{"unrelated":"value"}`},
	})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("synthesize %d: %s", response.StatusCode, data)
	}
	created := decodeMap(t, data)
	if created["state"] != "draft" || created["published"] != false || created["requires_human_approval"] != true || created["requires_validation_examples"] != true {
		t.Fatalf("unsafe lifecycle response: %s", data)
	}
	validation, _ := created["validation"].(map[string]any)
	held, _ := validation["held_out"].(map[string]any)
	if held["exact"] != float64(1) || validation["eligible"] != true {
		t.Fatalf("held-out validation missing: %s", data)
	}
	evolution, _ := created["nupire"].(map[string]any)
	if evolution["id"] == nil || evolution["state"] != "rejected" || evolution["scope"] != "evaluation" || evolution["parser_id"] != "napi-json" {
		t.Fatalf("NAPI candidate was not bound to the stricter EGPE evidence gate: %s", data)
	}

	response, stored := f.request(http.MethodGet, "/api/v1/assurance/parsers/napi-json", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("get draft %d: %s", response.StatusCode, stored)
	}
	for _, raw := range []string{`{"level":"INFO","count":12}`, `{"level":"ERROR","count":42}`, `{"unrelated":"value"}`} {
		if bytes.Contains(stored, []byte(raw)) {
			t.Fatalf("raw synthesis sample leaked into parser metadata: %s", stored)
		}
		if bytes.Contains(data, []byte(raw)) {
			t.Fatalf("raw synthesis sample leaked into NUPIRE response: %s", data)
		}
	}
	if !bytes.Contains(stored, []byte(`"raw_samples_persisted":false`)) || !bytes.Contains(stored, []byte(`"held_out_sample_hashes"`)) {
		t.Fatalf("synthesis provenance missing: %s", stored)
	}

	response, publish := f.request(http.MethodPost, "/api/v1/assurance/parsers/napi-json/publish", map[string]any{})
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("draft bypassed review gate: %d %s", response.StatusCode, publish)
	}
	const draftPath = "/api/v1/assurance/parsers/napi-json"
	for _, action := range []string{"validate", "submit"} {
		response, body := f.request(http.MethodPost, draftPath+"/"+action, struct{}{})
		if response.StatusCode != http.StatusConflict || !bytes.Contains(body, []byte("add representative redacted validation examples")) {
			t.Fatalf("%s did not explain the evidence requirement %d: %s", action, response.StatusCode, body)
		}
	}
	draft := decodeMap(t, stored)["payload"].(map[string]any)
	checksum, _ := draft["artifact_checksum"].(string)
	if !validBundleRecoverySHA(checksum) || draft["validation_passed"] != false || checksum != created["artifact_checksum"] {
		t.Fatalf("synthetic proof was confused with saved review evidence: %s", stored)
	}
	definition, _ := draft["parser"].(map[string]any)
	if definition["pattern_type"] != "mapping" {
		t.Fatalf("JSON candidate has no production-native mapping: %+v", definition)
	}
	confirmed := map[string]any{"raw": `{"level":"NOTICE","count":50}`, "service": "napi-test", "desired": map[string]any{"level": "NOTICE", "count": 50}}
	response, body := f.request(http.MethodPut, draftPath, map[string]any{"name": "NAPI JSON", "version": "0.1.0", "parser": definition, "cases": []any{confirmed}})
	if response.StatusCode != http.StatusOK || decodeMap(t, body)["validation"].(map[string]any)["status"] != "passed" {
		t.Fatalf("attach NAPI reviewed examples %d: %s", response.StatusCode, body)
	}
	response, body = f.request(http.MethodPost, draftPath+"/submit", struct{}{})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("submit exact NAPI definition %d: %s", response.StatusCode, body)
	}
	loginParserSyncApprover(t, f)
	response, body = f.request(http.MethodPost, draftPath+"/approve", approvalRequest{Reason: "Independent NAPI evidence review"})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("approve exact NAPI definition %d: %s", response.StatusCode, body)
	}
	response, body = f.request(http.MethodPost, draftPath+"/publish", struct{}{})
	if response.StatusCode != http.StatusOK || decodeMap(t, body)["approval_gate"] != "pending_approval" {
		t.Fatalf("publish reviewed NAPI JSON parser %d: %s", response.StatusCode, body)
	}
	bundle, err := f.server.buildActiveParserBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, asset := range bundle.Assets {
		if asset.AssetClass == "parser-packs" && asset.AssetID == "napi-json" {
			pack, err := parserpolicy.LoadParserPackBytes(asset.Payload)
			if err != nil || len(pack.RegressionCases) != 1 || pack.RegressionCases[0].Input != confirmed["raw"] {
				t.Fatalf("published pack did not pin only the intentionally saved example: %+v %v", pack, err)
			}
			return
		}
	}
	t.Fatal("published NAPI parser omitted from the fleet bundle")
}

func TestNAPISynthesisExplicitReviewRetentionSubmitsThroughBothCatalogs(t *testing.T) {
	for _, catalog := range []string{"assurance/parsers", "parser-packs"} {
		t.Run(catalog, func(t *testing.T) {
			f := newAPIFixture(t)
			discovery := []any{
				map[string]any{"raw": `{"level":"INFO","count":12}`, "desired": map[string]any{"level": "INFO", "count": 12}},
				map[string]any{"raw": `{"level":"WARN","count":19}`, "desired": map[string]any{"level": "WARN", "count": 19}},
			}
			heldOut := []any{map[string]any{"raw": `{"level":"ERROR","count":42}`, "desired": map[string]any{"level": "ERROR", "count": 42}}}
			response, data := f.request(http.MethodPost, "/api/v1/assurance/napi/synthesize", map[string]any{
				"id": "napi-saved-examples", "name": "NAPI explicitly redacted examples", "version": "0.1.0",
				"discovery": discovery, "held_out": heldOut, "negative": []string{"not a matching record"},
				"retain_review_examples": true,
			})
			if response.StatusCode != http.StatusCreated {
				t.Fatalf("synthesize %d: %s", response.StatusCode, data)
			}
			created := decodeMap(t, data)
			if created["requires_validation_examples"] != false || created["review_examples_retained"] != float64(3) || created["review_validation"].(map[string]any)["status"] != "passed" {
				t.Fatalf("explicit saved examples not validated: %s", data)
			}
			_, stored := f.request(http.MethodGet, "/api/v1/assurance/parsers/napi-saved-examples", nil)
			payload := decodeMap(t, stored)["payload"].(map[string]any)
			if payload["validation_passed"] != true || len(payload["cases"].([]any)) != 3 {
				t.Fatalf("saved artifact has no exact review evidence: %s", stored)
			}
			if bytes.Contains(stored, []byte("not a matching record")) {
				t.Fatal("negative raw record was retained without review-example authorization")
			}
			response, body := f.request(http.MethodPost, "/api/v1/"+catalog+"/napi-saved-examples/submit", map[string]any{})
			if response.StatusCode != http.StatusOK {
				t.Fatalf("submit through %s %d: %s", catalog, response.StatusCode, body)
			}
			response, body = f.request(http.MethodPost, "/api/v1/assurance/parsers/napi-saved-examples/publish", map[string]any{})
			if response.StatusCode != http.StatusConflict {
				t.Fatalf("retained examples bypassed independent review: %d %s", response.StatusCode, body)
			}
		})
	}
}

func TestNAPISynthesisRetainedExamplesCannotTurnWrongExpectedOutputIntoPassingEvidence(t *testing.T) {
	f := newAPIFixture(t)
	response, data := f.request(http.MethodPost, "/api/v1/assurance/napi/synthesize", map[string]any{
		"id": "napi-wrong-output", "name": "NAPI mismatched expectations", "retain_review_examples": true,
		"discovery": []any{
			map[string]any{"raw": `{"count":12}`, "desired": map[string]any{"count": 912}},
			map[string]any{"raw": `{"count":19}`, "desired": map[string]any{"count": 919}},
		},
		"held_out": []any{map[string]any{"raw": `{"count":42}`, "desired": map[string]any{"count": 942}}},
	})
	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("wrong expectations accepted %d: %s", response.StatusCode, data)
	}
	response, _ = f.request(http.MethodGet, "/api/v1/assurance/parsers/napi-wrong-output", nil)
	if response.StatusCode != http.StatusNotFound {
		t.Fatal("failed opted-in synthesis persisted a parser")
	}
}

func TestNAPISynthesisBuildsAnchoredRegexAndRejectsOverfit(t *testing.T) {
	f := newAPIFixture(t)
	valid := map[string]any{
		"id": "napi-regex", "name": "NAPI Regex",
		"discovery": []any{
			map[string]any{"raw": "INFO alice 100", "desired": map[string]any{"level": "INFO", "user": "alice", "count": 100}},
			map[string]any{"raw": "WARN bob 200", "desired": map[string]any{"level": "WARN", "user": "bob", "count": 200}},
		},
		"held_out": []any{map[string]any{"raw": "ERROR carol 300", "desired": map[string]any{"level": "ERROR", "user": "carol", "count": 300}}},
		"negative": []string{"unrelated record"},
	}
	response, data := f.request(http.MethodPost, "/api/v1/assurance/napi/synthesize", valid)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("regex synthesize %d: %s", response.StatusCode, data)
	}
	created := decodeMap(t, data)
	if created["strategy"] != "regex" {
		t.Fatalf("expected regex candidate: %s", data)
	}
	safety, _ := created["regex_safety"].(map[string]any)
	if safety["safe"] != true || safety["anchored"] != true || safety["predictable_runtime"] != true {
		t.Fatalf("regex safety missing: %s", data)
	}

	invalid := map[string]any{
		"id": "napi-overfit", "name": "NAPI Overfit",
		"discovery": valid["discovery"],
		"held_out":  []any{map[string]any{"raw": "ERROR|carol|300", "desired": map[string]any{"level": "ERROR", "user": "carol", "count": 300}}},
		"negative":  []string{"unrelated record"},
	}
	response, rejected := f.request(http.MethodPost, "/api/v1/assurance/napi/synthesize", invalid)
	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("overfit candidate accepted: %d %s", response.StatusCode, rejected)
	}
	if !bytes.Contains(rejected, []byte(`"draft_created":false`)) {
		t.Fatalf("rejection evidence missing: %s", rejected)
	}
	response, _ = f.request(http.MethodGet, "/api/v1/assurance/parsers/napi-overfit", nil)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("rejected synthesis persisted a draft: %d", response.StatusCode)
	}
}

func TestNAPIRegexSafetyBounds(t *testing.T) {
	unsafe := analyzeNAPIRegex(map[string]any{"pattern_type": "regex", "pattern": strings.Repeat("a", napiMaxRegexBytes+1)})
	if unsafe.Safe || len(unsafe.Errors) == 0 {
		t.Fatalf("oversized regex accepted: %+v", unsafe)
	}
	safe := analyzeNAPIRegex(map[string]any{"pattern_type": "regex", "pattern": `^(?P<level>INFO|WARN|ERROR)$`})
	if !safe.Safe || !safe.Anchored || safe.Engine != "go-re2" || safe.CaptureGroups != 1 || safe.Instructions == 0 {
		encoded, _ := json.Marshal(safe)
		t.Fatalf("bounded regex rejected: %s", encoded)
	}
}

func TestNAPISynthesisRejectsDatasetLeakage(t *testing.T) {
	f := newAPIFixture(t)
	sample := map[string]any{"raw": `{"level":"INFO"}`, "desired": map[string]any{"level": "INFO"}}
	response, data := f.request(http.MethodPost, "/api/v1/assurance/napi/synthesize", map[string]any{
		"id": "napi-leak", "name": "NAPI Leakage",
		"discovery": []any{sample, map[string]any{"raw": `{"level":"WARN"}`, "desired": map[string]any{"level": "WARN"}}},
		"held_out":  []any{sample},
	})
	if response.StatusCode != http.StatusBadRequest || !bytes.Contains(data, []byte("must not contain the same normalized record")) {
		t.Fatalf("dataset leakage accepted: %d %s", response.StatusCode, data)
	}
}

func TestNAPIRecoveredKVRequiresRealExamplesThenPublishesThroughSameRuntime(t *testing.T) {
	f := newAPIFixture(t)
	const id = "napi-recovered-kv"
	const path = "/api/v1/assurance/parsers/" + id
	definition := map[string]any{"id": id, "version": 1, "format": "key_value", "pattern_type": "", "pattern": "", "fields": []any{
		map[string]any{"name": "status", "source": "kv:status", "type": "string", "required": true},
		map[string]any{"name": "count", "source": "kv:count", "type": "integer", "required": true},
	}}
	recovery := map[string]any{"source_format": "user-export", "source_filename": "napi-guided-parser.json", "lifecycle": "draft_only", "blockers": []string{"Missing parser artifact checksum", "No validation cases"}}
	_, err := f.server.putBundleRecoveryDocument(context.Background(), "parser-packs", id, "draft", "admin", map[string]any{
		"name": "Recovered NAPI KV", "version": "0.1.0", "parser": definition, "validation_passed": false, "recovery": recovery, "review_state": "draft",
	})
	if err != nil {
		t.Fatal(err)
	}
	response, body := f.request(http.MethodPost, path+"/submit", struct{}{})
	if response.StatusCode != http.StatusConflict || !bytes.Contains(body, []byte("validation examples")) {
		t.Fatalf("legacy NAPI submission lacked an actionable blocker %d: %s", response.StatusCode, body)
	}
	response, body = f.request(http.MethodPut, path, map[string]any{
		"name": "Recovered NAPI KV", "version": "0.1.0", "parser": definition, "cases": []any{
			map[string]any{"raw": "status=INFO count=27", "service": "napi-test", "desired": map[string]any{"status": "INFO", "count": 27}},
		},
	})
	if response.StatusCode != http.StatusOK || decodeMap(t, body)["validation"].(map[string]any)["status"] != "passed" {
		t.Fatalf("legacy NAPI KV upgrade %d: %s", response.StatusCode, body)
	}
	doc, err := f.server.metadata.Get(context.Background(), "parser-packs", id, 0)
	if err != nil {
		t.Fatal(err)
	}
	saved := decodeMap(t, doc.Payload)
	if saved["parser"].(map[string]any)["pattern_type"] != "mapping" || saved["recovery"].(map[string]any)["blockers"] != nil {
		t.Fatalf("current draft still reports obsolete migration blockers: %s", doc.Payload)
	}
	response, body = f.request(http.MethodPost, path+"/submit", struct{}{})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("submit revalidated recovered NAPI KV %d: %s", response.StatusCode, body)
	}
	loginParserSyncApprover(t, f)
	response, body = f.request(http.MethodPost, path+"/approve", approvalRequest{Reason: "Independent restored parser review"})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("approve revalidated recovered NAPI KV %d: %s", response.StatusCode, body)
	}
	response, body = f.request(http.MethodPost, path+"/publish", struct{}{})
	if response.StatusCode != http.StatusOK || decodeMap(t, body)["approval_gate"] != "pending_approval" {
		t.Fatalf("publish revalidated KV parser %d: %s", response.StatusCode, body)
	}
}

type failingNAPICatalogRead struct {
	metastore.Store
	id string
}

func (s failingNAPICatalogRead) Get(ctx context.Context, collection, id string, revision int) (metastore.Document, error) {
	if collection == "parser-packs" && id == s.id {
		return metastore.Document{}, errors.New("test catalog read unavailable")
	}
	return s.Store.Get(ctx, collection, id, revision)
}

func TestNAPISynthesisFailsClosedWhenPriorRevisionCannotBeRead(t *testing.T) {
	f := newAPIFixture(t)
	const id = "napi-cannot-verify-head"
	metadata := f.server.metadata
	original, err := metadata.Put(context.Background(), metastore.Document{Collection: "parser-packs", ID: id, State: "published", Payload: json.RawMessage(`{"name":"Existing parser"}`)})
	if err != nil {
		t.Fatal(err)
	}
	f.server.metadata = failingNAPICatalogRead{Store: metadata, id: id}
	response, body := f.request(http.MethodPost, "/api/v1/assurance/napi/synthesize", map[string]any{
		"id": id, "name": "Cannot verify published parser",
		"discovery": []any{
			map[string]any{"raw": "level=INFO count=12", "desired": map[string]any{"level": "INFO", "count": 12}},
			map[string]any{"raw": "level=WARN count=19", "desired": map[string]any{"level": "WARN", "count": 19}},
		},
		"held_out": []any{map[string]any{"raw": "level=ERROR count=42", "desired": map[string]any{"level": "ERROR", "count": 42}}},
	})
	if response.StatusCode != http.StatusServiceUnavailable || !bytes.Contains(body, []byte("revision could not be verified")) {
		t.Fatalf("NAPI ignored unverified head %d: %s", response.StatusCode, body)
	}
	after, err := metadata.Get(context.Background(), original.Collection, original.ID, 0)
	if err != nil || after.Revision != original.Revision || after.State != "published" {
		t.Fatalf("NAPI replaced a published parser during a catalog read error: %+v %v", after, err)
	}
}
