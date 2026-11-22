package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"nexora.local/nli-v20/internal/engine"
	"nexora.local/nli-v20/internal/registry"
)

func napiSMTPExample(n int, extra int, dynamic bool) assuranceRequest {
	date, timestamp := "20250811", "080053105+0100"
	host, pid, thread, random := "aaa-gmailrgi009", "3692", "140026854221568", "123456"
	if n > 0 {
		date = fmt.Sprintf("202508%02d", 11+n)
		timestamp = fmt.Sprintf("0800%02d105+0100", 53+n)
		host = fmt.Sprintf("mail-%03d", n)
		pid = fmt.Sprint(3692 + n)
		thread = fmt.Sprint(140026854221568 + int64(n))
		random = fmt.Sprint(123456 + n)
	}
	desired := map[string]any{"date": date, "timestamp": timestamp, "hostname": host, "service": "smtp", "pid": pid, "minor_pid": "0", "thread_id": thread, "random_number": random, "event_type": "Note", "event": "SieveRuleMsg", "status": "failed", "reason": "not needed"}
	tags := []string{"efgh", "ijkl", "mnop", "qrst", "uvwx"}
	for i := 0; i < extra; i++ {
		desired[fmt.Sprintf("extra_tag%d", i+1)] = tags[i]
	}
	raw := fmt.Sprintf("%s %s %s smtp %s 0 %s %s;Note;", date, timestamp, host, pid, thread, random)
	if extra > 0 {
		raw += strings.Join(tags[:extra], ";") + ";"
	}
	raw += "SieveRuleMsg status=failed;reason=not needed"
	if dynamic {
		raw += ";vjay=vjay;reply=done"
		desired["vjay"] = "vjay"
		desired["reply"] = "done"
	}
	return assuranceRequest{Raw: raw, Service: "smtp", Desired: desired}
}

func napiSMTPChangedKV(sample assuranceRequest, status, reason string, reorder bool) assuranceRequest {
	start := strings.Index(sample.Raw, " status=")
	if start < 0 {
		panic("SMTP test fixture missing KV boundary")
	}
	sample.Raw = sample.Raw[:start] + " "
	if reorder {
		sample.Raw += "reason=" + reason + ";status=" + status
	} else {
		sample.Raw += "status=" + status + ";reason=" + reason
	}
	if _, ok := sample.Desired["vjay"]; ok {
		sample.Raw += ";vjay=vjay;reply=done"
	}
	sample.Desired["status"], sample.Desired["reason"] = status, reason
	return sample
}

func TestNAPISMTPSuppliedHeaderKVProducesExactProductionOutput(t *testing.T) {
	f := newAPIFixture(t)
	input := map[string]any{"id": "napi-smtp-full", "name": "SMTP complete header and KV", "retain_review_examples": true, "discovery": []assuranceRequest{napiSMTPExample(0, 3, false), napiSMTPChangedKV(napiSMTPExample(1, 3, false), "success", "mail delivered", false)}, "held_out": []assuranceRequest{napiSMTPChangedKV(napiSMTPExample(2, 3, true), "queued", "waiting for relay", true)}, "negative": []string{"not a structured record"}}
	response, body := f.request(http.MethodPost, "/api/v1/assurance/napi/synthesize", input)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("complete SMTP synthesis %d: %s", response.StatusCode, body)
	}
	created := decodeMap(t, body)
	if created["strategy"] != "header_kv" || created["requires_validation_examples"] != false {
		t.Fatalf("wrong generated strategy/review state: %s", body)
	}
	_, stored := f.request(http.MethodGet, "/api/v1/assurance/parsers/napi-smtp-full", nil)
	payload := decodeMap(t, stored)["payload"].(map[string]any)
	definition := payload["parser"].(map[string]any)
	proof := []map[string]any{}
	for _, sample := range []assuranceRequest{napiSMTPExample(0, 3, false), napiSMTPChangedKV(napiSMTPExample(3, 3, true), "deferred", "remote relay not ready", true)} {
		encoded, _ := json.Marshal(definition)
		var parser registry.ParserDef
		if json.Unmarshal(encoded, &parser) != nil || registry.Validate(&parser) != nil {
			t.Fatal("invalid native mapping")
		}
		actual, failures := registry.Apply(&parser, sample.Raw)
		diff, _ := structuralDiff(actual, sample.Desired)
		if len(failures) != 0 || len(diff) != 0 {
			t.Fatalf("wrong full flat SMTP output: actual=%v failures=%v diff=%v", actual, failures, diff)
		}
		if _, nested := actual["kv_pair"]; nested {
			t.Fatal("nested KV wrapper emitted")
		}
		proof = append(proof, map[string]any{"raw": sample.Raw, "expected": sample.Desired, "actual": actual, "flat_field_count": len(actual), "exact_output": true, "production_native_validation": "passed"})
	}
	if err := validateNAPIRuntime(context.Background(), "napi-smtp-full", "0.1.0", "admin", definition, []assuranceRequest{napiSMTPExample(3, 3, true)}); err != nil {
		t.Fatalf("production runtime mismatch: %v", err)
	}
	if report := os.Getenv("NLI_NAPI_SMTP_REPORT"); report != "" {
		data, _ := json.MarshalIndent(map[string]any{"release": engine.ReleaseID, "source": "Provided SMTP sample and separate changed-value/reordered-KV variant", "strategy": "header_kv", "cases": proof, "limits": "Observed validated header grammar only; unseen layouts require a new validated template. Negative tests prove rejection, not successful parsing."}, "", "  ")
		if err := os.WriteFile(report, append(data, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNAPISMTPSavedExamplesSubmitApprovePublishThroughBothCatalogs(t *testing.T) {
	for _, routes := range []struct{ submit, approve string }{{"assurance/parsers", "assurance/parsers"}, {"parser-packs", "assurance/parsers"}, {"assurance/parsers", "parser-packs"}, {"parser-packs", "parser-packs"}} {
		t.Run(routes.submit+" to "+routes.approve, func(t *testing.T) {
			f := newAPIFixture(t)
			id := "napi-smtp-lifecycle"
			response, body := f.request(http.MethodPost, "/api/v1/assurance/napi/synthesize", map[string]any{"id": id, "name": "SMTP full output review", "retain_review_examples": true, "candidate_limit": 1, "discovery": []assuranceRequest{napiSMTPExample(0, 3, false), napiSMTPExample(1, 3, false)}, "held_out": []assuranceRequest{napiSMTPExample(2, 3, true)}, "negative": []string{"not a mail record"}})
			if response.StatusCode != http.StatusCreated {
				t.Fatalf("synthesize %d: %s", response.StatusCode, body)
			}
			response, body = f.request(http.MethodPost, "/api/v1/"+routes.submit+"/"+id+"/submit", map[string]any{})
			if response.StatusCode != http.StatusOK {
				t.Fatalf("submit %d: %s", response.StatusCode, body)
			}
			response, body = f.request(http.MethodPost, "/api/v1/assurance/parsers/"+id+"/publish", map[string]any{})
			if response.StatusCode != http.StatusConflict {
				t.Fatalf("publication bypassed review: %d %s", response.StatusCode, body)
			}
			doc, err := f.server.metadata.Get(context.Background(), "parser-packs", id, 0)
			if err != nil {
				t.Fatal(err)
			}
			var submitted map[string]any
			if json.Unmarshal(doc.Payload, &submitted) != nil {
				t.Fatal("bad submitted payload")
			}
			response, body = f.request(http.MethodPost, "/api/v1/"+routes.approve+"/"+id+"/approve", approvalRequest{Reason: "Exact SMTP revision approval", EmergencySelfApproval: true, ExpectedRevision: doc.Revision - 1, ExpectedChecksum: fmt.Sprint(submitted["artifact_checksum"])})
			if response.StatusCode != http.StatusConflict {
				t.Fatalf("stale revision approved %d: %s", response.StatusCode, body)
			}
			loginParserSyncApprover(t, f)
			response, body = f.request(http.MethodPost, "/api/v1/"+routes.approve+"/"+id+"/approve", approvalRequest{Reason: "Independent full SMTP expected-output review"})
			if response.StatusCode != http.StatusOK {
				t.Fatalf("approve %d: %s", response.StatusCode, body)
			}
			response, body = f.request(http.MethodPost, "/api/v1/assurance/parsers/"+id+"/publish", map[string]any{})
			if response.StatusCode != http.StatusOK || decodeMap(t, body)["approval_gate"] != "pending_approval" {
				t.Fatalf("publish %d: %s", response.StatusCode, body)
			}
			_, stored := f.request(http.MethodGet, "/api/v1/assurance/parsers/"+id, nil)
			payload := decodeMap(t, stored)["payload"].(map[string]any)
			definition := payload["parser"].(map[string]any)
			if err := validateNAPIRuntime(context.Background(), id, "0.1.0", "admin", definition, []assuranceRequest{napiSMTPExample(3, 3, true)}); err != nil {
				t.Fatalf("published SMTP native runtime: %v", err)
			}
		})
	}
}

func TestNAPISMTPTamperedSubmittedArtifactCannotApproveThroughEitherCatalog(t *testing.T) {
	for _, catalog := range []string{"assurance/parsers", "parser-packs"} {
		t.Run(catalog, func(t *testing.T) {
			f := newAPIFixture(t)
			id := "napi-smtp-tamper"
			response, body := f.request(http.MethodPost, "/api/v1/assurance/napi/synthesize", map[string]any{"id": id, "name": "SMTP exact submitted artifact", "retain_review_examples": true, "candidate_limit": 1, "discovery": []assuranceRequest{napiSMTPExample(0, 3, false), napiSMTPExample(1, 3, false)}, "held_out": []assuranceRequest{napiSMTPExample(2, 3, false)}})
			if response.StatusCode != http.StatusCreated {
				t.Fatalf("synthesize %d: %s", response.StatusCode, body)
			}
			response, body = f.request(http.MethodPost, "/api/v1/parser-packs/"+id+"/submit", map[string]any{})
			if response.StatusCode != http.StatusOK {
				t.Fatalf("submit %d: %s", response.StatusCode, body)
			}
			doc, err := f.server.metadata.Get(context.Background(), "parser-packs", id, 0)
			if err != nil {
				t.Fatal(err)
			}
			var payload map[string]any
			_ = json.Unmarshal(doc.Payload, &payload)
			definition := payload["parser"].(map[string]any)
			definition["description"] = "Out-of-band changed definition after submission"
			payload["artifact_checksum"] = parserArtifactChecksum(definition)
			doc.Payload, _ = json.Marshal(payload)
			if _, err = f.server.metadata.Put(context.Background(), doc); err != nil {
				t.Fatal(err)
			}
			loginParserSyncApprover(t, f)
			response, body = f.request(http.MethodPost, "/api/v1/"+catalog+"/"+id+"/approve", approvalRequest{Reason: "Review must reject replaced artifact"})
			if response.StatusCode != http.StatusConflict {
				t.Fatalf("tampered artifact approved via %s %d: %s", catalog, response.StatusCode, body)
			}
		})
	}
}

func TestNAPISMTPObservedExtraTagVariantsAndDynamicKVRemainExact(t *testing.T) {
	f := newAPIFixture(t)
	response, body := f.request(http.MethodPost, "/api/v1/assurance/napi/synthesize", map[string]any{"id": "napi-smtp-variants", "name": "SMTP bounded observed tag range", "retain_review_examples": true, "candidate_limit": 1, "discovery": []assuranceRequest{napiSMTPExample(0, 0, false), napiSMTPExample(1, 4, false)}, "held_out": []assuranceRequest{napiSMTPExample(2, 3, true)}})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("observed variant synthesis %d: %s", response.StatusCode, body)
	}
	_, stored := f.request(http.MethodGet, "/api/v1/assurance/parsers/napi-smtp-variants", nil)
	definition := decodeMap(t, stored)["payload"].(map[string]any)["parser"].(map[string]any)
	encoded, _ := json.Marshal(definition)
	var parser registry.ParserDef
	if json.Unmarshal(encoded, &parser) != nil || registry.Validate(&parser) != nil {
		t.Fatal("invalid composed parser")
	}
	for tags := 0; tags <= 4; tags++ {
		sample := napiSMTPExample(3, tags, true)
		actual, failures := registry.Apply(&parser, sample.Raw)
		diff, _ := structuralDiff(actual, sample.Desired)
		if len(failures) != 0 || len(diff) != 0 {
			t.Fatalf("%d tags incorrect output: actual=%v failures=%v diff=%v", tags, actual, failures, diff)
		}
	}
	for _, raw := range []string{
		napiSMTPExample(3, 5, true).Raw,
		strings.Replace(napiSMTPExample(3, 3, false).Raw, "Note;", "Note;Error;", 1),
		strings.Replace(napiSMTPExample(3, 3, false).Raw, "reason=not needed", "reason=\"unterminated", 1),
		"not a structured mail record",
	} {
		actual, failures := registry.Apply(&parser, raw)
		if len(failures) == 0 {
			t.Fatalf("unsupported or malformed record accepted: %q => %v", raw, actual)
		}
	}
}

func TestNAPISMTPWrongExpectedOutputAndUnobservedHeaderDoNotCreatePassingDraft(t *testing.T) {
	for _, variant := range []string{"wrong expected value", "missing expected field", "extra expected field", "wrong expected type", "unobserved extra tag", "ambiguous header"} {
		t.Run(variant, func(t *testing.T) {
			f := newAPIFixture(t)
			held := napiSMTPExample(2, 3, false)
			switch variant {
			case "wrong expected value":
				held.Desired["status"] = "success"
			case "missing expected field":
				delete(held.Desired, "reason")
			case "extra expected field":
				held.Desired["invented_field"] = "absent from source"
			case "wrong expected type":
				held.Desired["pid"] = float64(3694)
			case "unobserved extra tag":
				held = napiSMTPExample(2, 4, false)
			case "ambiguous header":
				held.Raw = strings.Replace(held.Raw, "Note;", "Note;Error;", 1)
			}
			response, body := f.request(http.MethodPost, "/api/v1/assurance/napi/synthesize", map[string]any{"id": "napi-smtp-rejected", "name": "SMTP rejection gate", "retain_review_examples": true, "discovery": []assuranceRequest{napiSMTPExample(0, 3, false), napiSMTPExample(1, 3, false)}, "held_out": []assuranceRequest{held}})
			if response.StatusCode != http.StatusUnprocessableEntity {
				t.Fatalf("bad %s accepted: %d %s", variant, response.StatusCode, body)
			}
			response, _ = f.request(http.MethodGet, "/api/v1/assurance/parsers/napi-smtp-rejected", nil)
			if response.StatusCode != http.StatusNotFound {
				t.Fatalf("rejected %s persisted a parser", variant)
			}
		})
	}
}
