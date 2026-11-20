package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	metastore "nexora.local/nli-v20/internal/store"
	"strings"
	"testing"
)

func TestFreshReviewedBaselineAssuranceCombinesHeaderVariantsAndDynamicKeys(t *testing.T) {
	f := newAPIFixture(t)
	const head = "20250811 080053105+0100 aaa-gmailrgi009 smtp 3692 0 140026854221568 123456;Note;"
	const tail = "SieveRuleMsg status=failed;reason=not needed;vjay=vjay"
	samples := []string{head + "efgh;ijkl;mnop;" + tail, head + "efgh;ijkl;mnop;qrst;" + tail, head + "efgh;ijkl;mnop;qrst;uvwx;" + tail}
	saveDraft := func(kind, collection, id string) {
		t.Helper()
		response, data := f.request(http.MethodPost, "/api/v1/field-mapping/template-draft", map[string]any{"kind": kind, "samples": samples})
		result := decodeMap(t, data)
		if response.StatusCode != 200 || result["passed"] != true {
			t.Fatalf("%s draft %d %s", kind, response.StatusCode, data)
		}
		payload, err := json.Marshal(map[string]any{"config": result["config"]})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.server.metadata.Put(context.Background(), metastore.Document{Collection: collection, ID: id, State: "active", Payload: payload, CreatedBy: "reviewed-test-admin"}); err != nil {
			t.Fatal(err)
		}
	}
	saveDraft("template", "templates", "smtp-header-variants")
	saveDraft("kv_template", "kv-config", "smtp-tail-variants")
	if _, err := f.server.metadata.Put(context.Background(), metastore.Document{Collection: "known-keys", ID: "smtp-known", State: "active", Payload: json.RawMessage(`{"config":{"keys":["status","reason"]}}`), CreatedBy: "reviewed-test-admin"}); err != nil {
		t.Fatal(err)
	}
	for i, sample := range samples {
		response, data := f.request(http.MethodPost, "/api/v1/assurance/run", map[string]any{"raw": sample, "service": "auto", "preserve_source": true})
		result := decodeMap(t, data)
		if response.StatusCode != 200 || result["passed"] != true || result["parser"].(map[string]any)["name"] != "template/smtp-header-variants" {
			t.Fatalf("variant%d failed %d %s", i+3, response.StatusCode, data)
		}
		actual := result["actual"].(map[string]any)
		if actual["kv_pair"] != nil || actual["status"] != "failed" || actual["reason"] != "not needed" || actual["vjay"] != "vjay" || actual["extra_tag3"] != "mnop" {
			t.Fatalf("flat field mapping variant%d: %v", i+3, actual)
		}
		if i >= 1 && actual["extra_tag4"] != "qrst" {
			t.Fatal("fourth header tag missing")
		}
		if i == 2 && actual["extra_tag5"] != "uvwx" {
			t.Fatal("fifth header tag missing")
		}
		if !strings.Contains(string(data), `"event":"SieveRuleMsg","status":"failed","reason":"not needed","vjay":"vjay"`) {
			t.Fatalf("final JSON lost raw field order: %s", data)
		}
	}
}
