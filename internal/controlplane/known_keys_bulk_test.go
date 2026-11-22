package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	metastore "nexora.local/nli-v20/internal/store"
)

func TestBulkKnownKeysPublicationRecognitionAndRuntime(t *testing.T) {
	f := newAPIFixture(t)
	keys := make([]string, 1500)
	for i := range keys {
		keys[i] = fmt.Sprintf("KnownKey_%04d", i)
	}
	const base = "/api/v1/config/known-keys"
	const id = "bulk-1500-keys"
	response, data := f.request(http.MethodPost, base, map[string]any{"id": id, "name": "Bulk keys", "config": map[string]any{"keys": keys}})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create1500: %d %s", response.StatusCode, data)
	}
	doc, err := f.server.metadata.Get(context.Background(), "known-keys", id, 0)
	if err != nil {
		t.Fatal(err)
	}
	var saved struct {
		Config struct {
			Keys []string `json:"keys"`
		} `json:"config"`
	}
	if json.Unmarshal(doc.Payload, &saved) != nil || len(saved.Config.Keys) != 1500 || saved.Config.Keys[1499] != "KnownKey_1499" {
		t.Fatalf("bulk list truncated: %s", doc.Payload)
	}
	suggest := func() []byte {
		t.Helper()
		response, data := f.request(http.MethodPost, "/api/v1/field-mapping/suggest", map[string]any{"samples": []string{"status=failed;KnownKey_1499=preserved;dynamic_unknown=also preserved"}, "service": "auto"})
		if response.StatusCode != http.StatusOK {
			t.Fatalf("suggest: %d %s", response.StatusCode, data)
		}
		return data
	}
	if strings.Contains(string(suggest()), `"confidence":"known_catalog"`) {
		t.Fatal("draft keys entered suggestions before publication")
	}
	for _, action := range []string{"submit", "approve", "publish"} {
		response, data = f.request(http.MethodPost, base+"/"+id+"/"+action, map[string]any{})
		if response.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d %s", action, response.StatusCode, data)
		}
	}
	if data := suggest(); !strings.Contains(string(data), `"confidence":"known_catalog"`) || !strings.Contains(string(data), `KnownKey_1499`) {
		t.Fatalf("last key not recognized: %s", data)
	}
	header := []byte(`{"config":{"engine":"re2","pattern":"^(?P<host>node[0-9]+) (?P<event>retry) ","fields":{"host":"host","event":"event"}}}`)
	if _, err = f.server.metadata.Put(context.Background(), metastore.Document{Collection: "templates", ID: "bulk-header", State: "active", Payload: header, CreatedBy: "admin"}); err != nil {
		t.Fatal(err)
	}
	response, data = f.request(http.MethodPost, "/api/v1/assurance/run", map[string]any{"raw": "node42 retry KnownKey_1499=preserved;dynamic_unknown=also preserved", "service": "auto"})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("assurance: %d %s", response.StatusCode, data)
	}
	result := decodeMap(t, data)
	actual, ok := result["actual"].(map[string]any)
	if result["passed"] != true || !ok || actual["KnownKey_1499"] != "preserved" || actual["dynamic_unknown"] != "also preserved" || actual["kv_pair"] != nil {
		t.Fatalf("published bulk catalog lost dynamic flat output: %s", data)
	}
	response, data = f.request(http.MethodPost, base+"/"+id+"/revoke", map[string]any{})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("revoke: %d %s", response.StatusCode, data)
	}
	if strings.Contains(string(suggest()), `"confidence":"known_catalog"`) {
		t.Fatal("revoked catalog remained in suggestions")
	}
}

func TestKnownKeyBulkBoundaries(t *testing.T) {
	keys := make([]any, 10000)
	for i := range keys {
		keys[i] = fmt.Sprintf("key_%d", i)
	}
	if err := validateCatalogConfig("known-keys", map[string]any{"keys": keys}); err != nil {
		t.Fatal(err)
	}
	if err := validateCatalogConfig("known-keys", map[string]any{"keys": append(keys, "overflow")}); err == nil {
		t.Fatal("accepted >10000 keys")
	}
	if err := validateCatalogConfig("known-keys", map[string]any{"keys": []any{"Key", "key"}}); err == nil {
		t.Fatal("accepted case-folded duplicates")
	}
	if err := validateCatalogConfig("known-keys", map[string]any{"keys": []any{"valid"}, "metadata": keys}); err == nil {
		t.Fatal("known-key exception bypassed unrelated metadata array bound")
	}
	if err := validateCatalogConfig("known-keys", map[string]any{"keys": []any{map[string]any{"exec": "unsafe"}}}); err == nil {
		t.Fatal("known-key exception accepted non-identifier object")
	}
	if err := validateCatalogConfig("known-keys", map[string]any{"keys": []any{"valid"}, "secret": "do not persist"}); err == nil {
		t.Fatal("known-key exception bypassed forbidden metadata fields")
	}
}
