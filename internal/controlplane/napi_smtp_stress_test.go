package controlplane

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"nexora.local/nli-v20/internal/registry"
)

func TestNAPISMTPSynthesizedOutputStress(t *testing.T) {
	f := newAPIFixture(t)
	response, body := f.request(http.MethodPost, "/api/v1/assurance/napi/synthesize", map[string]any{
		"id": "napi-smtp-stress", "name": "Synthetic SMTP exact-output stress", "retain_review_examples": true,
		"discovery": []assuranceRequest{napiSMTPExample(0, 0, false), napiSMTPExample(1, 4, false)},
		"held_out": []assuranceRequest{napiSMTPExample(2, 3, true)}, "negative": []string{"not a structured mail record"},
	})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("synthesis %d: %s", response.StatusCode, body)
	}
	_, stored := f.request(http.MethodGet, "/api/v1/assurance/parsers/napi-smtp-stress", nil)
	definition := decodeMap(t, stored)["payload"].(map[string]any)["parser"]
	encoded, _ := json.Marshal(definition)
	var parser registry.ParserDef
	if json.Unmarshal(encoded, &parser) != nil || registry.Validate(&parser) != nil {
		t.Fatal("synthesized production definition did not compile")
	}
	samples := make([]assuranceRequest, 5)
	for index := range samples {
		samples[index] = napiSMTPExample(3, index, true)
	}
	const records = 4096
	start := time.Now()
	for index := 0; index < records; index++ {
		sample := samples[index%len(samples)]
		actual, failures := registry.Apply(&parser, sample.Raw)
		diff, _ := structuralDiff(actual, sample.Desired)
		if len(failures) != 0 || len(diff) != 0 {
			t.Fatalf("record %d: failures=%v diff=%v actual=%v", index, failures, diff, actual)
		}
	}
	t.Logf("NAPI generated parser: %d exact flat outputs over 5 observed header variants, zero mismatches, duration=%s", records, time.Since(start))
}
