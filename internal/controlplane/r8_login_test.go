package controlplane

import (
	"context"
	"net/http"
	"testing"

	metastore "nexora.local/nli-v20/internal/store"
)

func TestR8LoginAndCatalogReadsDoNotCreateApprovalProposals(t *testing.T) {
	f := newAPIFixture(t)
	bundle, err := f.server.buildActiveParserBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.server.proposeParserBundleRollout(context.Background(), "admin", "Existing reviewed change", "Retain this pre-login pending proposal", "all_eligible", bundle, nil); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		t.Helper()
		docs, err := f.server.metadata.List(context.Background(), "rollout-proposals", metastore.Query{Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		return len(docs)
	}
	before := count()
	for round := 0; round < 2; round++ {
		f.login("admin", "Admin-password-12345!")
		for _, path := range []string{"/api/v1/auth/me", "/api/v1/parser-packs", "/api/v1/assurance/parsers", "/api/v1/parser-sync", "/api/v1/rollouts", "/api/v1/config/known-keys"} {
			response, body := f.request(http.MethodGet, path, nil)
			if response.StatusCode != http.StatusOK {
				t.Fatalf("%s status %d: %s", path, response.StatusCode, body)
			}
		}
	}
	if after := count(); after != before {
		t.Fatalf("read-only login/navigation created approval proposals: before=%d after=%d", before, after)
	}
}
