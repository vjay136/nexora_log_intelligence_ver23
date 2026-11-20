package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	parsercatalog "nexora.local/nli-v20/configs/catalog"
	parserassets "nexora.local/nli-v20/configs/parsers"
	"nexora.local/nli-v20/internal/canonicaljson"
	"nexora.local/nli-v20/internal/fleet"
	metastore "nexora.local/nli-v20/internal/store"
)

func TestReviewedCatalogSeedsMissingOnlyAndPreservesRetiredHistory(t *testing.T) {
	ctx := context.Background()
	store, err := metastore.Open(metastore.Config{Provider: "local", LocalDir: filepath.Join(t.TempDir(), "metadata")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	header, err := store.Put(ctx, metastore.Document{Collection: "templates", ID: "site-header", State: "active", Payload: json.RawMessage(`{"name":"keep customer header"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := seedBuiltinCatalog(ctx, store); err != nil {
		t.Fatal(err)
	}
	reviewed, err := reviewedBuiltinDocuments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(reviewed) < 2 {
		t.Fatal("reviewed product set is incomplete")
	}
	for _, expected := range reviewed {
		actual, err := store.Get(ctx, "parser-packs", expected.ID, 0)
		if err != nil || actual.Revision != 1 || actual.State != "published" {
			t.Fatalf("missing published releasepack %s: %v", expected.ID, err)
		}
		a, _ := canonicaljson.Normalize(actual.Payload)
		b, _ := canonicaljson.Normalize(expected.Payload)
		if !bytes.Equal(a, b) {
			t.Fatal("reviewed pack content changed during seed")
		}
	}
	edited := reviewed[0]
	edited.State = "draft"
	edited.Payload = json.RawMessage(`{"name":"site-owned revision"}`)
	if _, err := store.Put(ctx, edited); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, "parser-packs", reviewed[1].ID, false, "operator"); err != nil {
		t.Fatal(err)
	}
	if err := seedBuiltinCatalog(ctx, store); err != nil {
		t.Fatal(err)
	}
	current, err := store.Get(ctx, "parser-packs", edited.ID, 0)
	if err != nil || current.Revision != 2 || current.State != "draft" || !strings.Contains(string(current.Payload), "site-owned") {
		t.Fatal("startup overwrote existing parser revision")
	}
	if _, err := store.Get(ctx, "parser-packs", reviewed[1].ID, 0); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("startup resurrected retired product parser")
	}
	if _, err := store.Get(ctx, "parser-packs", reviewed[1].ID, 1); err != nil {
		t.Fatal("retired parser history was lost")
	}
	current, err = store.Get(ctx, "templates", header.ID, 0)
	if err != nil || current.Revision != header.Revision || !bytes.Equal(current.Payload, header.Payload) {
		t.Fatal("customer header overwritten")
	}
	for _, doc := range reviewed[2:] {
		current, err := store.Get(ctx, "parser-packs", doc.ID, 0)
		if err != nil || current.Revision != 1 {
			t.Fatal("repeat seed created extra revisions")
		}
	}
}

func TestReviewedCatalogExactProvenanceAndCanonicalRuntimeIdentity(t *testing.T) {
	f := newAPIFixture(t)
	bundle, err := f.server.buildActiveParserBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	configs, _ := parsercatalog.Assets()
	packs, _ := parserassets.All()
	if len(bundle.Assets) != len(configs)+len(packs) || !isBuiltinEnrollmentBundle(bundle) {
		t.Fatalf("expanded release baseline not trusted: assets%d", len(bundle.Assets))
	}
	expected := map[string][]byte{}
	reviewed, _ := reviewedBuiltinDocuments(context.Background())
	for _, doc := range reviewed {
		canonical, _ := canonicaljson.Normalize(doc.Payload)
		expected[doc.ID] = canonical
	}
	legacy := parserAssetBundle{SchemaVersion: 1, Assets: []parserBundleAsset{}}
	changed := bundle
	changed.Assets = append([]parserBundleAsset(nil), bundle.Assets...)
	altered := false
	for i, asset := range bundle.Assets {
		if asset.AssetClass != "parser-packs" {
			legacy.Assets = append(legacy.Assets, asset)
			continue
		}
		if !bytes.Equal(expected[asset.AssetID], asset.Payload) {
			t.Fatalf("controller normalization changed exact reviewed runtime identity %s", asset.AssetID)
		}
		if !altered {
			changed.Assets[i].Payload = append([]byte(nil), asset.Payload...)
			changed.Assets[i].Payload = bytes.Replace(changed.Assets[i].Payload, []byte(`"version":"5.0.0"`), []byte(`"version":"5.0.1"`), 1)
			altered = true
		}
	}
	if !altered || isBuiltinEnrollmentBundle(changed) {
		t.Fatal("modified protected parser was trusted")
	}
	legacy.BundleHash, _, err = bundleDigest(legacy)
	if err != nil || !isBuiltinEnrollmentBundle(legacy) {
		t.Fatal("exact legacy configuration-only baseline lost compatibility")
	}
	revised := bundle
	revised.Assets = append([]parserBundleAsset(nil), bundle.Assets...)
	revised.Assets[0].Revision++
	if isBuiltinEnrollmentBundle(revised) {
		t.Fatal("user revision trusted as product baseline")
	}
	extra := bundle
	extra.Assets = append(append([]parserBundleAsset(nil), bundle.Assets...), parserBundleAsset{AssetClass: "parser-packs", AssetID: "site-addon", Revision: 1, Payload: json.RawMessage(`{}`)})
	if isBuiltinEnrollmentBundle(extra) {
		t.Fatal("site addon auto-trusted")
	}
	minimum := parserBundleMinimumKVRelease(bundle)
	if minimum != reviewedBaselineMinimumRelease {
		t.Fatalf("baseline minimum %s", minimum)
	}
	if parserClientSupportsKVRelease("22.19.1-0", minimum) || !parserClientSupportsKVRelease("23.0.0-1", minimum) {
		t.Fatal("old client protected identity gate failed")
	}
	code, next := parserSyncClientBlocker(&fleet.Node{Version: "22.19.1-0"}, minimum, false, nil)
	if code != "client_upgrade_required" || !strings.Contains(next, "23.0.0-1") {
		t.Fatal("old client lacks actionable upgrade reason")
	}
}
