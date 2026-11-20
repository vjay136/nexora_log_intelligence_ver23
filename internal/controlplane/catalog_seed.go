package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	parsercatalog "nexora.local/nli-v20/configs/catalog"
	parserassets "nexora.local/nli-v20/configs/parsers"
	"nexora.local/nli-v20/internal/canonicaljson"
	"nexora.local/nli-v20/internal/familyprofile"
	metastore "nexora.local/nli-v20/internal/store"
)

var catalogCollections = map[string]string{
	"kv": "kv-config", "regex": "regex-patterns", "known-keys": "known-keys",
	"static-patterns": "static-patterns", "templates": "templates", "projections": "projections",
	"semantic-extraction": "semantic-extraction",
}

func builtinCatalogPayload(asset parsercatalog.Asset) ([]byte, error) {
	return json.Marshal(map[string]any{
		"name": asset.Name, "config": asset.Config,
		"review_state": "active", "approved_by": "nli-v21-release",
		"published_by": "nli-v21-release",
	})
}

// Only the original release assets may be delivered on enrollment without
// a new operator approval. Compare their content against the binary, since
// catalog IDs and approval labels alone do not establish provenance.
func isBuiltinEnrollmentBundle(bundle parserAssetBundle) bool {
	embedded, err := parsercatalog.Assets()
	if err != nil {
		return false
	}
	packs, err := reviewedBuiltinDocuments(context.Background())
	if err != nil || (len(bundle.Assets) != len(embedded) && len(bundle.Assets) != len(embedded)+len(packs)) {
		return false
	}
	type assetKey struct{ collection, id string }
	byKey := make(map[assetKey]parserBundleAsset, len(bundle.Assets))
	for _, asset := range bundle.Assets {
		if _, duplicate := byKey[assetKey{asset.AssetClass, asset.AssetID}]; duplicate {
			return false
		}
		byKey[assetKey{asset.AssetClass, asset.AssetID}] = asset
	}
	for _, asset := range embedded {
		published := byKey[assetKey{catalogCollections[asset.Collection], asset.ID}]
		if published.Revision != 1 {
			return false
		}
		payload, err := builtinCatalogPayload(asset)
		if err != nil {
			return false
		}
		canonicalPayload, err := canonicaljson.Normalize(payload)
		if err != nil || !bytes.Equal(canonicalPayload, published.Payload) {
			return false
		}
	}
	// Keep the exact legacy configuration-only baseline valid for existing
	// generations. An expanded baseline must contain every reviewed product pack.
	if len(bundle.Assets) == len(embedded) {
		return true
	}
	for _, doc := range packs {
		published, ok := byKey[assetKey{"parser-packs", doc.ID}]
		if !ok || published.Revision != 1 {
			return false
		}
		_, runtime, err := runtimeParserPackForDocument(doc)
		if err != nil {
			return false
		}
		expected, err := canonicaljson.Normalize(runtime)
		if err != nil || !bytes.Equal(expected, published.Payload) {
			return false
		}
	}
	return true
}

func seedBuiltinCatalog(ctx context.Context, store metastore.Store) error {
	assets, err := parsercatalog.Assets()
	if err != nil {
		return err
	}
	for _, asset := range assets {
		collection, ok := catalogCollections[asset.Collection]
		if !ok || safeID(asset.ID) == "" || asset.Name == "" || len(asset.Config) == 0 {
			return errors.New("embedded parser catalog has an invalid asset")
		}
		exists, err := builtinAlreadyRecorded(ctx, store, collection, asset.ID)
		if err != nil {
			return err
		}
		if exists {
			continue // Preserve user revisions and edits across restarts.
		}
		payload, err := builtinCatalogPayload(asset)
		if err != nil {
			return err
		}
		// The embedded catalog is part of the tested, signed release. Treat it as
		// pre-approved so a fresh controller immediately has a deployable baseline.
		if _, err := store.Put(ctx, metastore.Document{Collection: collection, ID: asset.ID, State: "active", Payload: payload, CreatedBy: "nli-v21-release"}); err != nil {
			return err
		}
	}
	packs, err := reviewedBuiltinDocuments(ctx)
	if err != nil {
		return err
	}
	for _, doc := range packs {
		exists, err := builtinAlreadyRecorded(ctx, store, doc.Collection, doc.ID)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		if _, err := store.Put(ctx, doc); err != nil {
			return err
		}
	}
	return nil
}

func builtinAlreadyRecorded(ctx context.Context, store metastore.Store, collection, id string) (bool, error) {
	for _, revision := range []int{0, 1} {
		if _, err := store.Get(ctx, collection, id, revision); err == nil {
			return true, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("cannot verify existing catalog %s/%s; refusing to seed: %w", collection, id, err)
		}
	}
	// A normal soft deletion hides latest revision but retains revision one.
	// Such history means the operator intentionally retired this release asset.
	return false, nil
}

func reviewedBuiltinDocuments(ctx context.Context) ([]metastore.Document, error) {
	assets, err := parserassets.All()
	if err != nil {
		return nil, err
	}
	documents := make([]metastore.Document, 0, len(assets))
	for _, asset := range assets {
		pack, err := familyprofile.ValidatePublishedPackBytesContext(ctx, asset.Name, asset.Data)
		if err != nil {
			return nil, fmt.Errorf("reviewed release parser %s failed validation: %w", asset.Name, err)
		}
		documents = append(documents, metastore.Document{Collection: "parser-packs", ID: pack.ID, Revision: 1, State: "published", Payload: append(json.RawMessage(nil), asset.Data...), CreatedBy: pack.Author})
	}
	return documents, nil
}
