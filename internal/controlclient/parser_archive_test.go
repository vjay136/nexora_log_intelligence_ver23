package controlclient

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	parsercatalog "nexora.local/nli-v20/configs/catalog"
	parserassets "nexora.local/nli-v20/configs/parsers"
	"nexora.local/nli-v20/internal/canonicaljson"
	"nexora.local/nli-v20/internal/familyprofile"
	parserpolicy "nexora.local/nli-v20/parser-policy"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestClientRetainsPriorParserEvidenceAcrossDeletion(t *testing.T) {
	root := t.TempDir()
	client, err := New(Config{ControllerURL: "http://127.0.0.1:12345", AllowInsecureHTTP: true, NodeTokenFile: filepath.Join(root, "node.token"), InstallIDFile: filepath.Join(root, "install.id"), JournalFile: filepath.Join(root, "journal.json"), AgentConfigPath: filepath.Join(root, "agent.json"), ParserDir: filepath.Join(root, "parsers"), AssetDir: filepath.Join(root, "parser-assets"), PackageSpoolDir: filepath.Join(root, "spool"), PollSeconds: 5}, &fakeExecutor{})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := canonicaljson.Normalize([]byte(`{"config":{"pattern":"^customer$"},"name":"customer"}`))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	prior := synchronizedAssetBundle{SchemaVersion: 1, Assets: []synchronizedAsset{{AssetClass: "regex-patterns", AssetID: "customer", Name: "customer", Revision: 3, SHA256: fmt.Sprintf("%x", digest), Payload: payload}}}
	prior.BundleHash, err = synchronizedBundleHash(prior)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := json.Marshal(prior)
	if _, err := client.applyAssetBundle(context.Background(), original); err != nil {
		t.Fatal(err)
	}
	empty := synchronizedAssetBundle{SchemaVersion: 1, Assets: []synchronizedAsset{}}
	empty.BundleHash, err = synchronizedBundleHash(empty)
	if err != nil {
		t.Fatal(err)
	}
	next, _ := json.Marshal(empty)
	if _, err := client.applyAssetBundle(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "parser-assets-history", prior.BundleHash+".json")
	archived, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if hash, err := verifyArchivedClientBundle(archived); err != nil || hash != prior.BundleHash {
		t.Fatalf("archive %s %v", hash, err)
	}
	if _, err := os.Stat(filepath.Join(client.cfg.AssetDir, "regex", "customer.json")); !os.IsNotExist(err) {
		t.Fatal("approved deletion did not remove live asset")
	}
	if err := os.WriteFile(archive, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := client.applyAssetBundle(context.Background(), original); err == nil {
		t.Fatal("failed archive did not prevent asset swap")
	}
	actual, _ := os.ReadFile(filepath.Join(client.cfg.AssetDir, "bundle.json"))
	if string(actual) != string(next) {
		t.Fatal("archive failure changed live generation")
	}
}

func TestClientAppliesCompleteReviewedBaselineWithRPMAuditCopies(t *testing.T) {
	root := t.TempDir()
	parserDir := filepath.Join(root, "parsers")
	if err := os.Mkdir(parserDir, 0750); err != nil {
		t.Fatal(err)
	}
	assets, err := parserassets.All()
	if err != nil {
		t.Fatal(err)
	}
	bundle := synchronizedAssetBundle{SchemaVersion: 1, Assets: []synchronizedAsset{}}
	for _, asset := range assets {
		if err := os.WriteFile(filepath.Join(parserDir, asset.Name), asset.Data, 0640); err != nil {
			t.Fatal(err)
		}
		pack, err := parserpolicy.LoadParserPackBytes(asset.Data)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := canonicaljson.Normalize(asset.Data)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(payload)
		bundle.Assets = append(bundle.Assets, synchronizedAsset{AssetClass: "parser-packs", AssetID: pack.ID, Name: pack.ID, Revision: 1, SHA256: fmt.Sprintf("%x", digest), Payload: payload})
	}
	configs, err := parsercatalog.Assets()
	if err != nil {
		t.Fatal(err)
	}
	collections := map[string]string{"kv": "kv-config", "regex": "regex-patterns", "known-keys": "known-keys", "static-patterns": "static-patterns", "templates": "templates", "projections": "projections", "semantic-extraction": "semantic-extraction"}
	for _, asset := range configs {
		data, err := json.Marshal(map[string]any{"name": asset.Name, "config": asset.Config, "review_state": "active", "approved_by": "nli-v21-release", "published_by": "nli-v21-release"})
		if err != nil {
			t.Fatal(err)
		}
		payload, err := canonicaljson.Normalize(data)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(payload)
		bundle.Assets = append(bundle.Assets, synchronizedAsset{AssetClass: collections[asset.Collection], AssetID: asset.ID, Name: asset.Name, Revision: 1, SHA256: fmt.Sprintf("%x", digest), Payload: payload})
	}
	sort.Slice(bundle.Assets, func(i, j int) bool {
		a, b := bundle.Assets[i], bundle.Assets[j]
		if a.AssetClass == b.AssetClass {
			return a.AssetID < b.AssetID
		}
		return a.AssetClass < b.AssetClass
	})
	bundle.BundleHash, err = synchronizedBundleHash(bundle)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(bundle)
	transport, err := canonicaljson.Normalize(data)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(Config{ControllerURL: "http://127.0.0.1:12345", AllowInsecureHTTP: true, NodeTokenFile: filepath.Join(root, "node.token"), InstallIDFile: filepath.Join(root, "install.id"), JournalFile: filepath.Join(root, "journal.json"), AgentConfigPath: filepath.Join(root, "agent.json"), ParserDir: parserDir, AssetDir: filepath.Join(root, "parser-assets"), PackageSpoolDir: filepath.Join(root, "spool"), PollSeconds: 5}, &fakeExecutor{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.applyAssetBundle(context.Background(), transport); err != nil {
		t.Fatal(err)
	}
	profiles, err := familyprofile.Resolve(parserDir)
	if err != nil || len(profiles) != len(assets) {
		t.Fatalf("reviewed runtime duplicates or failed: %d %v", len(profiles), err)
	}
	stored, err := os.ReadFile(filepath.Join(client.cfg.AssetDir, "bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := verifyArchivedClientBundle(stored)
	if err != nil || hash != bundle.BundleHash {
		t.Fatal("client/controller canonical bundle identity changed")
	}
	for _, asset := range assets {
		original, err := os.ReadFile(filepath.Join(parserDir, asset.Name))
		if err != nil || string(original) != string(asset.Data) {
			t.Fatal("synchronization altered RPM reviewed audit copy")
		}
	}
}
