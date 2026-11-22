package controlclient

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestParserAssetBundleKeepsAgentReadAccessUnderBootstrapUmask(t *testing.T) {
	// The client setup script sets this umask before the initial --once cycle.
	// This test must remain sequential because Linux umask applies process-wide.
	previous := syscall.Umask(0o077)
	defer syscall.Umask(previous)

	root := t.TempDir()
	client := &Client{
		cfg:      Config{AssetDir: filepath.Join(root, "parser-assets"), ParserDir: filepath.Join(root, "parsers")},
		executor: &fakeExecutor{},
	}
	payload := json.RawMessage(`{"config":{"keys":["fixture_key"]}}`)
	digest := sha256.Sum256(payload)
	bundle := synchronizedAssetBundle{SchemaVersion: 1, Assets: []synchronizedAsset{{
		AssetClass: "known-keys", AssetID: "fixture", Name: "Synthetic known keys", Revision: 1,
		SHA256: fmt.Sprintf("%x", digest), Payload: payload,
	}}}
	var err error
	bundle.BundleHash, err = synchronizedBundleHash(bundle)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.applyAssetBundle(context.Background(), encoded); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		path string
		mode os.FileMode
	}{
		{client.cfg.AssetDir, 0o750},
		{filepath.Join(client.cfg.AssetDir, "known-keys"), 0o750},
		{filepath.Join(client.cfg.AssetDir, "known-keys", "fixture.json"), 0o640},
		{filepath.Join(client.cfg.AssetDir, "bundle.json"), 0o640},
	} {
		info, err := os.Stat(check.path)
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != check.mode {
			t.Errorf("%s mode = %04o, want %04o", check.path, mode, check.mode)
		}
	}
}
