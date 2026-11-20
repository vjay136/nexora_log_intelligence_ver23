package parserarchive

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"nexora.local/nli-v20/internal/canonicaljson"
	"os"
	"path/filepath"
	"testing"
)

func verifyFixture(data []byte) (string, error) {
	var item struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &item); err != nil {
		return "", err
	}
	canonical, err := canonicaljson.Normalize(data)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return fmt.Sprintf("%x", sum), nil
}

func TestPriorParserEvidenceIsBoundedAndPrivate(t *testing.T) {
	root := t.TempDir()
	assets := filepath.Join(root, "parser-assets")
	if err := os.Mkdir(assets, 0700); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 13; i++ {
		data := []byte(fmt.Sprintf("{ \"version\" : %d }", i))
		if err := os.WriteFile(filepath.Join(assets, "bundle.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := BeforeReplace(assets, verifyFixture); err != nil {
			t.Fatal(err)
		}
	}
	history := filepath.Join(root, "parser-assets-history")
	entries, err := os.ReadDir(history)
	if err != nil || len(entries) != MaxGenerations {
		t.Fatalf("archivecount%d %v", len(entries), err)
	}
	for _, entry := range entries {
		path := filepath.Join(history, entry.Name())
		data, err := Read(path)
		if err != nil {
			t.Fatal(err)
		}
		canonical, _ := canonicaljson.Normalize(data)
		if string(data) != string(canonical) {
			t.Fatal("archive not canonical")
		}
		info, _ := os.Stat(path)
		if os.PathSeparator == '/' && info.Mode().Perm() != 0600 {
			t.Fatal("archive permissions expose data")
		}
	}
	if err := BeforeReplace(assets, verifyFixture); err != nil {
		t.Fatal(err)
	}
	entries, _ = os.ReadDir(history)
	if len(entries) != MaxGenerations {
		t.Fatal("repeated generation duplicated history")
	}
}

func TestArchiveFailureDoesNotTouchLiveEvidence(t *testing.T) {
	root := t.TempDir()
	assets := filepath.Join(root, "parser-assets")
	_ = os.Mkdir(assets, 0700)
	live := filepath.Join(assets, "bundle.json")
	original := []byte(`{"version":1}`)
	_ = os.WriteFile(live, original, 0600)
	_ = os.WriteFile(filepath.Join(root, "parser-assets-history"), []byte("blocked"), 0600)
	if err := BeforeReplace(assets, verifyFixture); err == nil {
		t.Fatal("write failure was hidden")
	}
	actual, _ := os.ReadFile(live)
	if string(actual) != string(original) {
		t.Fatal("live evidence modified on failure")
	}
}
