package familyprofile

import (
	"context"
	"encoding/json"
	parserassets "nexora.local/nli-v20/configs/parsers"
	parserpolicy "nexora.local/nli-v20/parser-policy"
	"os"
	"path/filepath"
	"testing"
)

func TestReviewedPublishedPackRequiresExactEmbeddedContent(t *testing.T) {
	assets, err := parserassets.All()
	if err != nil {
		t.Fatal(err)
	}
	for _, asset := range assets {
		if _, err := ValidatePublishedPackBytesContext(context.Background(), asset.Name, asset.Data); err != nil {
			t.Fatalf("shipped pack rejected: %s %v", asset.Name, err)
		}
	}
	pack, err := parserpolicy.LoadParserPackBytes(assets[0].Data)
	if err != nil {
		t.Fatal(err)
	}
	pack.Rules[0].Name = "same protected ID with site edits"
	if err := parserpolicy.SealParserPack(pack); err != nil {
		t.Fatal(err)
	}
	modified, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parserpolicy.LoadParserPackBytes(modified); err != nil {
		t.Fatal("test mutation must retain a valid seal")
	}
	if _, err := ValidatePublishedPackBytesContext(context.Background(), pack.ID, modified); err == nil {
		t.Fatal("resealed site edits impersonated reviewed product parser")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, pack.ID+".json"), modified, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(dir); err == nil {
		t.Fatal("modified protected ID replaced embedded runtime")
	}
}
