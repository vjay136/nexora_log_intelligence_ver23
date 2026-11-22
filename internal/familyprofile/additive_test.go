package familyprofile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	parserassets "nexora.local/nli-v20/configs/parsers"
)

func TestShippedParserFilesDoNotDuplicateEmbeddedProfiles(t *testing.T) {
	builtins := mustBuiltins(t)
	assets, err := parserassets.All()
	if err != nil {
		t.Fatal(err)
	}
	installed := t.TempDir()
	for _, asset := range assets {
		if err := os.WriteFile(filepath.Join(installed, asset.Name), asset.Data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	resolved, diagnostics, err := ResolveResilient(installed)
	if err != nil || len(diagnostics) != 0 || len(resolved) != len(builtins) {
		t.Fatalf("shipped files were not reconciled: profiles=%d diagnostics=%+v err=%v", len(resolved), diagnostics, err)
	}
	for _, embedded := range builtins {
		profile := findProfile(t, resolved, embedded.Pack.ID)
		if profile.Managed || profile.Pack.SHA256 != embedded.Pack.SHA256 {
			t.Errorf("shipped file displaced embedded parser %q", embedded.Pack.ID)
		}
	}
	if _, err := Resolve(installed); err != nil {
		t.Fatalf("strict loading rejected the shipped files: %v", err)
	}
}

func TestAddOnCannotReplaceProtectedBuiltinIdentity(t *testing.T) {
	builtins := mustBuiltins(t)
	original := findProfile(t, builtins, "nli_reviewed_imap")
	pack := clonePack(t, original.Pack)
	pack.Author = "new-add-on"
	directory := t.TempDir()
	sealAndWrite(t, directory, pack)
	profiles, diagnostics, err := ResolveResilient(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != len(builtins) || len(diagnostics) != 1 || !strings.Contains(diagnostics[0].Reason, "protected built-in") {
		t.Fatalf("conflicting addon not isolated: %+v %+v", profiles, diagnostics)
	}
	preserved := findProfile(t, profiles, original.Pack.ID)
	if preserved.Managed || preserved.Pack.SHA256 != original.Pack.SHA256 {
		t.Fatal("new pack displaced existing built-in")
	}
	if _, err = Resolve(directory); err == nil {
		t.Fatal("strict generation accepted builtin replacement")
	}
	encoded, _ := json.Marshal(pack)
	if _, err = CompileManagedPayload("conflicting", encoded); err == nil {
		t.Fatal("controller memory generation accepted builtin replacement")
	}
}
