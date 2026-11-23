package fleet_test

import (
	"nexora.local/nli-v20/internal/fleet"
	"os"
	"path/filepath"
	"testing"
)

func TestR9FeatureCapabilitiesPersistAndClone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.json")
	f := fleet.New(path)
	f.Register(&fleet.Node{ID: "client", Hostname: "client", Version: "23.0.0"})
	if err := f.UpdateFeatureCapabilities("client", "v23.0.0-9", []string{"log-policies-v1", "log-policies-v1"}); err != nil {
		t.Fatal(err)
	}
	reopened := fleet.New(path)
	node, ok := reopened.Get("client")
	if !ok || node.ReleaseID != "v23.0.0-9" || len(node.FeatureCapabilities) != 1 {
		t.Fatalf("capability lost on restart: %+v", node)
	}
	node.FeatureCapabilities[0] = "bad"
	cloned, _ := reopened.Get("client")
	if cloned.FeatureCapabilities[0] != "log-policies-v1" {
		t.Fatal("Get exposed mutable capability array")
	}
	all := reopened.All()
	all[0].FeatureCapabilities[0] = "bad"
	cloned, _ = reopened.Get("client")
	if cloned.FeatureCapabilities[0] != "log-policies-v1" {
		t.Fatal("All exposed mutable capability array")
	}
	if err := reopened.UpdateFeatureCapabilities("client", "v23.0.0-9", []string{"bad\ncap"}); err == nil {
		t.Fatal("unsafe capability accepted")
	}
	if err := reopened.UpdateFeatureCapabilities("client", "v23.0.0-8", nil); err != nil {
		t.Fatal(err)
	}
	downgraded, _ := fleet.New(path).Get("client")
	if len(downgraded.FeatureCapabilities) != 0 {
		t.Fatal("stale capability survived downgrade")
	}
}

func TestR9EnrollmentCapabilitiesAndTokenPersistAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.json")
	f := fleet.New(path)
	if err := f.RegisterEnrollment(fleet.Node{ID: "client", Hostname: "original", ReleaseID: "v23.0.0-8"}, "old-token"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path+".tmp", 0700); err != nil {
		t.Fatal(err)
	}
	newer := fleet.Node{ID: "client", Hostname: "replacement", ReleaseID: "v23.0.0-9", FeatureCapabilities: []string{"log-policies-v1"}}
	if err := f.RegisterEnrollment(newer, "new-token"); err == nil {
		t.Fatal("enrollment succeeded without durable credential/capability write")
	}
	node, _ := f.Get("client")
	disk, _ := fleet.New(path).Get("client")
	if node.ReleaseID != "v23.0.0-8" || len(node.FeatureCapabilities) != 0 || disk.ReleaseID != node.ReleaseID || !f.Authorize("client", "old-token") || f.Authorize("client", "new-token") {
		t.Fatalf("partial enrollment survived failure: %+v disk=%+v", node, disk)
	}
	if err := os.Remove(path + ".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := f.RegisterEnrollment(newer, "new-token"); err != nil {
		t.Fatal(err)
	}
	node, _ = fleet.New(path).Get("client")
	if node.Hostname != "original" || node.ReleaseID != "v23.0.0-9" || len(node.FeatureCapabilities) != 1 || !f.Authorize("client", "new-token") {
		t.Fatalf("atomic retry lost metadata or capability: %+v", node)
	}
	newer.ReleaseID = "v23.0.0-8"
	newer.FeatureCapabilities = nil
	if err := f.RegisterEnrollment(newer, "downgraded-token"); err != nil {
		t.Fatal(err)
	}
	node, _ = fleet.New(path).Get("client")
	if len(node.FeatureCapabilities) != 0 {
		t.Fatal("re-enrollment downgrade retained obsolete policy capability")
	}
}
