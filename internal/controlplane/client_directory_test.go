package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"nexora.local/nli-v20/internal/fleet"
	metastore "nexora.local/nli-v20/internal/store"
)

func directoryRequest(t *testing.T, f *apiFixture, method, path string, body any, want int) []byte {
	t.Helper()
	res, data := f.request(method, clientDirectoryRoute+path, body)
	if res.StatusCode != want {
		t.Fatalf("%s %s: %d want %d: %s", method, path, res.StatusCode, want, data)
	}
	return data
}

func directoryNode(f *apiFixture, id string) {
	f.server.fleet.Register(&fleet.Node{ID: id, Hostname: "host-" + id, Version: "23.0.0", TokenHash: "not-for-the-browser"})
}

func TestClientDirectoryNamesGroupsAndRevisionedRestart(t *testing.T) {
	f := newAPIFixture(t)
	directoryNode(f, "node-a")
	directoryNode(f, "node-b")
	directoryRequest(t, f, http.MethodPut, "/nodes/node-a", map[string]any{"display_name": "Finance collector", "expected_revision": 0}, http.StatusOK)
	directoryRequest(t, f, http.MethodPut, "/groups/payroll", map[string]any{"name": "Payroll nodes", "node_ids": []string{"node-b", "node-a", "node-a"}, "expected_revision": 0}, http.StatusOK)
	data := directoryRequest(t, f, http.MethodGet, "", nil, http.StatusOK)
	var view clientDirectoryView
	if err := json.Unmarshal(data, &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Nodes) != 2 || view.Nodes[0].NodeID != "node-a" || view.Nodes[0].DisplayName != "Finance collector" || view.Nodes[0].LabelRevision != 1 || len(view.Nodes[0].Groups) != 1 || len(view.Groups[0].NodeIDs) != 2 {
		t.Fatalf("wrong directory: %s", data)
	}
	directoryRequest(t, f, http.MethodPut, "/nodes/node-a", map[string]any{"display_name": "stale overwrite", "expected_revision": 0}, http.StatusConflict)
	directoryRequest(t, f, http.MethodPut, "/nodes", map[string]any{"labels": []map[string]any{
		{"node_id": "node-a", "display_name": "Finance primary", "expected_revision": 1},
		{"node_id": "node-b", "display_name": "Finance secondary", "expected_revision": 0},
	}}, http.StatusOK)
	// Reject the entire batch before the single immutable snapshot write.
	directoryRequest(t, f, http.MethodPut, "/nodes", map[string]any{"labels": []map[string]any{
		{"node_id": "node-a", "display_name": "must not save", "expected_revision": 2},
		{"node_id": "missing", "display_name": "not enrolled", "expected_revision": 0},
	}}, http.StatusNotFound)
	current, err := f.server.readClientDirectoryLabels(context.Background())
	if err != nil || current.Nodes["node-a"].DisplayName != "Finance primary" || current.Nodes["node-b"].Revision != 1 {
		t.Fatalf("batch not atomic: %+v %v", current, err)
	}
	prior, err := f.server.metadata.Get(context.Background(), clientDirectoryLabelsCollection, clientDirectoryLabelsID, 1)
	if err != nil || !bytes.Contains(prior.Payload, []byte("Finance collector")) {
		t.Fatalf("display-name history lost: %+v %v", prior, err)
	}
	for _, route := range []string{"/api/v1/fleet", "/api/v1/fleet/sync", "/api/v1/fleet/node-a"} {
		response, body := f.request(http.MethodGet, route, nil)
		if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"display_name":"Finance primary"`)) || !bytes.Contains(body, []byte("Payroll nodes")) || bytes.Contains(body, []byte("not-for-the-browser")) {
			t.Fatalf("directory projection %s: %d %s", route, response.StatusCode, body)
		}
	}
	actual, _ := f.server.fleet.Get("node-a")
	if actual.ID != "node-a" || actual.Hostname != "host-node-a" {
		t.Fatalf("display alias changed node identity: %+v", actual)
	}
	// Re-open the durable metadata and fleet registries without directory state
	// from the running controller. No process-local alias map is authoritative.
	reopened, err := metastore.Open(metastore.Config{Provider: "local", LocalDir: f.server.cfg.StorageDir})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restarted := &Server{metadata: reopened, fleet: fleet.New(filepath.Join(f.state, "fleet.json"))}
	after, err := restarted.clientDirectoryView(context.Background())
	if err != nil || len(after.Nodes) != 2 || after.Nodes[0].DisplayName != "Finance primary" || after.Groups[0].Name != "Payroll nodes" {
		t.Fatalf("restart lost directory: %+v %v", after, err)
	}
	directoryRequest(t, f, http.MethodDelete, "/groups/payroll", map[string]any{"expected_revision": 0}, http.StatusConflict)
	directoryRequest(t, f, http.MethodDelete, "/groups/payroll", map[string]any{"expected_revision": 1}, http.StatusOK)
	data = directoryRequest(t, f, http.MethodGet, "", nil, http.StatusOK)
	if json.Unmarshal(data, &view) != nil || len(view.Groups) != 0 || len(view.Nodes[0].Groups) != 0 {
		t.Fatalf("removed group still active: %s", data)
	}
	if _, err := f.server.metadata.Get(context.Background(), clientDirectoryGroupsCollection, "payroll", 1); err != nil {
		t.Fatal("group removal destroyed prior revision", err)
	}
	directoryRequest(t, f, http.MethodPut, "/nodes/node-a", map[string]any{"display_name": "", "expected_revision": 2}, http.StatusOK)
	current, err = f.server.readClientDirectoryLabels(context.Background())
	if err != nil || current.Nodes["node-a"].DisplayName != "" || current.Nodes["node-a"].Revision != 3 {
		t.Fatal("display-name reset did not preserve revision history", current, err)
	}
}

func TestClientDirectoryGroupThousandClientsAndFrozenRolloutTargets(t *testing.T) {
	f := newAPIFixture(t)
	ids := make([]string, 1005)
	labels := make([]map[string]any, 1005)
	for index := range ids {
		ids[index] = fmt.Sprintf("directory-%04d", index)
		directoryNode(f, ids[index])
		labels[index] = map[string]any{"node_id": ids[index], "display_name": fmt.Sprintf("Collector %04d", index), "expected_revision": 0}
	}
	directoryRequest(t, f, http.MethodPut, "/nodes", map[string]any{"labels": labels}, http.StatusOK)
	directoryRequest(t, f, http.MethodPut, "/groups/regional", map[string]any{"name": "Regional collectors", "node_ids": ids, "expected_revision": 0}, http.StatusOK)
	data := directoryRequest(t, f, http.MethodGet, "", nil, http.StatusOK)
	var view clientDirectoryView
	if json.Unmarshal(data, &view) != nil || len(view.Nodes) != 1005 || len(view.Groups) != 1 || len(view.Groups[0].NodeIDs) != 1005 || view.Nodes[1004].DisplayName != "Collector 1004" {
		t.Fatalf("large directory truncated: %s", data)
	}
	response, fleetBody := f.request(http.MethodGet, "/api/v1/fleet/sync", nil)
	var fleetView struct {
		Nodes []struct {
			Node struct {
				ID          string `json:"id"`
				DisplayName string `json:"display_name"`
			} `json:"node"`
		} `json:"nodes"`
	}
	if response.StatusCode != http.StatusOK || json.Unmarshal(fleetBody, &fleetView) != nil || len(fleetView.Nodes) != 1005 {
		t.Fatalf("large fleet projection truncated: %d", response.StatusCode)
	}
	for _, item := range fleetView.Nodes {
		if item.Node.DisplayName == "" {
			t.Fatalf("client %s lost its display name in shared fleet projection", item.Node.ID)
		}
	}
	resolved := directoryRequest(t, f, http.MethodPost, "/resolve-targets", map[string]any{"group_ids": []string{"regional"}, "node_ids": []string{ids[0]}}, http.StatusOK)
	var targets clientDirectoryTargets
	if json.Unmarshal(resolved, &targets) != nil || targets.Count != 1005 || targets.NodeIDs[1004] != ids[1004] {
		t.Fatalf("large group target resolution: %s", resolved)
	}
	response, body := f.request(http.MethodPost, "/api/v1/rollouts", map[string]any{"name": "Restart regional agents", "type": "restart", "target_group_ids": []string{"regional"}, "expected_group_revisions": map[string]int{"regional": 1}, "payload": map[string]any{}})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("group proposal %d: %s", response.StatusCode, body)
	}
	proposalID, _ := decodeMap(t, body)["id"].(string)
	doc, err := f.server.metadata.Get(context.Background(), "rollout-proposals", proposalID, 0)
	if err != nil {
		t.Fatal(err)
	}
	var proposal map[string]any
	if json.Unmarshal(doc.Payload, &proposal) != nil || doc.State != "pending_approval" || len(interfaceStrings(proposal["target_nodes"])) != 1005 || proposal["target_group_ids"] != nil {
		t.Fatalf("group proposal did not freeze exact identities: %s", doc.Payload)
	}
	directoryRequest(t, f, http.MethodPut, "/groups/regional", map[string]any{"name": "Smaller regional group", "node_ids": ids[:2], "expected_revision": 1}, http.StatusOK)
	directoryRequest(t, f, http.MethodPost, "/resolve-targets", map[string]any{"group_ids": []string{"regional"}, "expected_groups": map[string]int{"regional": 1}}, http.StatusConflict)
	unchanged, err := f.server.metadata.Get(context.Background(), "rollout-proposals", proposalID, 0)
	if err != nil || unchanged.Hash != doc.Hash || !bytes.Equal(unchanged.Payload, doc.Payload) {
		t.Fatalf("group edit retargeted pending rollout: %+v %v", unchanged, err)
	}
	if len(f.server.rollouts.List()) != 0 {
		t.Fatal("creating a group or proposal executed an unapproved action")
	}
	response, body = f.request(http.MethodPost, "/api/v1/rollouts", map[string]any{"name": "Stale regional preview", "type": "restart", "target_group_ids": []string{"regional"}, "expected_group_revisions": map[string]int{"regional": 1}, "payload": map[string]any{}})
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("stale group preview created a rollout %d: %s", response.StatusCode, body)
	}
	loginParserSyncApprover(t, f)
	response, body = f.request(http.MethodPost, "/api/v1/rollouts/"+proposalID+"/approve", map[string]any{"reason": "Independent regional group target review"})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("approve frozen group targets %d: %s", response.StatusCode, body)
	}
	live := f.server.rollouts.List()
	if len(live) != 1 || len(live[0].TargetNodes) != 1005 || live[0].TargetNodes[1004] != ids[1004] {
		t.Fatalf("approved group rollout re-read changed membership: %+v", live)
	}
}

type clientDirectoryFailingStore struct {
	metastore.Store
	failPut bool
}

func (s clientDirectoryFailingStore) Get(ctx context.Context, collection, id string, rev int) (metastore.Document, error) {
	if !s.failPut && collection == clientDirectoryLabelsCollection {
		return metastore.Document{}, errors.New("directory offline")
	}
	return s.Store.Get(ctx, collection, id, rev)
}
func (s clientDirectoryFailingStore) Put(ctx context.Context, doc metastore.Document) (metastore.Document, error) {
	if s.failPut && doc.Collection == clientDirectoryLabelsCollection {
		return metastore.Document{}, errors.New("directory write failed")
	}
	return s.Store.Put(ctx, doc)
}

func TestClientDirectoryFailurePreservesFleetAndAtomicStoredNames(t *testing.T) {
	f := newAPIFixture(t)
	directoryNode(f, "stable")
	directoryRequest(t, f, http.MethodPut, "/nodes/stable", map[string]any{"display_name": "Stored name", "expected_revision": 0}, http.StatusOK)
	storage := f.server.metadata
	f.server.metadata = clientDirectoryFailingStore{Store: storage, failPut: true}
	directoryRequest(t, f, http.MethodPut, "/nodes/stable", map[string]any{"display_name": "must not replace stored name", "expected_revision": 1}, http.StatusServiceUnavailable)
	f.server.metadata = clientDirectoryFailingStore{Store: storage}
	directoryRequest(t, f, http.MethodGet, "", nil, http.StatusServiceUnavailable)
	for _, route := range []string{"/api/v1/fleet", "/api/v1/fleet/sync"} {
		response, body := f.request(http.MethodGet, route, nil)
		if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte("host-stable")) || !bytes.Contains(body, []byte(`"directory_status":"unavailable"`)) {
			t.Fatalf("optional directory failure hid fleet %s %d: %s", route, response.StatusCode, body)
		}
	}
	f.server.metadata = storage
	data := directoryRequest(t, f, http.MethodGet, "", nil, http.StatusOK)
	if !bytes.Contains(data, []byte("Stored name")) || bytes.Contains(data, []byte("must not replace")) {
		t.Fatalf("failed write overwrote names: %s", data)
	}
}

func TestClientDirectoryPermissionsBoundsAndUnknownIdentities(t *testing.T) {
	f := newAPIFixture(t)
	directoryNode(f, "one")
	directoryRequest(t, f, http.MethodPut, "/nodes/missing", map[string]any{"display_name": "Unknown", "expected_revision": 0}, http.StatusNotFound)
	directoryRequest(t, f, http.MethodPut, "/nodes/one", map[string]any{"node_id": "different", "display_name": "Identity mutation", "expected_revision": 0}, http.StatusBadRequest)
	directoryRequest(t, f, http.MethodPut, "/nodes/one", map[string]any{"display_name": "missing revision"}, http.StatusBadRequest)
	directoryRequest(t, f, http.MethodPut, "/nodes/one", map[string]any{"display_name": strings.Repeat("x", 161), "expected_revision": 0}, http.StatusBadRequest)
	directoryRequest(t, f, http.MethodPut, "/groups/empty", map[string]any{"name": "Empty group", "node_ids": []string{}, "expected_revision": 0}, http.StatusBadRequest)
	directoryRequest(t, f, http.MethodPut, "/groups/unknown", map[string]any{"name": "Unknown group", "node_ids": []string{"missing"}, "expected_revision": 0}, http.StatusBadRequest)
	directoryRequest(t, f, http.MethodPut, "/groups/too-many", map[string]any{"name": "Too many", "node_ids": make([]string, 10001), "expected_revision": 0}, http.StatusBadRequest)
	directoryRequest(t, f, http.MethodPost, "/resolve-targets", map[string]any{"group_ids": []string{"missing"}}, http.StatusConflict)
	if _, err := f.server.auth.CreateUser("admin", "directory-viewer", "viewer@example.test", "viewer", "Viewer-password-12345!"); err != nil {
		t.Fatal(err)
	}
	f.login("directory-viewer", "Viewer-password-12345!")
	f.refreshCSRF()
	directoryRequest(t, f, http.MethodGet, "", nil, http.StatusOK)
	directoryRequest(t, f, http.MethodPut, "/nodes/one", map[string]any{"display_name": "Not allowed", "expected_revision": 0}, http.StatusForbidden)
	directoryRequest(t, f, http.MethodPut, "/groups/no-access", map[string]any{"name": "Not allowed", "node_ids": []string{"one"}, "expected_revision": 0}, http.StatusForbidden)
	directoryRequest(t, f, http.MethodPost, "/resolve-targets", map[string]any{"node_ids": []string{"one"}}, http.StatusForbidden)
	response, err := http.Get(f.http.URL + clientDirectoryRoute)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous directory read status=%d", response.StatusCode)
	}
}
