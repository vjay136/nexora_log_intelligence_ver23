package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"nexora.local/nli-v20/internal/fleet"
	"nexora.local/nli-v20/internal/middleware"
	metastore "nexora.local/nli-v20/internal/store"
)

const (
	clientDirectoryRoute            = "/api/v1/client-directory"
	clientDirectoryMaxNodes         = 10000
	clientDirectoryMaxGroups        = 1000
	clientDirectoryMaxNameBytes     = 160
	clientDirectoryMaxLabelBatch    = 4096
	clientDirectoryMaxLabelBytes    = 3 << 20
	clientDirectoryMaxMemberships   = 50000
	clientDirectoryLabelsCollection = "client-directory"
	clientDirectoryLabelsID         = "node-labels"
	clientDirectoryGroupsCollection = "client-groups"
)

var clientDirectoryIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type clientDirectoryLabel struct {
	DisplayName string `json:"display_name"`
	Revision    int    `json:"revision"`
}

type clientDirectoryLabels struct {
	SchemaVersion int                             `json:"schema_version"`
	Nodes         map[string]clientDirectoryLabel `json:"nodes"`
}

type clientDirectoryGroup struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	NodeIDs  []string `json:"node_ids"`
	Revision int      `json:"revision"`
}

type clientDirectoryGroupRef struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Revision int    `json:"revision"`
}

type clientDirectoryNode struct {
	NodeID        string                    `json:"node_id"`
	DisplayName   string                    `json:"display_name"`
	LabelRevision int                       `json:"label_revision"`
	Groups        []clientDirectoryGroupRef `json:"groups"`
}

type clientDirectoryView struct {
	SchemaVersion int                    `json:"schema_version"`
	Nodes         []clientDirectoryNode  `json:"nodes"`
	Groups        []clientDirectoryGroup `json:"groups"`
	Limits        map[string]int         `json:"limits"`
}

// The directory is control-plane display metadata. It never changes a node's
// identity, hostname, authentication, parser configuration or emitted JSON.
func (s *Server) readClientDirectoryLabels(ctx context.Context) (clientDirectoryLabels, error) {
	labels := clientDirectoryLabels{SchemaVersion: 1, Nodes: map[string]clientDirectoryLabel{}}
	doc, err := s.metadata.Get(ctx, clientDirectoryLabelsCollection, clientDirectoryLabelsID, 0)
	if errors.Is(err, os.ErrNotExist) {
		return labels, nil
	}
	if err != nil {
		return labels, err
	}
	if json.Unmarshal(doc.Payload, &labels) != nil || labels.SchemaVersion != 1 || labels.Nodes == nil || len(labels.Nodes) > clientDirectoryMaxNodes {
		return labels, errors.New("client display-name metadata is invalid")
	}
	return labels, nil
}

func (s *Server) readClientDirectoryGroups(ctx context.Context) ([]clientDirectoryGroup, error) {
	docs, err := s.listParserSyncDocuments(ctx, clientDirectoryGroupsCollection, "active", clientDirectoryMaxGroups)
	if err != nil {
		return nil, err
	}
	groups := make([]clientDirectoryGroup, 0, len(docs))
	memberships := 0
	for _, doc := range docs {
		var group clientDirectoryGroup
		if json.Unmarshal(doc.Payload, &group) != nil || group.ID != doc.ID || !validClientDirectoryName(group.Name, false) || len(group.NodeIDs) == 0 || len(group.NodeIDs) > clientDirectoryMaxNodes {
			return nil, errors.New("client group metadata is invalid")
		}
		memberships += len(group.NodeIDs)
		if memberships > clientDirectoryMaxMemberships {
			return nil, errors.New("client directory exceeds 50000 total group memberships")
		}
		group.Revision = doc.Revision
		groups = append(groups, group)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].ID < groups[j].ID })
	return groups, nil
}

func (s *Server) clientDirectoryView(ctx context.Context) (clientDirectoryView, error) {
	labels, err := s.readClientDirectoryLabels(ctx)
	if err != nil {
		return clientDirectoryView{}, err
	}
	groups, err := s.readClientDirectoryGroups(ctx)
	if err != nil {
		return clientDirectoryView{}, err
	}
	memberships := map[string][]clientDirectoryGroupRef{}
	for _, group := range groups {
		for _, id := range group.NodeIDs {
			memberships[id] = append(memberships[id], clientDirectoryGroupRef{ID: group.ID, Name: group.Name, Revision: group.Revision})
		}
	}
	view := clientDirectoryView{SchemaVersion: 1, Nodes: []clientDirectoryNode{}, Groups: groups, Limits: map[string]int{
		"max_nodes_per_group": clientDirectoryMaxNodes, "max_groups": clientDirectoryMaxGroups, "max_name_bytes": clientDirectoryMaxNameBytes, "max_label_batch": clientDirectoryMaxLabelBatch,
		"max_total_memberships": clientDirectoryMaxMemberships,
	}}
	for _, node := range s.fleet.All() {
		label := labels.Nodes[node.ID]
		refs := memberships[node.ID]
		if refs == nil {
			refs = []clientDirectoryGroupRef{}
		}
		view.Nodes = append(view.Nodes, clientDirectoryNode{NodeID: node.ID, DisplayName: label.DisplayName, LabelRevision: label.Revision, Groups: refs})
	}
	sort.Slice(view.Nodes, func(i, j int) bool { return view.Nodes[i].NodeID < view.Nodes[j].NodeID })
	return view, nil
}

func validClientDirectoryName(name string, allowEmpty bool) bool {
	if (!allowEmpty && name == "") || len(name) > clientDirectoryMaxNameBytes || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

type clientDirectoryLabelInput struct {
	NodeID           string `json:"node_id"`
	DisplayName      string `json:"display_name"`
	ExpectedRevision *int   `json:"expected_revision"`
}

func (s *Server) writeClientDirectoryLabels(w http.ResponseWriter, r *http.Request, principal *middleware.SecurityContext, inputs []clientDirectoryLabelInput) {
	if len(inputs) == 0 || len(inputs) > clientDirectoryMaxLabelBatch {
		jsonError(w, "provide 1..4096 client display names", http.StatusBadRequest)
		return
	}
	labels, err := s.readClientDirectoryLabels(r.Context())
	if err != nil {
		jsonError(w, "client display-name metadata unavailable", http.StatusServiceUnavailable)
		return
	}
	seen := map[string]bool{}
	for _, input := range inputs {
		if !clientDirectoryIDPattern.MatchString(input.NodeID) || seen[input.NodeID] || input.ExpectedRevision == nil || *input.ExpectedRevision < 0 || !validClientDirectoryName(strings.TrimSpace(input.DisplayName), true) {
			jsonError(w, "each display name requires a unique enrolled node_id, a valid name up to 160 UTF-8 bytes and expected_revision", http.StatusBadRequest)
			return
		}
		seen[input.NodeID] = true
		if _, ok := s.fleet.Get(input.NodeID); !ok {
			jsonError(w, "client is not enrolled: "+input.NodeID, http.StatusNotFound)
			return
		}
		if labels.Nodes[input.NodeID].Revision != *input.ExpectedRevision {
			jsonError(w, "client display-name revision changed; refresh the directory before saving", http.StatusConflict)
			return
		}
	}
	for _, input := range inputs {
		labels.Nodes[input.NodeID] = clientDirectoryLabel{DisplayName: strings.TrimSpace(input.DisplayName), Revision: labels.Nodes[input.NodeID].Revision + 1}
	}
	encoded, _ := json.Marshal(labels)
	if len(labels.Nodes) > clientDirectoryMaxNodes || len(encoded) > clientDirectoryMaxLabelBytes {
		jsonError(w, "client display-name directory exceeds its 10000-node or 3 MiB safety limit", http.StatusBadRequest)
		return
	}
	// A bounded batch is one immutable store revision, so a failed write never
	// leaves half the requested names applied.
	saved, err := s.metadata.Put(r.Context(), metastore.Document{Collection: clientDirectoryLabelsCollection, ID: clientDirectoryLabelsID, State: "active", Payload: encoded, CreatedBy: principal.Username})
	if err != nil {
		jsonError(w, "client display-name save failed", http.StatusServiceUnavailable)
		return
	}
	changed := make([]map[string]any, 0, len(inputs))
	for _, input := range inputs {
		label := labels.Nodes[input.NodeID]
		changed = append(changed, map[string]any{"node_id": input.NodeID, "display_name": label.DisplayName, "label_revision": label.Revision})
	}
	s.auditAction(principal, "client-directory.names", clientDirectoryLabelsCollection+"/"+clientDirectoryLabelsID, "success", map[string]string{"count": fmt.Sprint(len(inputs)), "revision": fmt.Sprint(saved.Revision)})
	s.publishClientDirectoryChange("names", clientDirectoryLabelsID, saved.Revision)
	if len(changed) == 1 {
		jsonOK(w, changed[0])
	} else {
		jsonOK(w, map[string]any{"nodes": changed, "revision": saved.Revision})
	}
}

func (s *Server) handleClientDirectory(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, clientDirectoryRoute), "/")
	if path == "resolve-targets" {
		s.handleClientDirectoryResolve(w, r)
		return
	}
	permission := middleware.PermissionReadFleet
	if r.Method != http.MethodGet {
		permission = middleware.PermissionManageFleet
	}
	principal := s.authorize(w, r, permission)
	if principal == nil {
		return
	}
	if r.Method == http.MethodGet && path == "" {
		s.clientDirectoryMu.RLock()
		defer s.clientDirectoryMu.RUnlock()
		view, err := s.clientDirectoryView(r.Context())
		if err != nil {
			jsonError(w, "client directory unavailable", http.StatusServiceUnavailable)
			return
		}
		jsonOK(w, view)
		return
	}
	if r.Method != http.MethodPut && r.Method != http.MethodDelete {
		jsonError(w, "GET, PUT or DELETE required", http.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(path, "/")
	if len(parts) < 1 || len(parts) > 2 || (len(parts) == 2 && !clientDirectoryIDPattern.MatchString(parts[1])) {
		jsonError(w, "invalid client directory resource", http.StatusBadRequest)
		return
	}
	s.clientDirectoryMu.Lock()
	defer s.clientDirectoryMu.Unlock()
	if parts[0] == "nodes" && r.Method == http.MethodPut {
		if len(parts) == 2 {
			var input clientDirectoryLabelInput
			if decodeJSON(r, &input, 8<<10) != nil {
				jsonError(w, "invalid client display-name input", http.StatusBadRequest)
				return
			}
			if input.NodeID != "" && input.NodeID != parts[1] {
				jsonError(w, "node identity cannot be renamed", http.StatusBadRequest)
				return
			}
			input.NodeID = parts[1]
			s.writeClientDirectoryLabels(w, r, principal, []clientDirectoryLabelInput{input})
			return
		}
		var input struct {
			Labels []clientDirectoryLabelInput `json:"labels"`
		}
		if decodeJSON(r, &input, 2<<20) != nil {
			jsonError(w, "invalid batch display-name input", http.StatusBadRequest)
			return
		}
		s.writeClientDirectoryLabels(w, r, principal, input.Labels)
		return
	}
	if len(parts) != 2 || parts[0] != "groups" {
		jsonError(w, "client directory resource not found", http.StatusNotFound)
		return
	}
	id := parts[1]
	var input struct {
		Name             string   `json:"name"`
		NodeIDs          []string `json:"node_ids"`
		ExpectedRevision *int     `json:"expected_revision"`
	}
	if decodeJSON(r, &input, 2<<20) != nil || input.ExpectedRevision == nil || *input.ExpectedRevision < 0 {
		jsonError(w, "group input requires expected_revision", http.StatusBadRequest)
		return
	}
	doc, err := s.metadata.Get(r.Context(), clientDirectoryGroupsCollection, id, 0)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		jsonError(w, "client group metadata unavailable", http.StatusServiceUnavailable)
		return
	}
	current := 0
	if err == nil && doc.State == "active" {
		current = doc.Revision
	}
	if current != *input.ExpectedRevision {
		jsonError(w, "client group revision changed; refresh the directory before saving", http.StatusConflict)
		return
	}
	if r.Method == http.MethodDelete {
		if current == 0 {
			jsonError(w, "client group not found", http.StatusNotFound)
			return
		}
		saved, putErr := s.metadata.Put(r.Context(), metastore.Document{Collection: clientDirectoryGroupsCollection, ID: id, State: "removed", Payload: doc.Payload, CreatedBy: principal.Username})
		if putErr != nil {
			jsonError(w, "client group removal failed", http.StatusServiceUnavailable)
			return
		}
		s.auditAction(principal, "client-directory.group.remove", clientDirectoryGroupsCollection+"/"+id, "success", nil)
		s.publishClientDirectoryChange("group", id, saved.Revision)
		jsonOK(w, map[string]any{"id": id, "revision": saved.Revision, "state": "removed", "pending_rollout_targets_changed": false})
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	if !validClientDirectoryName(input.Name, false) || len(input.NodeIDs) == 0 || len(input.NodeIDs) > clientDirectoryMaxNodes {
		jsonError(w, "group requires a name up to 160 UTF-8 bytes and 1..10000 enrolled node_ids", http.StatusBadRequest)
		return
	}
	targets, resolveErr := s.resolveClientDirectoryTargets(r.Context(), nil, input.NodeIDs, nil)
	if resolveErr != nil {
		jsonError(w, resolveErr.Error(), http.StatusBadRequest)
		return
	}
	groups, listErr := s.readClientDirectoryGroups(r.Context())
	if listErr != nil {
		jsonError(w, "client group catalog unavailable", http.StatusServiceUnavailable)
		return
	}
	if current == 0 && len(groups) >= clientDirectoryMaxGroups {
		jsonError(w, "client directory already has 1000 active groups", http.StatusBadRequest)
		return
	}
	memberships := len(targets.NodeIDs)
	for _, existing := range groups {
		if existing.ID != id {
			memberships += len(existing.NodeIDs)
		}
	}
	if memberships > clientDirectoryMaxMemberships {
		jsonError(w, "client directory exceeds its 50000 total group-membership safety limit", http.StatusBadRequest)
		return
	}
	group := clientDirectoryGroup{ID: id, Name: input.Name, NodeIDs: targets.NodeIDs}
	encoded, _ := json.Marshal(group)
	saved, err := s.metadata.Put(r.Context(), metastore.Document{Collection: clientDirectoryGroupsCollection, ID: id, State: "active", Payload: encoded, CreatedBy: principal.Username})
	if err != nil {
		jsonError(w, "client group save failed", http.StatusServiceUnavailable)
		return
	}
	group.Revision = saved.Revision
	s.auditAction(principal, "client-directory.group.save", clientDirectoryGroupsCollection+"/"+id, "success", map[string]string{"revision": fmt.Sprint(saved.Revision), "member_count": fmt.Sprint(len(group.NodeIDs))})
	s.publishClientDirectoryChange("group", id, saved.Revision)
	jsonOK(w, group)
}

func (s *Server) publishClientDirectoryChange(kind, id string, revision int) {
	if s.hub == nil {
		return
	}
	event, _ := json.Marshal(map[string]any{"type": "client_directory_changed", "kind": kind, "id": id, "revision": revision})
	s.hub.Publish(event)
}

type clientDirectoryTargets struct {
	NodeIDs []string                  `json:"node_ids"`
	Groups  []clientDirectoryGroupRef `json:"groups"`
	Count   int                       `json:"count"`
}

// The returned explicit identities are frozen evidence for a later proposal.
// No live rollout ever re-reads mutable group membership at approval time.
func (s *Server) resolveClientDirectoryTargets(ctx context.Context, groupIDs, nodeIDs []string, expected map[string]int) (clientDirectoryTargets, error) {
	out := clientDirectoryTargets{NodeIDs: []string{}, Groups: []clientDirectoryGroupRef{}}
	if len(groupIDs) > clientDirectoryMaxGroups || len(nodeIDs) > clientDirectoryMaxNodes {
		return out, errors.New("client target selection exceeds directory limits")
	}
	set := map[string]bool{}
	add := func(id string) error {
		if !clientDirectoryIDPattern.MatchString(id) {
			return errors.New("invalid client node identity")
		}
		if _, ok := s.fleet.Get(id); !ok {
			return fmt.Errorf("client is not enrolled: %s", id)
		}
		set[id] = true
		if len(set) > clientDirectoryMaxNodes {
			return errors.New("client target selection exceeds 10000 nodes")
		}
		return nil
	}
	for _, id := range nodeIDs {
		if err := add(id); err != nil {
			return out, err
		}
	}
	seenGroups := map[string]bool{}
	for _, id := range groupIDs {
		if seenGroups[id] {
			continue
		}
		seenGroups[id] = true
		if !clientDirectoryIDPattern.MatchString(id) {
			return out, errors.New("invalid client group identity")
		}
		doc, err := s.metadata.Get(ctx, clientDirectoryGroupsCollection, id, 0)
		if err != nil {
			return out, fmt.Errorf("client group %s could not be read", id)
		}
		if doc.State != "active" {
			return out, fmt.Errorf("client group %s is no longer active", id)
		}
		if revision, ok := expected[id]; ok && revision != doc.Revision {
			return out, fmt.Errorf("client group %s revision changed; refresh target selection", id)
		}
		var group clientDirectoryGroup
		if json.Unmarshal(doc.Payload, &group) != nil || group.ID != id || len(group.NodeIDs) == 0 || len(group.NodeIDs) > clientDirectoryMaxNodes {
			return out, errors.New("stored client group is invalid")
		}
		out.Groups = append(out.Groups, clientDirectoryGroupRef{ID: id, Name: group.Name, Revision: doc.Revision})
		for _, nodeID := range group.NodeIDs {
			if err := ctx.Err(); err != nil {
				return out, err
			}
			if err := add(nodeID); err != nil {
				return out, err
			}
		}
	}
	if len(set) == 0 {
		return out, errors.New("select at least one explicit client or nonempty group")
	}
	for id := range set {
		out.NodeIDs = append(out.NodeIDs, id)
	}
	sort.Strings(out.NodeIDs)
	sort.Slice(out.Groups, func(i, j int) bool { return out.Groups[i].ID < out.Groups[j].ID })
	out.Count = len(out.NodeIDs)
	return out, nil
}

func (s *Server) handleClientDirectoryResolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if s.authorize(w, r, middleware.PermissionTriggerRollout) == nil {
		return
	}
	var input struct {
		GroupIDs       []string       `json:"group_ids"`
		NodeIDs        []string       `json:"node_ids"`
		ExpectedGroups map[string]int `json:"expected_groups,omitempty"`
	}
	if decodeJSON(r, &input, 2<<20) != nil {
		jsonError(w, "invalid client target selection", http.StatusBadRequest)
		return
	}
	s.clientDirectoryMu.RLock()
	defer s.clientDirectoryMu.RUnlock()
	resolved, err := s.resolveClientDirectoryTargets(r.Context(), input.GroupIDs, input.NodeIDs, input.ExpectedGroups)
	if err != nil {
		jsonError(w, err.Error(), http.StatusConflict)
		return
	}
	jsonOK(w, resolved)
}

func (s *Server) bindClientDirectoryRolloutTargets(w http.ResponseWriter, r *http.Request, proposal map[string]any) bool {
	requested, hasGroups := proposal["target_group_ids"]
	delete(proposal, "client_directory_groups")
	if !hasGroups {
		return true
	}
	groupIDs := interfaceStrings(requested)
	if len(groupIDs) == 0 {
		jsonError(w, "target_group_ids must contain at least one named group", http.StatusBadRequest)
		return false
	}
	var expected map[string]int
	if value, supplied := proposal["expected_group_revisions"]; supplied {
		encoded, err := json.Marshal(value)
		if err != nil || json.Unmarshal(encoded, &expected) != nil || len(expected) > clientDirectoryMaxGroups {
			jsonError(w, "expected_group_revisions must contain the selected group revision numbers", http.StatusBadRequest)
			return false
		}
		for _, id := range groupIDs {
			if expected[id] < 1 {
				jsonError(w, "expected_group_revisions must include every selected group", http.StatusBadRequest)
				return false
			}
		}
	}
	s.clientDirectoryMu.RLock()
	defer s.clientDirectoryMu.RUnlock()
	resolved, err := s.resolveClientDirectoryTargets(r.Context(), groupIDs, interfaceStrings(proposal["target_nodes"]), expected)
	if err != nil {
		jsonError(w, err.Error(), http.StatusConflict)
		return false
	}
	proposal["target_nodes"] = resolved.NodeIDs
	proposal["client_directory_groups"] = resolved.Groups
	delete(proposal, "target_group_ids")
	delete(proposal, "expected_group_revisions")
	return true
}

type clientDirectoryFleetNode struct {
	*fleet.Node
	DisplayName     string                    `json:"display_name,omitempty"`
	LabelRevision   int                       `json:"label_revision,omitempty"`
	Groups          []clientDirectoryGroupRef `json:"groups"`
	DirectoryStatus string                    `json:"directory_status"`
}

// Directory availability must not hide fleet health or create a false sync
// failure. Existing fleet data remains readable with an explicit optional
// directory status while its metadata store recovers.
func (s *Server) enrichClientDirectoryNodes(ctx context.Context, nodes []*fleet.Node) []clientDirectoryFleetNode {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	s.clientDirectoryMu.RLock()
	defer s.clientDirectoryMu.RUnlock()
	view, err := s.clientDirectoryView(ctx)
	byID := map[string]clientDirectoryNode{}
	for _, node := range view.Nodes {
		byID[node.NodeID] = node
	}
	out := make([]clientDirectoryFleetNode, 0, len(nodes))
	for _, node := range nodes {
		item := byID[node.ID]
		status := "current"
		if err != nil {
			status = "unavailable"
		}
		groups := item.Groups
		if groups == nil {
			groups = []clientDirectoryGroupRef{}
		}
		out = append(out, clientDirectoryFleetNode{Node: node, DisplayName: item.DisplayName, LabelRevision: item.LabelRevision, Groups: groups, DirectoryStatus: status})
	}
	return out
}
