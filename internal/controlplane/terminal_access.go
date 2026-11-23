package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"nexora.local/nli-v20/internal/auditlog"
	"nexora.local/nli-v20/internal/auth"
	"nexora.local/nli-v20/internal/middleware"
	"nexora.local/nli-v20/internal/protocol"
)

type terminalAccessRecord struct {
	NodeID      string    `json:"node_id"`
	Epoch       string    `json:"access_epoch"`
	State       string    `json:"state"`
	Enabled     bool      `json:"enabled"`
	Revision    int       `json:"revision"`
	RequestedBy string    `json:"requested_by"`
	ApprovedBy  string    `json:"approved_by,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}
type terminalAccessStore struct {
	mu      sync.Mutex
	path    string
	records map[string]terminalAccessRecord
	err     error
}

var errTerminalAccessStorage = errors.New("terminal approval storage is unavailable")

func newTerminalAccessStore(dir string) *terminalAccessStore {
	a := &terminalAccessStore{path: filepath.Join(dir, "terminal-access.json"), records: map[string]terminalAccessRecord{}}
	info, statErr := os.Lstat(a.path)
	if errors.Is(statErr, os.ErrNotExist) {
		return a
	}
	if statErr != nil || !info.Mode().IsRegular() || info.Size() > 4<<20 || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		a.err = errors.New("terminal access policy file is unavailable or unsafe; existing data was preserved")
		return a
	}
	f, e := os.Open(a.path)
	if errors.Is(e, os.ErrNotExist) {
		return a
	}
	if e != nil {
		a.err = e
		return a
	}
	defer f.Close()
	var data struct {
		Schema  int                             `json:"schema"`
		Records map[string]terminalAccessRecord `json:"records"`
	}
	decoder := json.NewDecoder(io.LimitReader(f, 4<<20))
	decoder.DisallowUnknownFields()
	e = decoder.Decode(&data)
	if e == nil && decoder.Decode(new(any)) != io.EOF {
		e = errors.New("unexpected terminal access policy data")
	}
	if e != nil || data.Schema != 1 || data.Records == nil || len(data.Records) > 10000 {
		a.err = errors.New("terminal access policy could not be verified; existing data was preserved")
		return a
	}
	for id, v := range data.Records {
		if id != v.NodeID || len(id) > 512 || len(v.Epoch) > 128 || v.Revision < 1 {
			a.err = errors.New("terminal access policy is invalid; existing data was preserved")
			return a
		}
	}
	a.records = data.Records
	return a
}
func terminalAccessEpoch(st protocol.TerminalStatus) string {
	if len(st.AccessEpoch) != 64 {
		return ""
	}
	if _, err := hex.DecodeString(st.AccessEpoch); err != nil {
		return ""
	}
	return st.AccessEpoch
}
func (a *terminalAccessStore) observe(node string, st protocol.TerminalStatus) (terminalAccessRecord, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	v := a.records[node]
	epoch := terminalAccessEpoch(st)
	if a.err != nil {
		return terminalAccessRecord{NodeID: node, State: "policy_unavailable"}, false
	}
	if !st.Enabled {
		return v, false
	}
	if epoch == "" {
		return terminalAccessRecord{NodeID: node, State: "host_setup_required"}, false
	}
	if v.Epoch == epoch {
		return v, false
	}
	if len(a.records) >= 10000 && v.NodeID == "" {
		return terminalAccessRecord{NodeID: node, State: "capacity_reached"}, false
	}
	v = terminalAccessRecord{NodeID: node, Epoch: epoch, State: "pending_enable", Revision: v.Revision + 1, RequestedBy: "host opt-in", UpdatedAt: time.Now().UTC()}
	a.records[node] = v
	return v, true
}
func (a *terminalAccessStore) view(node string) terminalAccessRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return terminalAccessRecord{NodeID: node, State: "policy_unavailable"}
	}
	return a.records[node]
}
func (a *terminalAccessStore) allowed(node, epoch string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	v := a.records[node]
	return a.err == nil && epoch != "" && v.Epoch == epoch && v.Enabled
}
func (a *terminalAccessStore) update(node, epoch, action, actor string, revision int) (terminalAccessRecord, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return terminalAccessRecord{}, fmt.Errorf("%w: existing policy was preserved", errTerminalAccessStorage)
	}
	v, ok := a.records[node]
	if !ok || v.Revision != revision || v.Epoch != epoch {
		return v, errors.New("terminal approval changed; refresh the node and review the current request")
	}
	switch action {
	case "request_enable":
		if v.Enabled || v.State == "pending_enable" {
			return v, errors.New("terminal enable is already approved or pending")
		}
		v.State = "pending_enable"
		v.RequestedBy = actor
	case "request_disable":
		if v.State == "pending_disable" || v.State == "disabled" {
			return v, errors.New("terminal disable is already pending or approved")
		}
		v.State = "pending_disable"
		v.RequestedBy = actor
	case "approve":
		if v.State == "pending_enable" {
			v.Enabled = true
			v.State = "enabled"
		} else if v.State == "pending_disable" {
			v.Enabled = false
			v.State = "disabled"
		} else {
			return v, errors.New("there is no current terminal request to approve")
		}
		v.ApprovedBy = actor
	case "reject":
		if v.State != "pending_enable" && v.State != "pending_disable" {
			return v, errors.New("there is no current terminal request to reject")
		}
		if v.Enabled {
			v.State = "enabled"
		} else {
			v.State = "disabled"
		}
	default:
		return v, errors.New("select request_enable, request_disable, approve or reject")
	}
	v.Revision++
	v.UpdatedAt = time.Now().UTC()
	records := make(map[string]terminalAccessRecord, len(a.records))
	for id, r := range a.records {
		records[id] = r
	}
	records[node] = v
	data, e := json.Marshal(struct {
		Schema  int                             `json:"schema"`
		Records map[string]terminalAccessRecord `json:"records"`
	}{1, records})
	if e != nil {
		return v, e
	}
	if len(data) > 4<<20 {
		return v, errors.New("terminal approval state exceeds its capacity")
	}
	f, e := os.CreateTemp(filepath.Dir(a.path), ".terminal-access-*")
	if e != nil {
		return v, fmt.Errorf("%w: no access change was applied", errTerminalAccessStorage)
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(append(data, '\n'))
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = os.Rename(name, a.path)
	}
	if e != nil {
		return v, fmt.Errorf("%w: no access change was applied", errTerminalAccessStorage)
	}
	if dir, err := os.Open(filepath.Dir(a.path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	a.records = records
	return v, nil
}
func (t *terminalRelay) noteAccess(node string, st protocol.TerminalStatus) terminalAccessRecord {
	v, created := t.access.observe(node, st)
	if created && t.s.audit != nil {
		action, outcome := "terminal.access.approval_requested", "pending_approval"
		if v.State == "host_disabled" {
			action, outcome = "terminal.access.approval_host_disabled", "success"
		}
		_, _ = t.s.audit.Append(auditlog.Event{Action: action, Actor: "host opt-in", Role: auth.RoleAdmin, Resource: terminalAccessResource(v), Outcome: outcome, Details: map[string]string{"workspace": "node-terminal", "node_id": node, "state": v.State}})
	}
	return v
}
func terminalAccessResource(v terminalAccessRecord) string {
	h := sha256.Sum256([]byte(v.NodeID + "\x00" + v.Epoch))
	return "terminal-access:" + hex.EncodeToString(h[:16])
}
func (t *terminalRelay) currentHost(ctx context.Context, node string) (protocol.TerminalStatus, error) {
	if node == "@controller" {
		x, e := t.broker.Status(ctx)
		return protocol.TerminalStatus{Enabled: x.Enabled, Generation: x.Generation, AccessEpoch: x.AccessEpoch}, e
	}
	n, ok := t.s.fleet.Get(node)
	t.mu.Lock()
	o := t.nodes[node]
	t.mu.Unlock()
	if !ok || time.Since(n.LastSeen) > 90*time.Second || time.Since(o.at) > 45*time.Second {
		return protocol.TerminalStatus{}, errors.New("node is offline or awaiting a fresh terminal heartbeat")
	}
	return o.status, nil
}
func (s *Server) handleTerminalAccess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "POST required", 405)
		return
	}
	p := middleware.GetSecurityContext(r)
	if p == nil || p.Role != auth.RoleAdmin {
		jsonError(w, "administrator terminal access required", 403)
		return
	}
	var in struct {
		NodeID   string `json:"node_id"`
		Epoch    string `json:"access_epoch"`
		Action   string `json:"action"`
		Revision int    `json:"revision"`
	}
	if decodeJSON(r, &in, 2048) != nil || len(in.NodeID) > 512 || in.NodeID == "" || in.Revision < 1 {
		jsonError(w, "provide the exact selected node, request revision and action", 400)
		return
	}
	if in.Action == "approve" && s.terminal.access.view(in.NodeID).State == "pending_enable" || in.Action == "request_enable" {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		st, e := s.terminal.currentHost(ctx, in.NodeID)
		cancel()
		if e != nil || !st.Enabled || terminalAccessEpoch(st) != in.Epoch {
			jsonError(w, "host opt-in/runtime is unavailable or changed; refresh before approving", 409)
			return
		}
	}
	v, e := s.terminal.access.update(in.NodeID, in.Epoch, in.Action, p.Username, in.Revision)
	if e != nil {
		code := 409
		if errors.Is(e, errTerminalAccessStorage) {
			code = 503
		}
		jsonError(w, e.Error(), code)
		return
	}
	if in.Action == "approve" && !v.Enabled {
		s.terminal.mu.Lock()
		for _, session := range s.terminal.sessions {
			if session.NodeID == in.NodeID && terminalActive(session) {
				s.terminal.closeLocked(session, "Node Terminal disable approved")
			}
		}
		s.terminal.mu.Unlock()
	}
	action := "terminal.access.approval_requested"
	outcome := "pending_approval"
	if in.Action == "approve" {
		action = "terminal.access.approve"
		outcome = "success"
	}
	if in.Action == "reject" {
		action = "terminal.access.resolve"
		outcome = "success"
	}
	if s.audit != nil {
		_, _ = s.audit.Append(auditlog.Event{Action: action, Actor: p.Username, Role: p.Role, Resource: terminalAccessResource(v), Outcome: outcome, Details: map[string]string{"workspace": "node-terminal", "node_id": v.NodeID, "state": v.State, "revision": fmt.Sprint(v.Revision)}})
	}
	jsonOK(w, map[string]any{"access": v, "message": "Node Terminal request recorded. Parser, client and controller services were not changed."})
}
