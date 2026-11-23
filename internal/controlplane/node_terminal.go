package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"nexora.local/nli-v20/internal/auditlog"
	"nexora.local/nli-v20/internal/auth"
	"nexora.local/nli-v20/internal/middleware"
	"nexora.local/nli-v20/internal/nodeterminal"
	"nexora.local/nli-v20/internal/protocol"
	"nexora.local/nli-v20/internal/terminalrpc"
)

const terminalBuffer = 256 << 10

type terminalBroker interface {
	Status(context.Context) (terminalrpc.Status, error)
	Open(context.Context, string, uint16, uint16) (nodeterminal.State, error)
	Input(context.Context, string, uint64, []byte) (uint64, error)
	Resize(context.Context, string, uint16, uint16) error
	Read(context.Context, string, uint64, int) (nodeterminal.Output, error)
	Close(context.Context, string, string) error
}
type terminalSession struct {
	ID                          string    `json:"id"`
	NodeID                      string    `json:"node_id"`
	Status                      string    `json:"status"`
	Reason                      string    `json:"reason,omitempty"`
	ExpiresAt                   time.Time `json:"expires_at"`
	IdleTimeoutSeconds          int       `json:"idle_timeout_seconds"`
	ExitCode                    int       `json:"exit_code"`
	owner                       [32]byte
	username, token, generation string
	lease                       time.Time
	cols, rows                  uint16
	start, next, ack            uint64
	data                        []byte
	inputs                      []protocol.TerminalInput
	lastInputHash               [32]byte
	lastInputSeq                uint64
	closedAt                    time.Time
}
type terminalObservation struct {
	status protocol.TerminalStatus
	at     time.Time
}
type terminalAttempt struct {
	count int
	reset time.Time
}
type terminalRelay struct {
	mu       sync.Mutex
	s        *Server
	broker   terminalBroker
	sessions map[string]*terminalSession
	nodes    map[string]terminalObservation
	attempts map[[32]byte]terminalAttempt
	stop     chan struct{}
	done     chan struct{}
	once     sync.Once
}

func newTerminalRelay(s *Server) *terminalRelay {
	t := &terminalRelay{s: s, broker: terminalrpc.NewClient(terminalrpc.DefaultSocket), sessions: map[string]*terminalSession{}, nodes: map[string]terminalObservation{}, attempts: map[[32]byte]terminalAttempt{}, stop: make(chan struct{}), done: make(chan struct{})}
	go t.run()
	return t
}
func terminalActive(s *terminalSession) bool {
	return s.Status == "pending" || s.Status == "connecting" || s.Status == "running"
}
func (t *terminalRelay) closeLocked(s *terminalSession, reason string) {
	if s.Status == "closed" {
		return
	}
	if t.s.audit != nil {
		_, _ = t.s.audit.Append(auditlog.Event{Action: "terminal_close", Actor: s.username, Role: auth.RoleAdmin, Resource: s.NodeID, Outcome: "success", Details: map[string]string{"session_id": s.ID, "reason": reason, "output_bytes": strconv.FormatUint(s.next, 10)}})
	}

	s.Status = "closed"
	s.Reason = reason
	s.closedAt = time.Now()
	s.inputs = nil
	s.data = nil
	s.start = s.next
	s.token = ""
}
func (t *terminalRelay) observe(node string, status protocol.TerminalStatus) {
	if _, ok := t.s.fleet.Get(node); !ok {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nodes[node] = terminalObservation{status, time.Now()}
	for _, s := range t.sessions {
		if s.NodeID == node && terminalActive(s) && s.generation != status.Generation {
			t.closeLocked(s, "Node terminal restarted; connect a new session")
		}
	}
}
func (t *terminalRelay) logout(token string) {
	h := sha256.Sum256([]byte(token))
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, s := range t.sessions {
		if s.owner == h {
			t.closeLocked(s, "Signed out")
		}
	}
}
func (t *terminalRelay) shutdown() { t.once.Do(func() { close(t.stop); <-t.done }) }
func (t *terminalRelay) run() {
	defer close(t.done)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-t.stop:
			t.mu.Lock()
			ids := []string{}
			for _, s := range t.sessions {
				if s.NodeID == "@controller" {
					ids = append(ids, s.ID)
				}
				t.closeLocked(s, "Controller stopped")
			}
			t.mu.Unlock()
			for _, id := range ids {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				_ = t.broker.Close(ctx, id, "Controller stopped")
				cancel()
			}
			return
		case <-tick.C:
			ids := []string{}
			t.mu.Lock()
			for id, s := range t.sessions {
				if terminalActive(s) {
					_, role, err := t.s.auth.ValidateToken(s.token)
					if err != nil || role != auth.RoleAdmin || time.Now().After(s.lease) || time.Now().After(s.ExpiresAt) {
						t.closeLocked(s, "Session expired or authorization revoked")
					}
				}
				if s.Status == "closed" && s.NodeID == "@controller" {
					ids = append(ids, id)
				}
				if !s.closedAt.IsZero() && time.Since(s.closedAt) > time.Minute {
					delete(t.sessions, id)
				}
			}
			for key, a := range t.attempts {
				if time.Now().After(a.reset) {
					delete(t.attempts, key)
				}
			}
			t.mu.Unlock()
			for _, id := range ids {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				_ = t.broker.Close(ctx, id, "Session closed")
				cancel()
			}
		}
	}
}
func (s *Server) handleTerminalNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", 405)
		return
	}
	type node struct {
		ID            string   `json:"id"`
		Role          string   `json:"role"`
		DisplayName   string   `json:"display_name"`
		Hostname      string   `json:"hostname"`
		Groups        []string `json:"groups"`
		Status        string   `json:"status"`
		Enabled       bool     `json:"terminal_enabled"`
		Reason        string   `json:"reason"`
		PrivilegeMode string   `json:"privilege_mode"`
	}
	labels := map[string]clientDirectoryNode{}
	if view, err := s.clientDirectoryView(r.Context()); err == nil {
		for _, n := range view.Nodes {
			labels[n.NodeID] = n
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
	status, err := s.terminal.broker.Status(ctx)
	cancel()
	local := node{ID: "@controller", Role: "controller", DisplayName: "Controller", Hostname: "Controller", Groups: []string{}, Status: "online", Enabled: err == nil && status.Enabled, PrivilegeMode: "operator", Reason: status.Reason}
	if err != nil {
		local.Reason = "Host terminal is not enabled. Run the host setup helper."
	}
	nodes := []node{local}
	s.terminal.mu.Lock()
	for _, n := range s.fleet.All() {
		obs := s.terminal.nodes[n.ID]
		label := labels[n.ID]
		groups := []string{}
		for _, g := range label.Groups {
			groups = append(groups, g.Name)
		}
		online := time.Since(n.LastSeen) < 90*time.Second
		state := "offline"
		if online {
			state = "online"
		}
		enabled := online && time.Since(obs.at) < 45*time.Second && obs.status.Enabled
		reason := obs.status.Reason
		if reason == "" && !enabled {
			reason = "Node terminal disabled or awaiting a fresh heartbeat"
		}
		nodes = append(nodes, node{n.ID, "client", label.DisplayName, n.Hostname, groups, state, enabled, reason, "operator"})
	}
	s.terminal.mu.Unlock()
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	items := []node{}
	q := strings.ToLower(r.URL.Query().Get("q"))
	cursor := r.URL.Query().Get("cursor")
	next := ""
	for _, n := range nodes {
		if n.ID <= cursor || !strings.Contains(strings.ToLower(n.ID+" "+n.DisplayName+" "+n.Hostname+" "+strings.Join(n.Groups, " ")), q) {
			continue
		}
		if len(items) == 100 {
			next = items[99].ID
			break
		}
		items = append(items, n)
	}
	jsonOK(w, map[string]any{"items": items, "next_cursor": next, "permission": middleware.PermissionTerminal, "limits": map[string]int{"max_active_sessions": 64, "max_user_sessions": 4, "max_output_bytes": terminalBuffer}})
}
func (s *Server) handleTerminalSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	var in struct {
		NodeID           string `json:"node_id"`
		Cols, Rows       uint16
		Password, Reason string
	}
	if decodeJSON(r, &in, 8192) != nil || len(in.Reason) < 3 || len(in.Reason) > 200 || strings.ContainsAny(in.Reason, "\r\n") || in.Cols < 20 || in.Cols > 400 || in.Rows < 5 || in.Rows > 200 {
		jsonError(w, "provide a node, terminal size, current password and a short reason", 400)
		return
	}
	p := middleware.GetSecurityContext(r)
	if p == nil || p.Role != auth.RoleAdmin {
		jsonError(w, "administrator terminal access required", 403)
		return
	}
	token := extractToken(r)
	owner := sha256.Sum256([]byte(token))
	t := s.terminal
	t.mu.Lock()
	a := t.attempts[owner]
	if time.Now().After(a.reset) {
		a = terminalAttempt{reset: time.Now().Add(time.Minute)}
	}
	a.count++
	t.attempts[owner] = a
	t.mu.Unlock()
	if a.count > 5 {
		jsonError(w, "terminal step-up attempt limit reached; wait one minute", 429)
		return
	}
	if !s.auth.VerifyCurrentPassword(p.Username, in.Password) {
		jsonError(w, "current password required", 403)
		return
	}
	in.Password = ""
	var st protocol.TerminalStatus
	if in.NodeID == "@controller" {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		x, err := t.broker.Status(ctx)
		cancel()
		if err != nil {
			jsonError(w, "host terminal is not enabled", 409)
			return
		}
		st = protocol.TerminalStatus{Enabled: x.Enabled, Generation: x.Generation, IdleTimeoutSeconds: x.IdleTimeoutSeconds, LifetimeSeconds: x.LifetimeSeconds, MaxSessions: x.MaxSessions}
	} else {
		n, ok := s.fleet.Get(in.NodeID)
		t.mu.Lock()
		o := t.nodes[in.NodeID]
		t.mu.Unlock()
		if !ok || time.Since(n.LastSeen) > 90*time.Second || time.Since(o.at) > 45*time.Second {
			jsonError(w, "node is offline or awaiting terminal heartbeat", 409)
			return
		}
		st = o.status
	}
	if !st.Enabled || st.Generation == "" {
		jsonError(w, "terminal is disabled by host policy", 409)
		return
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		jsonError(w, "cannot create session", 503)
		return
	}
	id := "term-" + hex.EncodeToString(random[:])
	life := st.LifetimeSeconds
	if life < 1 || life > 1800 {
		life = 1800
	}
	session := &terminalSession{ID: id, NodeID: in.NodeID, Status: "pending", ExpiresAt: time.Now().Add(time.Duration(life) * time.Second), IdleTimeoutSeconds: st.IdleTimeoutSeconds, owner: owner, username: p.Username, token: token, generation: st.Generation, lease: time.Now().Add(15 * time.Second), cols: in.Cols, rows: in.Rows}
	t.mu.Lock()
	active, user, nodeCount := 0, 0, 0
	for _, v := range t.sessions {
		if terminalActive(v) {
			active++
			if v.owner == owner {
				user++
			}
			if v.NodeID == in.NodeID {
				nodeCount++
			}
		}
	}
	cap := st.MaxSessions
	if cap < 1 || cap > 16 {
		cap = 4
	}
	if active >= 64 || user >= 4 || nodeCount >= cap || len(t.sessions) >= 256 {
		t.mu.Unlock()
		jsonError(w, "terminal capacity reached; close an existing session", 409)
		return
	}
	t.sessions[id] = session
	t.mu.Unlock()
	if in.NodeID == "@controller" {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		_, err := t.broker.Open(ctx, id, in.Cols, in.Rows)
		cancel()
		t.mu.Lock()
		if err != nil {
			t.closeLocked(session, "Node terminal could not start")
		} else if terminalActive(session) {
			session.Status = "running"
		}
		t.mu.Unlock()
		if err != nil {
			jsonError(w, "node terminal could not start", 409)
			return
		}
	}
	_, _ = s.audit.Append(auditlog.Event{Action: "terminal_open", Actor: p.Username, Role: p.Role, Resource: in.NodeID, Outcome: "success", RemoteIP: r.RemoteAddr, Details: map[string]string{"session_id": id, "reason": in.Reason, "privilege_mode": "operator"}})
	t.mu.Lock()
	defer t.mu.Unlock()
	jsonOK(w, map[string]any{"session": session, "next_sequence": 1})
}
func (s *Server) handleTerminalSession(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/terminal/sessions/"), "/")
	if len(parts) > 2 {
		jsonError(w, "session not found", 404)
		return
	}
	id := parts[0]
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}
	t := s.terminal
	owner := sha256.Sum256([]byte(extractToken(r)))
	t.mu.Lock()
	v := t.sessions[id]
	if v == nil || v.owner != owner {
		t.mu.Unlock()
		jsonError(w, "session not found", 404)
		return
	}
	local := v.NodeID == "@controller"
	t.mu.Unlock()
	if r.Method == http.MethodGet && action == "" {
		after, err := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
		if err != nil {
			jsonError(w, "valid output cursor required", 400)
			return
		}
		t.mu.Lock()
		v.lease = time.Now().Add(15 * time.Second)
		active := terminalActive(v)
		t.mu.Unlock()
		if local && active {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			out, err := t.broker.Read(ctx, id, after, 64<<10)
			cancel()
			t.mu.Lock()
			if err != nil {
				t.closeLocked(v, "Node terminal disconnected")
			} else {
				t.mergeLocked(v, protocol.TerminalSessionUpdate{ID: id, Status: "running", Start: out.Start, Next: out.Next, Data: out.Data, AckedInput: out.InputAck, Truncated: out.Truncated, ExitCode: out.ExitCode})
				if out.Closed {
					v.Status = "exited"
					v.Reason = out.Reason
					v.closedAt = time.Now()
					v.token = ""
				}
			}
			t.mu.Unlock()
		}
		t.mu.Lock()
		defer t.mu.Unlock()
		start := after
		if start < v.start {
			start = v.start
		}
		if start > v.next {
			jsonError(w, "output cursor exceeds available output", 400)
			return
		}
		end := v.next
		if end-start > 64<<10 {
			end = start + (64 << 10)
		}
		data := append([]byte(nil), v.data[start-v.start:end-v.start]...)
		jsonOK(w, map[string]any{"session": v, "data_b64": base64.StdEncoding.EncodeToString(data), "start": start, "next_sequence": end, "truncated": after < v.start})
		return
	}
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	if action == "close" {
		t.mu.Lock()
		t.closeLocked(v, "Disconnected by operator")
		t.mu.Unlock()
		if local {
			ctx, cancel := context.WithTimeout(r.Context(), time.Second)
			_ = t.broker.Close(ctx, id, "Disconnected by operator")
			cancel()
		}
		jsonOK(w, map[string]any{"status": "closed"})
		return
	}
	t.mu.Lock()
	if !terminalActive(v) {
		t.mu.Unlock()
		jsonError(w, "session is closed", 409)
		return
	}
	t.mu.Unlock()
	switch action {
	case "resize":
		var in struct{ Cols, Rows uint16 }
		if decodeJSON(r, &in, 1024) != nil || in.Cols < 20 || in.Cols > 400 || in.Rows < 5 || in.Rows > 200 {
			jsonError(w, "invalid terminal size", 400)
			return
		}
		t.mu.Lock()
		v.cols, v.rows = in.Cols, in.Rows
		t.mu.Unlock()
		if local {
			ctx, cancel := context.WithTimeout(r.Context(), time.Second)
			err := t.broker.Resize(ctx, id, in.Cols, in.Rows)
			cancel()
			if err != nil {
				jsonError(w, "resize failed", 409)
				return
			}
		}
		jsonOK(w, map[string]any{"status": "ok"})
	case "input":
		var in struct {
			Data     string `json:"data"`
			Sequence uint64 `json:"sequence"`
		}
		if decodeJSON(r, &in, 64<<10) != nil || len(in.Data) == 0 || len(in.Data) > 8192 || in.Sequence == 0 {
			jsonError(w, "input requires 1..8192 bytes and a sequence", 400)
			return
		}
		hash := sha256.Sum256([]byte(in.Data))
		t.mu.Lock()
		if in.Sequence == v.lastInputSeq && hash == v.lastInputHash {
			t.mu.Unlock()
			jsonOK(w, map[string]any{"acknowledged": in.Sequence})
			return
		}
		if in.Sequence != v.lastInputSeq+1 || len(v.inputs) >= 32 {
			t.mu.Unlock()
			jsonError(w, "input sequence conflict or queue full", 409)
			return
		}
		v.lastInputSeq = in.Sequence
		v.lastInputHash = hash
		v.lease = time.Now().Add(15 * time.Second)
		if !local {
			v.inputs = append(v.inputs, protocol.TerminalInput{Sequence: in.Sequence, Data: []byte(in.Data)})
		}
		t.mu.Unlock()
		if local {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			_, err := t.broker.Input(ctx, id, in.Sequence, []byte(in.Data))
			cancel()
			if err != nil {
				t.mu.Lock()
				t.closeLocked(v, "Input delivery interrupted; reconnect without replaying commands")
				t.mu.Unlock()
				jsonError(w, "input delivery interrupted; session closed", 409)
				return
			}
		}
		jsonOK(w, map[string]any{"acknowledged": in.Sequence})
	default:
		jsonError(w, "operation not found", 404)
	}
}
func (t *terminalRelay) mergeLocked(s *terminalSession, u protocol.TerminalSessionUpdate) {
	if u.Next < u.Start || u.Next-u.Start != uint64(len(u.Data)) || len(u.Data) > 64<<10 {
		return
	}
	if u.Start > s.next {
		s.data = nil
		s.start = u.Start
		s.next = u.Start
	}
	if u.Next > s.next {
		offset := s.next - u.Start
		s.data = append(s.data, u.Data[offset:]...)
		s.next = u.Next
		if len(s.data) > terminalBuffer {
			s.data = s.data[len(s.data)-terminalBuffer:]
			s.start = s.next - uint64(len(s.data))
		}
	}
	if u.AckedInput >= s.ack && u.AckedInput <= s.lastInputSeq {
		s.ack = u.AckedInput
		for len(s.inputs) > 0 && s.inputs[0].Sequence <= s.ack {
			s.inputs = s.inputs[1:]
		}
	}
	if u.Status == "running" {
		s.Status = "running"
	}
	if u.Status == "closed" || u.Status == "exited" || u.Status == "failed" {
		s.Status = u.Status
		s.Reason = u.Reason
		s.ExitCode = u.ExitCode
		s.closedAt = time.Now()
		s.token = ""
		s.inputs = nil
	}
}
func (s *Server) handleTerminalExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	var in protocol.TerminalExchangeRequest
	if decodeJSON(r, &in, 2<<20) != nil || !s.authorizeNode(r, in.NodeID) {
		jsonError(w, "invalid node credentials or exchange", 401)
		return
	}
	if len(in.Sessions) > 16 {
		jsonError(w, "too many terminal updates", 400)
		return
	}
	for _, u := range in.Sessions {
		if len(u.Data) > 64<<10 || u.Next < u.Start || u.Next-u.Start != uint64(len(u.Data)) {
			jsonError(w, "invalid terminal output frame", 400)
			return
		}
	}
	t := s.terminal
	t.observe(in.NodeID, in.Terminal)
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, u := range in.Sessions {
		v := t.sessions[u.ID]
		if v != nil && v.NodeID == in.NodeID && terminalActive(v) && v.generation == in.Terminal.Generation {
			t.mergeLocked(v, u)
		}
	}
	out := protocol.TerminalExchangeResponse{Sessions: []protocol.TerminalSessionDirective{}, PollAfterMS: 10000}
	for _, v := range t.sessions {
		if v.NodeID != in.NodeID || !terminalActive(v) {
			continue
		}
		active := terminalActive(v)
		if active {
			out.PollAfterMS = 350
		}
		out.Sessions = append(out.Sessions, protocol.TerminalSessionDirective{ID: v.ID, Cols: v.cols, Rows: v.rows, Close: !active, After: v.next, Inputs: append([]protocol.TerminalInput(nil), v.inputs...)})
	}
	jsonOK(w, out)
}
