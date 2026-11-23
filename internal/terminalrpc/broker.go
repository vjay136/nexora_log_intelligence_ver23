package terminalrpc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"nexora.local/nli-v20/internal/nodeterminal"
)

type Status struct {
	Supported          bool   `json:"supported"`
	Enabled            bool   `json:"enabled"`
	PrivilegeMode      string `json:"privilege_mode"`
	Generation         string `json:"generation"`
	Reason             string `json:"reason,omitempty"`
	MaxSessions        int    `json:"max_sessions"`
	IdleTimeoutSeconds int    `json:"idle_timeout_seconds"`
	LifetimeSeconds    int    `json:"lifetime_seconds"`
}
type request struct {
	ID       string `json:"id"`
	Cols     uint16 `json:"cols,omitempty"`
	Rows     uint16 `json:"rows,omitempty"`
	Sequence uint64 `json:"sequence,omitempty"`
	Data     []byte `json:"data,omitempty"`
	After    uint64 `json:"after,omitempty"`
	Limit    int    `json:"limit,omitempty"`
	Reason   string `json:"reason,omitempty"`
}
type response struct {
	Status       *Status              `json:"status,omitempty"`
	State        *nodeterminal.State  `json:"state,omitempty"`
	Output       *nodeterminal.Output `json:"output,omitempty"`
	Acknowledged uint64               `json:"acknowledged,omitempty"`
	Error        string               `json:"error,omitempty"`
}

type Server struct {
	manager         *nodeterminal.Manager
	status          Status
	mu              sync.Mutex
	leases          map[string]time.Time
	allowInputWrite bool
}

func NewServer(manager *nodeterminal.Manager, cfg HostConfig) (*Server, error) {
	var err error
	cfg, err = NormalizeHostConfig(cfg)
	if err != nil {
		return nil, err
	}
	if manager == nil {
		return nil, errors.New("terminal manager is required")
	}
	if cfg.Enabled {
		if _, err = exec.LookPath("/usr/bin/setfacl"); err != nil {
			return nil, errors.New("terminal access requires the host ACL setup")
		}
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return nil, err
	}
	status := Status{Supported: true, Enabled: manager.Enabled(), PrivilegeMode: cfg.PrivilegeMode, Generation: hex.EncodeToString(random[:]), MaxSessions: cfg.MaxSessions, IdleTimeoutSeconds: cfg.IdleTimeoutSeconds, LifetimeSeconds: cfg.LifetimeSeconds}
	if !status.Enabled {
		status.Reason = "Node terminal is disabled by host policy"
	}
	return &Server{manager: manager, status: status, leases: map[string]time.Time{}, allowInputWrite: cfg.AllowInputWrite != nil && *cfg.AllowInputWrite}, nil
}

// Serve accepts only local peers authorized using kernel credentials, not HTTP
// headers. The API daemon keeps its existing sandbox; only its process receives
// the socket's supplementary group when terminal access is enabled on the host.
func (s *Server) Serve(ctx context.Context, path, group string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := prepareSocketPath(path); err != nil {
		return err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(path)
	mode := os.FileMode(0600)
	if group != "" {
		g, lookupErr := user.LookupGroup(group)
		if lookupErr != nil {
			return errors.New("terminal API socket group is unavailable")
		}
		gid, parseErr := strconv.Atoi(g.Gid)
		if parseErr != nil {
			return errors.New("terminal API socket group is invalid")
		}
		if err = os.Chown(filepath.Dir(path), 0, gid); err != nil {
			return err
		}
		if err = os.Chmod(filepath.Dir(path), 0750); err != nil {
			return err
		}
		if err = os.Chown(path, 0, gid); err != nil {
			return err
		}
		mode = 0660
	}
	if err = os.Chmod(path, mode); err != nil {
		return err
	}
	server := &http.Server{Handler: s, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 4096, ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
		return context.WithValue(ctx, peerContextKey{}, trustedPeer(conn))
	}}
	go func() { <-ctx.Done(); _ = server.Close() }()
	go s.expireLeases(ctx)
	err = server.Serve(listener)
	if ctx.Err() != nil || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func prepareSocketPath(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("terminal socket path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 || !rootOwned(info) {
			return errors.New("refusing to replace a non-root terminal socket")
		}
		conn, dialErr := net.DialTimeout("unix", path, 250*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			return errors.New("terminal broker is already running")
		}
		return os.Remove(path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

type peerContextKey struct{}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if trusted, _ := r.Context().Value(peerContextKey{}).(bool); !trusted {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(response{Error: "local terminal peer is not authorized"})
		return
	}
	if r.URL.Path == "/v1/status" && r.Method == http.MethodGet {
		_ = json.NewEncoder(w).Encode(response{Status: &s.status})
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path == "/v1/refresh-read-access" {
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		var empty struct{}
		if decoder.Decode(&empty) != nil || decoder.Decode(new(any)) != io.EOF {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(response{Error: "read access refresh accepts no arguments"})
			return
		}
		if !s.status.Enabled {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(response{Error: "node terminal is disabled by host policy"})
			return
		}
		if err := refreshReadAccess(r.Context()); err != nil {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(response{Error: "NLI read access refresh failed"})
			return
		}
		_ = json.NewEncoder(w).Encode(response{})
		return
	}
	var input request
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 96<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(response{Error: "invalid terminal broker request"})
		return
	}
	var result response
	var err error
	switch r.URL.Path {
	case "/v1/open":
		if s.status.Enabled {
			if err = refreshReadAccess(r.Context()); err != nil {
				break
			}
		}
		if s.status.Enabled && s.allowInputWrite {
			if err = refreshInputACL(r.Context()); err != nil {
				break
			}
		}
		var state nodeterminal.State
		state, err = s.manager.Open(input.ID, input.Cols, input.Rows)
		result.State = &state
	case "/v1/input":
		result.Acknowledged, err = s.manager.Input(input.ID, input.Sequence, input.Data)
	case "/v1/resize":
		err = s.manager.Resize(input.ID, input.Cols, input.Rows)
	case "/v1/read":
		var output nodeterminal.Output
		output, err = s.manager.Read(input.ID, input.After, input.Limit)
		result.Output = &output
	case "/v1/close":
		err = s.manager.Close(input.ID, "remote session closed")
		s.mu.Lock()
		delete(s.leases, input.ID)
		s.mu.Unlock()
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err != nil {
		code := http.StatusConflict
		if errors.Is(err, nodeterminal.ErrDisabled) {
			code = http.StatusForbidden
		}
		if errors.Is(err, nodeterminal.ErrNotFound) {
			code = http.StatusNotFound
		}
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(response{Error: err.Error()})
		return
	}
	if r.URL.Path != "/v1/close" {
		closed := result.State != nil && result.State.Closed || result.Output != nil && result.Output.Closed
		s.mu.Lock()
		if closed {
			delete(s.leases, input.ID)
		} else {
			s.leases[input.ID] = time.Now().Add(15 * time.Second)
		}
		s.mu.Unlock()
	}
	_ = json.NewEncoder(w).Encode(result)
}
func (s *Server) expireLeases(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			var ids []string
			s.mu.Lock()
			for id, until := range s.leases {
				if now.After(until) {
					ids = append(ids, id)
					delete(s.leases, id)
				}
			}
			s.mu.Unlock()
			for _, id := range ids {
				_ = s.manager.Close(id, "terminal transport lease expired")
			}
		}
	}
}

type Client struct{ http *http.Client }

// RefreshReadAccess notifies the opt-in host broker after an atomic parser
// generation swap. Failure cannot invalidate a successful parser rollout.
func (c *Client) RefreshReadAccess(ctx context.Context) error {
	_, err := c.call(ctx, "/v1/refresh-read-access", struct{}{})
	return err
}

func NewClient(socket string) *Client {
	if socket == "" {
		socket = DefaultSocket
	}
	transport := &http.Transport{MaxIdleConnsPerHost: 4, IdleConnTimeout: 15 * time.Second, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socket)
	}}
	return &Client{http: &http.Client{Transport: transport, Timeout: 3 * time.Second}}
}
func (c *Client) call(ctx context.Context, path string, input any) (response, error) {
	var result response
	method := http.MethodGet
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return result, err
		}
		body = bytes.NewReader(data)
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://terminal-broker"+path, body)
	if err != nil {
		return result, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return result, errors.New("local terminal broker is unavailable")
	}
	defer resp.Body.Close()
	if json.NewDecoder(io.LimitReader(resp.Body, 128<<10)).Decode(&result) != nil {
		return result, errors.New("local terminal broker response is invalid")
	}
	if resp.StatusCode != 200 || result.Error != "" {
		if result.Error == "" {
			result.Error = "terminal broker request failed"
		}
		return result, errors.New(result.Error)
	}
	return result, nil
}
func (c *Client) Status(ctx context.Context) (Status, error) {
	r, e := c.call(ctx, "/v1/status", nil)
	if e != nil {
		return Status{}, e
	}
	if r.Status == nil {
		return Status{}, errors.New("terminal broker status missing")
	}
	return *r.Status, nil
}
func (c *Client) Open(ctx context.Context, id string, cols, rows uint16) (nodeterminal.State, error) {
	r, e := c.call(ctx, "/v1/open", request{ID: id, Cols: cols, Rows: rows})
	if e != nil {
		return nodeterminal.State{}, e
	}
	if r.State == nil {
		return nodeterminal.State{}, errors.New("terminal state missing")
	}
	return *r.State, nil
}
func (c *Client) Input(ctx context.Context, id string, seq uint64, data []byte) (uint64, error) {
	r, e := c.call(ctx, "/v1/input", request{ID: id, Sequence: seq, Data: data})
	return r.Acknowledged, e
}
func (c *Client) Resize(ctx context.Context, id string, cols, rows uint16) error {
	_, e := c.call(ctx, "/v1/resize", request{ID: id, Cols: cols, Rows: rows})
	return e
}
func (c *Client) Read(ctx context.Context, id string, after uint64, limit int) (nodeterminal.Output, error) {
	r, e := c.call(ctx, "/v1/read", request{ID: id, After: after, Limit: limit})
	if e != nil {
		return nodeterminal.Output{}, e
	}
	if r.Output == nil {
		return nodeterminal.Output{}, errors.New("terminal output missing")
	}
	return *r.Output, nil
}
func (c *Client) Close(ctx context.Context, id, reason string) error {
	_, e := c.call(ctx, "/v1/close", request{ID: id})
	return e
}
