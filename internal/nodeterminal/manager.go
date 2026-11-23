// Package nodeterminal provides bounded, opt-in local PTY sessions. Authentication
// and remote ownership checks belong to the broker; shell privileges come only
// from the configured host account. No terminal content is persisted here.
package nodeterminal

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sync"
	"time"
)

const Capability = "node-terminal-v1"

var (
	ErrDisabled    = errors.New("node terminal is disabled by host policy")
	ErrUnsupported = errors.New("node terminal requires Linux")
	ErrNotFound    = errors.New("terminal session not found")
	ErrCapacity    = errors.New("node terminal session capacity reached")
	ErrClosed      = errors.New("terminal session is closed")
	ErrSequence    = errors.New("terminal input sequence is invalid")
	ErrCursor      = errors.New("terminal output cursor is ahead of available output")
)
var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{15,127}$`)

type Config struct {
	Systemd              bool // Production brokers must enable cgroup containment.
	Enabled              bool
	Username             string
	AllowRoot            bool
	Shell                string
	WorkDir              string
	MaxSessions          int
	MaxOutputBytes       int
	MaxInputBytes        int
	OutputBytesPerSecond int
	IdleTimeout          time.Duration
	MaxLifetime          time.Duration
	RetainClosed         time.Duration
}

type State struct {
	ID            string    `json:"id"`
	Username      string    `json:"username"`
	StartedAt     time.Time `json:"started_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	IdleExpiresAt time.Time `json:"idle_expires_at"`
	Closed        bool      `json:"closed"`
	Closing       bool      `json:"closing"`
	ExitCode      int       `json:"exit_code"`
	Reason        string    `json:"reason,omitempty"`
	InputAck      uint64    `json:"input_ack"`
	OutputStart   uint64    `json:"output_start"`
	OutputNext    uint64    `json:"output_next"`
}
type Output struct {
	State
	Data      []byte `json:"data,omitempty"`
	Start     uint64 `json:"start"`
	Next      uint64 `json:"next"`
	Truncated bool   `json:"truncated"`
}

type localProcess interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Resize(uint16, uint16) error
	Wait() int
	Stop()
}
type platformAccount struct {
	uid, gid uint32
	groups   []uint32
	home     string
}
type Manager struct {
	mu       sync.Mutex
	cfg      Config
	account  platformAccount
	sessions map[string]*session
	done     chan struct{}
	stopOnce sync.Once
}
type session struct {
	cols, rows                   uint16
	mu                           sync.Mutex
	id                           string
	process                      localProcess
	started, lastInput, closedAt time.Time
	output                       []byte
	start, next, inputAck        uint64
	lastInputHash                [32]byte
	closed, closing              bool
	exitCode                     int
	reason                       string
	stop                         chan struct{}
	stopOnce                     sync.Once
}

func normalize(cfg Config) (Config, error) {
	if cfg.MaxSessions == 0 {
		cfg.MaxSessions = 4
	}
	if cfg.MaxSessions < 1 || cfg.MaxSessions > 16 {
		return cfg, errors.New("max terminal sessions must be 1..16")
	}
	if cfg.MaxOutputBytes == 0 {
		cfg.MaxOutputBytes = 256 << 10
	}
	if cfg.MaxOutputBytes < 4096 || cfg.MaxOutputBytes > 1<<20 {
		return cfg, errors.New("terminal output buffer must be 4096..1048576 bytes")
	}
	if cfg.MaxInputBytes == 0 {
		cfg.MaxInputBytes = 16 << 10
	}
	if cfg.MaxInputBytes < 256 || cfg.MaxInputBytes > 64<<10 {
		return cfg, errors.New("terminal input chunk must be 256..65536 bytes")
	}
	if cfg.OutputBytesPerSecond == 0 {
		cfg.OutputBytesPerSecond = 128 << 10
	}
	if cfg.OutputBytesPerSecond < 4096 || cfg.OutputBytesPerSecond > 1<<20 {
		return cfg, errors.New("terminal output rate must be 4096..1048576 bytes per second")
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}
	if cfg.MaxLifetime == 0 {
		cfg.MaxLifetime = 30 * time.Minute
	}
	if cfg.RetainClosed == 0 {
		cfg.RetainClosed = time.Minute
	}
	for _, value := range []time.Duration{cfg.IdleTimeout, cfg.MaxLifetime, cfg.RetainClosed} {
		if value < 100*time.Millisecond || value > time.Hour {
			return cfg, errors.New("terminal time limits must be 100ms..1h")
		}
	}
	if cfg.IdleTimeout > cfg.MaxLifetime {
		cfg.IdleTimeout = cfg.MaxLifetime
	}
	if cfg.Shell == "" {
		cfg.Shell = "/bin/bash"
	}
	return cfg, nil
}
func New(cfg Config) (*Manager, error) {
	cfg, err := normalize(cfg)
	if err != nil {
		return nil, err
	}
	m := &Manager{cfg: cfg, sessions: map[string]*session{}, done: make(chan struct{})}
	if cfg.Systemd {
		if err := cleanupSystemdSessions(); err != nil {
			return nil, err
		}
	}
	if cfg.Enabled {
		m.account, cfg, err = resolveAccount(cfg)
		if err != nil {
			return nil, err
		}
		m.cfg = cfg
	}
	go m.janitor()
	return m, nil
}
func (m *Manager) Enabled() bool { return m != nil && m.cfg.Enabled }
func (m *Manager) Open(id string, cols, rows uint16) (State, error) {
	if !m.Enabled() {
		return State{}, ErrDisabled
	}
	if !idPattern.MatchString(id) {
		return State{}, errors.New("invalid terminal session id")
	}
	if err := validateSize(cols, rows); err != nil {
		return State{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	select {
	case <-m.done:
		return State{}, ErrClosed
	default:
	}
	if old := m.sessions[id]; old != nil {
		return m.snapshot(old), nil
	}
	active := 0
	for _, s := range m.sessions {
		s.mu.Lock()
		if !s.closed {
			active++
		}
		s.mu.Unlock()
	}
	if active >= m.cfg.MaxSessions {
		return State{}, ErrCapacity
	}
	for len(m.sessions) >= m.cfg.MaxSessions*4 {
		var oldest *session
		var key string
		for id, s := range m.sessions {
			s.mu.Lock()
			closed, when := s.closed, s.closedAt
			s.mu.Unlock()
			if closed && (oldest == nil || when.Before(oldest.closedAt)) {
				oldest, key = s, id
			}
		}
		if oldest == nil {
			return State{}, ErrCapacity
		}
		delete(m.sessions, key)
	}
	proc, err := startProcess(m.cfg, m.account, id, cols, rows)
	if err != nil {
		return State{}, fmt.Errorf("start terminal: %w", err)
	}
	now := time.Now().UTC()
	s := &session{cols: cols, rows: rows, id: id, process: proc, started: now, lastInput: now, exitCode: -1, stop: make(chan struct{}), output: make([]byte, 0, m.cfg.MaxOutputBytes)}
	m.sessions[id] = s
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		buf := make([]byte, 16<<10)
		for {
			n, err := proc.Read(buf)
			if n > 0 {
				s.mu.Lock()
				s.appendOutput(buf[:n], m.cfg.MaxOutputBytes)
				s.mu.Unlock()
				timer := time.NewTimer(time.Duration(n) * time.Second / time.Duration(m.cfg.OutputBytesPerSecond))
				select {
				case <-timer.C:
				case <-s.stop:
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		code := proc.Wait()
		select {
		case <-drained:
		case <-time.After(2 * time.Second):
			proc.Stop()
			<-drained
		}
		s.mu.Lock()
		s.closed = true
		s.closing = false
		s.exitCode = code
		s.closedAt = time.Now().UTC()
		if s.reason == "" {
			s.reason = "process_exit"
		}
		s.mu.Unlock()
		proc.Stop()
	}()
	return m.snapshot(s), nil
}
func validateSize(cols, rows uint16) error {
	if cols < 20 || cols > 500 || rows < 5 || rows > 200 {
		return errors.New("terminal size must be 20..500 columns and 5..200 rows")
	}
	return nil
}
func (s *session) appendOutput(data []byte, max int) {
	s.next += uint64(len(data))
	if len(data) >= max {
		s.output = append(s.output[:0], data[len(data)-max:]...)
	} else {
		overflow := len(s.output) + len(data) - max
		if overflow > 0 {
			copy(s.output, s.output[overflow:])
			s.output = s.output[:len(s.output)-overflow]
		}
		s.output = append(s.output, data...)
	}
	s.start = s.next - uint64(len(s.output))
}
func (m *Manager) lookup(id string) (*session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[id]
	if s == nil {
		return nil, ErrNotFound
	}
	return s, nil
}
func (m *Manager) snapshot(s *session) State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return m.stateLocked(s)
}
func (m *Manager) stateLocked(s *session) State {
	return State{ID: s.id, Username: m.cfg.Username, StartedAt: s.started, ExpiresAt: s.started.Add(m.cfg.MaxLifetime), IdleExpiresAt: s.lastInput.Add(m.cfg.IdleTimeout), Closed: s.closed, Closing: s.closing, ExitCode: s.exitCode, Reason: s.reason, InputAck: s.inputAck, OutputStart: s.start, OutputNext: s.next}
}
func (m *Manager) Input(id string, seq uint64, data []byte) (uint64, error) {
	if len(data) == 0 || len(data) > m.cfg.MaxInputBytes {
		return 0, errors.New("terminal input chunk is empty or exceeds host limit")
	}
	s, err := m.lookup(id)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	if s.closed || s.closing {
		s.mu.Unlock()
		return 0, ErrClosed
	}
	hash := sha256.Sum256(data)
	if seq == 0 || seq > s.inputAck+1 || seq == s.inputAck && hash != s.lastInputHash {
		s.mu.Unlock()
		return 0, ErrSequence
	}
	if seq <= s.inputAck {
		ack := s.inputAck
		s.mu.Unlock()
		return ack, nil
	}
	n, err := s.process.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		s.mu.Unlock()
		_ = m.Close(id, "input_failed")
		return 0, errors.New("terminal input could not be delivered; session closed to prevent replay")
	}
	s.inputAck = seq
	s.lastInputHash = hash
	s.lastInput = time.Now().UTC()
	s.mu.Unlock()
	return seq, nil
}
func (m *Manager) Resize(id string, cols, rows uint16) error {
	if err := validateSize(cols, rows); err != nil {
		return err
	}
	s, err := m.lookup(id)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.closing {
		return ErrClosed
	}
	if s.cols == cols && s.rows == rows {
		return nil
	}
	if err := s.process.Resize(cols, rows); err != nil {
		return errors.New("terminal resize failed")
	}
	s.cols, s.rows = cols, rows
	s.lastInput = time.Now().UTC()
	return nil
}
func (m *Manager) Read(id string, after uint64, limit int) (Output, error) {
	s, err := m.lookup(id)
	if err != nil {
		return Output{}, err
	}
	if limit <= 0 || limit > 64<<10 {
		limit = 64 << 10
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if after > s.next {
		return Output{}, ErrCursor
	}
	start := after
	truncated := start < s.start
	if truncated {
		start = s.start
	}
	end := s.next
	if end-start > uint64(limit) {
		end = start + uint64(limit)
	}
	data := append([]byte(nil), s.output[int(start-s.start):int(end-s.start)]...)
	return Output{State: m.stateLocked(s), Data: data, Start: start, Next: end, Truncated: truncated}, nil
}
func (m *Manager) Close(id, reason string) error {
	s, err := m.lookup(id)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.closed || s.closing {
		s.mu.Unlock()
		return nil
	}
	s.closing = true
	s.reason = reason
	if !validCloseReason(s.reason) {
		s.reason = "closed"
	}
	if len(s.reason) > 128 {
		s.reason = "closed"
	}
	s.mu.Unlock()
	s.stopOnce.Do(func() { close(s.stop) })
	s.process.Stop()
	return nil
}
func (m *Manager) Shutdown() {
	if m == nil {
		return
	}
	m.stopOnce.Do(func() {
		close(m.done)
		m.mu.Lock()
		ids := make([]string, 0, len(m.sessions))
		for id := range m.sessions {
			ids = append(ids, id)
		}
		m.mu.Unlock()
		for _, id := range ids {
			_ = m.Close(id, "manager_shutdown")
		}
	})
}
func (m *Manager) janitor() {
	timer := time.NewTicker(100 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case <-m.done:
			return
		case now := <-timer.C:
			m.mu.Lock()
			expired := map[string]string{}
			for id, s := range m.sessions {
				s.mu.Lock()
				if s.closed {
					if now.Sub(s.closedAt) >= m.cfg.RetainClosed {
						delete(m.sessions, id)
					}
				} else if now.Sub(s.started) >= m.cfg.MaxLifetime {
					expired[id] = "lifetime_limit"
				} else if now.Sub(s.lastInput) >= m.cfg.IdleTimeout {
					expired[id] = "idle_timeout"
				}
				s.mu.Unlock()
			}
			m.mu.Unlock()
			for id, reason := range expired {
				_ = m.Close(id, reason)
			}
		}
	}
}

func validCloseReason(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
