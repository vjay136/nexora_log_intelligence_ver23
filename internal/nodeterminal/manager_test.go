package nodeterminal

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestDisabledAndBounds(t *testing.T) {
	m, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Shutdown()
	if _, err = m.Open("session-1234567890", 80, 24); !errors.Is(err, ErrDisabled) {
		t.Fatal("disabled policy spawned terminal", err)
	}
	for _, cfg := range []Config{{MaxSessions: 17}, {MaxOutputBytes: 1}, {MaxInputBytes: 1}, {OutputBytesPerSecond: 1}, {MaxLifetime: 2 * time.Hour}} {
		if _, err := New(cfg); err == nil {
			t.Fatal("unbounded configuration accepted", cfg)
		}
	}
	if validateSize(1, 24) == nil || validateSize(80, 0) == nil {
		t.Fatal("invalid terminal dimensions accepted")
	}
}
func TestBoundedOutputOffsetsAndImmutability(t *testing.T) {
	s := &session{id: "session-1234567890", started: time.Now(), lastInput: time.Now()}
	m := &Manager{cfg: Config{}, sessions: map[string]*session{s.id: s}}
	s.appendOutput([]byte("0123456789"), 8)
	if s.start != 2 || s.next != 10 || string(s.output) != "23456789" {
		t.Fatal("initial ring", s)
	}
	s.appendOutput([]byte("abc"), 8)
	out, err := m.Read(s.id, 0, 4)
	if err != nil || !out.Truncated || out.Start != 5 || out.Next != 9 || string(out.Data) != "5678" {
		t.Fatalf("gap/cursor=%+v %v", out, err)
	}
	out.Data[0] = 'X'
	again, _ := m.Read(s.id, 5, 4)
	if bytes.Equal(out.Data, again.Data) {
		t.Fatal("output aliases ring")
	}
	if _, err := m.Read(s.id, 14, 4); !errors.Is(err, ErrCursor) {
		t.Fatal("future cursor accepted")
	}
	s.appendOutput(bytes.Repeat([]byte{'z'}, 10000), 8)
	if len(s.output) != 8 || cap(s.output) > 16 || s.start != s.next-8 {
		t.Fatal("ring grew beyond bound")
	}
}
