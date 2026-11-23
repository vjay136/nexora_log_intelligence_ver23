// Package terminalrpc provides the local, opt-in Unix-socket boundary between
// NLI services and the node terminal broker. It has no network listener.
package terminalrpc

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"nexora.local/nli-v20/internal/nodeterminal"
)

const DefaultSocket = "/run/nli-terminal/terminal.sock"
const DefaultConfig = "/etc/nli/node-terminal.json"

type HostConfig struct {
	Enabled              bool   `json:"enabled"`
	AllowInputWrite      *bool  `json:"allow_input_write,omitempty"`
	PrivilegeMode        string `json:"privilege_mode"`
	MaxSessions          int    `json:"max_sessions,omitempty"`
	IdleTimeoutSeconds   int    `json:"idle_timeout_seconds,omitempty"`
	LifetimeSeconds      int    `json:"lifetime_seconds,omitempty"`
	MaxOutputBytes       int    `json:"max_output_bytes,omitempty"`
	OutputBytesPerSecond int    `json:"output_bytes_per_second,omitempty"`
}

// LoadHostConfig refuses symlinks, non-root ownership and group/world access.
// A web request can never override this host-owned privilege policy.
func LoadHostConfig(path string) (HostConfig, error) {
	var cfg HostConfig
	file, err := openHostPolicy(path)
	if err != nil {
		return cfg, errors.New("terminal host policy is unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return cfg, errors.New("terminal host policy is unavailable")
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 || !rootOwned(info) {
		return cfg, errors.New("terminal host policy must be a root-owned regular file with mode 0600")
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(data) > 4096 {
		return cfg, errors.New("terminal host policy could not be read")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cfg) != nil || decoder.Decode(new(any)) != io.EOF {
		return cfg, errors.New("terminal host policy is invalid")
	}
	return NormalizeHostConfig(cfg)
}

func NormalizeHostConfig(cfg HostConfig) (HostConfig, error) {
	if cfg.PrivilegeMode == "" {
		cfg.PrivilegeMode = "operator"
	}
	if cfg.PrivilegeMode != "operator" {
		return cfg, errors.New("production terminal privilege_mode must be operator")
	}
	if cfg.AllowInputWrite == nil {
		enabled := true
		cfg.AllowInputWrite = &enabled
	}
	if cfg.MaxSessions == 0 {
		cfg.MaxSessions = 4
	}
	if cfg.MaxSessions < 1 || cfg.MaxSessions > 16 {
		return cfg, errors.New("terminal max_sessions must be 1..16")
	}
	if cfg.IdleTimeoutSeconds == 0 {
		cfg.IdleTimeoutSeconds = 300
	}
	if cfg.IdleTimeoutSeconds < 30 || cfg.IdleTimeoutSeconds > 3600 {
		return cfg, errors.New("terminal idle timeout must be 30..3600 seconds")
	}
	if cfg.LifetimeSeconds == 0 {
		cfg.LifetimeSeconds = 1800
	}
	if cfg.LifetimeSeconds < 60 || cfg.LifetimeSeconds > 3600 || cfg.IdleTimeoutSeconds > cfg.LifetimeSeconds {
		return cfg, errors.New("terminal lifetime must be 60..3600 seconds and cover the idle timeout")
	}
	if cfg.MaxOutputBytes == 0 {
		cfg.MaxOutputBytes = 256 << 10
	}
	if cfg.MaxOutputBytes < 4096 || cfg.MaxOutputBytes > 1<<20 {
		return cfg, errors.New("terminal output buffer must be 4096..1048576 bytes")
	}
	if cfg.OutputBytesPerSecond == 0 {
		cfg.OutputBytesPerSecond = 128 << 10
	}
	if cfg.OutputBytesPerSecond < 4096 || cfg.OutputBytesPerSecond > 1<<20 {
		return cfg, errors.New("terminal output rate must be 4096..1048576 bytes per second")
	}
	return cfg, nil
}

func (cfg HostConfig) ManagerConfig() nodeterminal.Config {
	username := "nli-terminal"
	return nodeterminal.Config{Enabled: cfg.Enabled, Username: username, AllowRoot: false, Shell: "/bin/bash", WorkDir: InputDirectory, MaxSessions: cfg.MaxSessions, MaxOutputBytes: cfg.MaxOutputBytes, MaxInputBytes: 16 << 10, OutputBytesPerSecond: cfg.OutputBytesPerSecond, IdleTimeout: time.Duration(cfg.IdleTimeoutSeconds) * time.Second, MaxLifetime: time.Duration(cfg.LifetimeSeconds) * time.Second, Systemd: true}
}
