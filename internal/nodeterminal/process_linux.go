//go:build linux

package nodeterminal

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type ptyProcess struct {
	master *os.File
	cmd    *exec.Cmd
	once   sync.Once
	unit   string
}

func resolveAccount(cfg Config) (platformAccount, Config, error) {
	if cfg.Username == "" {
		return platformAccount{}, cfg, errors.New("enabled terminal requires an explicit host account")
	}
	account, err := user.Lookup(cfg.Username)
	if err != nil {
		return platformAccount{}, cfg, errors.New("configured terminal account does not exist")
	}
	uid, e1 := strconv.ParseUint(account.Uid, 10, 32)
	gid, e2 := strconv.ParseUint(account.Gid, 10, 32)
	if e1 != nil || e2 != nil {
		return platformAccount{}, cfg, errors.New("configured terminal account has invalid ids")
	}
	if uid == 0 && !cfg.AllowRoot {
		return platformAccount{}, cfg, errors.New("root terminal requires explicit host allow_root policy")
	}
	if cfg.Systemd && os.Geteuid() != 0 {
		return platformAccount{}, cfg, errors.New("contained terminal requires the root broker")
	}
	if os.Geteuid() != 0 && os.Geteuid() != int(uid) {
		return platformAccount{}, cfg, errors.New("terminal broker cannot switch to configured account")
	}
	if cfg.Shell != "/bin/bash" && cfg.Shell != "/usr/bin/bash" {
		return platformAccount{}, cfg, errors.New("terminal shell must be the host bash executable")
	}
	info, err := os.Stat(cfg.Shell)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Sys().(*syscall.Stat_t).Uid != 0 {
		return platformAccount{}, cfg, errors.New("terminal bash executable must not be group/other writable")
	}
	if cfg.WorkDir == "" {
		cfg.WorkDir = account.HomeDir
		if info, e := os.Stat("/var/log/nli/input"); e == nil && info.IsDir() {
			cfg.WorkDir = "/var/log/nli/input"
		}
	}
	if !filepath.IsAbs(cfg.WorkDir) {
		return platformAccount{}, cfg, errors.New("terminal working directory must be absolute")
	}
	cfg.WorkDir = filepath.Clean(cfg.WorkDir)
	info, err = os.Stat(cfg.WorkDir)
	if err != nil || !info.IsDir() {
		return platformAccount{}, cfg, errors.New("terminal working directory does not exist")
	}
	groups, err := account.GroupIds()
	if err != nil {
		return platformAccount{}, cfg, errors.New("terminal supplementary groups could not be resolved")
	}
	ids := []uint32{}
	for _, group := range groups {
		value, err := strconv.ParseUint(group, 10, 32)
		if err != nil {
			return platformAccount{}, cfg, errors.New("invalid terminal supplementary group")
		}
		ids = append(ids, uint32(value))
	}
	return platformAccount{uid: uint32(uid), gid: uint32(gid), groups: ids, home: account.HomeDir}, cfg, nil
}
func startProcess(cfg Config, account platformAccount, id string, cols, rows uint16) (localProcess, error) {
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("PTY device is unavailable to terminal broker")
	}
	master := os.NewFile(uintptr(fd), "nli-terminal-pty")
	success := false
	defer func() {
		if !success {
			master.Close()
		}
	}()
	if err = unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		return nil, errors.New("PTY unlock failed")
	}
	number, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		return nil, errors.New("PTY number lookup failed")
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, errors.New("PTY slave is unavailable")
	}
	defer slave.Close()
	if err = unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Col: cols, Row: rows}); err != nil {
		return nil, errors.New("PTY initial resize failed")
	}
	environment := []string{"PATH=/usr/libexec/nli-terminal/bin:/usr/local/bin:/usr/bin:/bin", "TERM=xterm-256color", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "HOME=" + account.home, "USER=" + cfg.Username, "LOGNAME=" + cfg.Username, "SHELL=" + cfg.Shell, "HISTFILE=/dev/null", "HISTSIZE=0", "HISTFILESIZE=0", "PS1=" + `\u@\h:\w\$ `}
	unit := ""
	cmd := exec.Command(cfg.Shell, "--noprofile", "--norc", "-i")
	if cfg.Systemd {
		digest := sha256.Sum256([]byte(id))
		unit = fmt.Sprintf("nli-terminal-session-%x.service", digest[:16])
		seconds := int64((cfg.MaxLifetime + time.Second - 1) / time.Second)
		args := []string{"--quiet", "--no-ask-password", "--wait", "--collect", "--pty", "--service-type=exec", "--unit=" + unit, "--uid=" + strconv.FormatUint(uint64(account.uid), 10), "--gid=" + strconv.FormatUint(uint64(account.gid), 10),
			"--property=WorkingDirectory=" + cfg.WorkDir, "--property=RuntimeMaxSec=" + strconv.FormatInt(seconds, 10), "--property=KillMode=control-group", "--property=TimeoutStopSec=3s", "--property=SendSIGKILL=yes", "--property=TasksMax=64", "--property=NoNewPrivileges=false", "--property=MemoryMax=256M", "--property=CPUQuota=50%", "--property=BindsTo=nli-node-terminal.service", "--property=After=nli-node-terminal.service", "/usr/bin/env", "-i"}
		args = append(args, environment...)
		args = append(args, cfg.Shell, "--noprofile", "--norc", "-i")
		cmd = exec.Command("/usr/bin/systemd-run", args...)
	}
	cmd.Dir = cfg.WorkDir
	cmd.Env = environment
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	attr := &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0, Pdeathsig: syscall.SIGKILL}
	if os.Geteuid() == 0 && !cfg.Systemd {
		attr.Credential = &syscall.Credential{Uid: account.uid, Gid: account.gid, Groups: account.groups}
	}
	cmd.SysProcAttr = attr
	if err = cmd.Start(); err != nil {
		return nil, errors.New("terminal shell could not start under configured account")
	}
	success = true
	return &ptyProcess{master: master, cmd: cmd, unit: unit}, nil
}
func (p *ptyProcess) Read(b []byte) (int, error) { return p.master.Read(b) }
func (p *ptyProcess) Write(b []byte) (int, error) {
	_ = p.master.SetWriteDeadline(time.Now().Add(2 * time.Second))
	return p.master.Write(b)
}
func (p *ptyProcess) Resize(cols, rows uint16) error {
	return unix.IoctlSetWinsize(int(p.master.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Col: cols, Row: rows})
}
func (p *ptyProcess) Wait() int {
	err := p.cmd.Wait()
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	return -1
}
func (p *ptyProcess) Stop() {
	p.once.Do(func() {
		if p.unit != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = exec.CommandContext(ctx, "/usr/bin/systemctl", "stop", "--no-block", p.unit).Run()
			cancel()
		}
		pid := p.cmd.Process.Pid
		if p.unit == "" {
			killSession(pid)
		}
		_ = p.master.Close()
		_ = p.cmd.Process.Kill()
	})
}

// Bash job control places foreground jobs in separate groups within this SID.
// Explicitly detached sessions require a host cgroup boundary for containment;
// this routine deliberately makes no sandbox claim for arbitrary shell commands.
func killSession(sid int) {
	entries, _ := os.ReadDir("/proc")
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		handle, openErr := unix.PidfdOpen(pid, 0)
		if openErr != nil {
			continue
		}
		data, err := os.ReadFile("/proc/" + entry.Name() + "/stat")
		if err != nil {
			_ = unix.Close(handle)
			continue
		}
		end := strings.LastIndexByte(string(data), ')')
		if end < 0 {
			_ = unix.Close(handle)
			continue
		}
		fields := strings.Fields(string(data)[end+1:])
		if len(fields) < 4 {
			_ = unix.Close(handle)
			continue
		}
		session, _ := strconv.Atoi(fields[3])
		if session == sid {
			_ = unix.PidfdSendSignal(handle, unix.SIGKILL, nil, 0)
		}
		_ = unix.Close(handle)
	}
}

// Only exact units created by this package are stopped, never an operator unit
// with a merely similar prefix. This also runs for a disabled production host
// policy so a broker restart cannot revive stale sessions.
func cleanupSystemdSessions() error {
	if os.Geteuid() != 0 {
		return errors.New("contained terminal requires the root broker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "list-units", "--all", "--type=service", "--plain", "--no-legend", "nli-terminal-session-*.service").Output()
	if err != nil {
		return errors.New("terminal systemd containment is unavailable")
	}
	units := []string{}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		part := strings.TrimSuffix(strings.TrimPrefix(name, "nli-terminal-session-"), ".service")
		if len(part) != 32 || "nli-terminal-session-"+part+".service" != name {
			continue
		}
		valid := true
		for _, c := range part {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				valid = false
			}
		}
		if valid {
			units = append(units, name)
		}
	}
	if len(units) > 256 {
		return errors.New("terminal stale-session capacity exceeded")
	}
	if len(units) > 0 {
		args := append([]string{"stop", "--"}, units...)
		if exec.CommandContext(ctx, "/usr/bin/systemctl", args...).Run() != nil {
			return errors.New("stale terminal sessions could not be stopped")
		}
	}
	return nil
}
