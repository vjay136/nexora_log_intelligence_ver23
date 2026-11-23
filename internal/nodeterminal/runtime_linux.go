//go:build linux

package nodeterminal

import (
	"bytes"
	"errors"
	"fmt"
	"time"
)

// CheckRuntime tests a fresh, private contained PTY without touching any existing
// session. Only a synthetic UID marker is examined; no user input is accepted.
func CheckRuntime(cfg Config) error {
	cfg, err := normalize(cfg)
	if err != nil {
		return err
	}
	account, cfg, err := resolveAccount(cfg)
	if err != nil {
		return err
	}
	cfg.MaxLifetime = 5 * time.Second
	p, err := startProcess(cfg, account, fmt.Sprintf("runtime-check-%d", time.Now().UnixNano()), 80, 24)
	if err != nil {
		return err
	}
	defer p.Stop()
	done := make(chan int, 1)
	go func() { done <- p.Wait() }()
	ready := make(chan bool, 1)
	go func() {
		var output []byte
		buf := make([]byte, 2048)
		expected := []byte(fmt.Sprintf("\r\nNLI_RUNTIME_UID=%d\r\n", account.uid))
		for len(output) < 16384 {
			n, e := p.Read(buf)
			output = append(output, buf[:n]...)
			if bytes.Contains(output, expected) {
				ready <- true
				return
			}
			if e != nil {
				break
			}
		}
		ready <- false
	}()
	if _, err = p.Write([]byte("printf '\\nNLI_RUNTIME_UID=%s\\n' \"$(id -u)\"; exit\n")); err != nil {
		return errors.New("terminal runtime input check failed")
	}
	timer := time.NewTimer(4 * time.Second)
	defer timer.Stop()
	select {
	case ok := <-ready:
		if ok {
			return nil
		}
	case <-timer.C:
		return errors.New("terminal runtime check timed out; inspect nli-node-terminal journal and host security diagnostics")
	}
	select {
	case code := <-done:
		return fmt.Errorf("terminal runtime could not start a dedicated shell (exit %d); inspect host security diagnostics", code)
	case <-timer.C:
		return errors.New("terminal runtime check failed before the dedicated shell became ready")
	}
}
