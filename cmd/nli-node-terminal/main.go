// nli-node-terminal is an optional local-only PTY broker. It never listens on a
// TCP port; the existing authenticated NLI connection relays client sessions.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"nexora.local/nli-v20/internal/engine"
	"nexora.local/nli-v20/internal/nodeterminal"
	"nexora.local/nli-v20/internal/terminalaccess"
	"nexora.local/nli-v20/internal/terminalrpc"
)

func main() {
	if handled, err := terminalaccess.RunIfHelper(); handled {
		if err != nil {
			fail(err)
		}
		return
	}
	if err := run(); err != nil {
		fail(err)
	}
}
func run() error {
	configPath := flag.String("config", terminalrpc.DefaultConfig, "root-owned terminal host policy")
	socket := flag.String("socket", terminalrpc.DefaultSocket, "local Unix socket")
	version := flag.Bool("version", false, "print release identity")
	check := flag.Bool("check-config", false, "validate host policy without starting a terminal")
	flag.Parse()
	if *version {
		fmt.Println("nli-node-terminal", engine.ReleaseID)
		return nil
	}
	cfg, err := terminalrpc.LoadHostConfig(*configPath)
	if err != nil {
		return err
	}
	if *check {
		_ = json.NewEncoder(os.Stdout).Encode(cfg)
		return nil
	}
	manager, err := nodeterminal.New(cfg.ManagerConfig())
	if err != nil {
		return err
	}
	defer manager.Shutdown()
	if !cfg.Enabled {
		fmt.Fprintln(os.Stderr, "nli-node-terminal: disabled by host policy")
		return nil
	}
	server, err := terminalrpc.NewServer(manager, cfg)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	return server.Serve(ctx, *socket, "nli-terminal-api")
}
func fail(err error) { fmt.Fprintln(os.Stderr, "nli-node-terminal:", err); os.Exit(1) }
