package terminalaccess

import (
	"reflect"
	"strings"
	"testing"
)

func TestSystemctlScope(t *testing.T) {
	for _, args := range [][]string{{"status", "nli-agent"}, {"is-active", "-q", "nli-client-control"}, {"is-enabled", "nli-controller-agent.service"}, {"restart", "nli-agent", "nli-client-control"}, {"daemon-reload"}, {"status", "nli-node-terminal", "-l"}} {
		got, err := SystemctlArgs(args)
		if err != nil {
			t.Fatalf("%q: %v", args, err)
		}
		if got[0] != "--no-pager" || got[1] != "--no-ask-password" {
			t.Fatal(got)
		}
	}
	for _, args := range [][]string{nil, {"status"}, {"restart", "ssh"}, {"status", "nli-*"}, {"status", "../../nli-agent"}, {"restart", "nli-node-terminal"}, {"is-active", "nli-node-terminal"}, {"start", "nli-agent"}, {"stop", "nli-agent"}, {"enable", "nli-agent"}, {"disable", "nli-agent"}, {"daemon-reload", "nli-agent"}, {"restart", "nli-agent", "--now"}, {"status", "nli-agent", "--root=/tmp"}, {"status", "nli-agent\n.service"}, {"restart", "nli-agent", "--quiet"}, {"restart", "nli-agent", "-l"}, {"status", "nli-agent", "--"}} {
		if got, err := SystemctlArgs(args); err == nil {
			t.Fatalf("accepted %q: %q", args, got)
		}
	}
}
func TestJournalScope(t *testing.T) {
	got, err := JournalArgs([]string{"-u", "nli-agent", "-n50", "-f", "--since", "1 hour ago", "-o", "json", "-b", "-1"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--no-pager", "--no-ask-password", "--lines=50", "--unit=nli-agent.service", "--follow", "--since=1 hour ago", "--output=json", "--boot=-1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%q", got)
	}
	for _, args := range [][]string{{"--unit=nli-client-control", "--lines=1000"}, {"-unli-agent", "-b"}, {"-u", "nli-node-terminal", "--no-pager"}} {
		if _, err := JournalArgs(args); err != nil {
			t.Fatal(args, err)
		}
	}
	for _, args := range [][]string{nil, {"-u", "sshd"}, {"-u", "nli-*"}, {"-u"}, {"-u", "nli-agent", "--file=/etc/shadow"}, {"-u", "nli-agent", "--directory=/tmp"}, {"-u", "nli-agent", "--vacuum-time=1s"}, {"-u", "nli-agent", "--output=export"}, {"-u", "nli-agent", "-n0"}, {"-u", "nli-agent", "-n1001"}, {"-u", "nli-agent", "--since"}, {"-u", "nli-agent", "--since", strings.Repeat("x", 129)}, {"-u", "nli-agent", "--boot=1"}, {"-u", "nli-agent", "--boot=-11"}, {"-u", "nli-agent", "MESSAGE=secret"}, {"-u", "nli-agent", "--pager-end"}, {"-u", "nli-agent", "-n", "all"}} {
		if got, err := JournalArgs(args); err == nil {
			t.Fatalf("accepted %q: %q", args, got)
		}
	}
}
func TestHelperInvocation(t *testing.T) {
	for _, tc := range []struct {
		argv []string
		kind string
		args []string
	}{
		{[]string{"/usr/libexec/nli-terminal/bin/sudo", "-n", "systemctl", "status", "nli-agent"}, "--systemctl", []string{"status", "nli-agent"}},
		{[]string{"sudo", "journalctl", "-u", "nli-agent"}, "--journal", []string{"-u", "nli-agent"}},
		{[]string{"systemctl", "status", "nli-agent"}, "--systemctl", []string{"status", "nli-agent"}},
		{[]string{HelperBinary, "--journal", "-u", "nli-agent"}, "--journal", []string{"-u", "nli-agent"}},
		{[]string{HelperBinary, "--config", "/etc/nli/terminal.json"}, "", []string{"--config", "/etc/nli/terminal.json"}},
	} {
		kind, args, err := helperInvocation(tc.argv)
		if err != nil || kind != tc.kind || !reflect.DeepEqual(args, tc.args) {
			t.Fatalf("%q: %s %q %v", tc.argv, kind, args, err)
		}
	}
	for _, args := range [][]string{{"sudo"}, {"sudo", "bash"}, {"sudo", "-u", "root", "systemctl", "status", "nli-agent"}, {"sudo", "/usr/bin/systemctl", "status", "nli-agent"}, {"sudo", "-E", "journalctl", "-u", "nli-agent"}} {
		if _, _, err := helperInvocation(args); err == nil {
			t.Fatal("accepted", args)
		}
	}
}
