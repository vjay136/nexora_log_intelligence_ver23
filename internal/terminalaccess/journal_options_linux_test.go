//go:build linux

package terminalaccess

import (
	"os/exec"
	"strings"
	"testing"
)

func TestJournalHelperOptionsExistInActualJournalctl(t *testing.T) {
	executable, err := exec.LookPath("journalctl")
	if err != nil {
		t.Skip("journalctl is not installed in this test environment")
	}
	help, err := exec.Command(executable, "--help").Output()
	if err != nil {
		t.Fatal(err)
	}
	args, err := JournalArgs([]string{"-u", "nli-agent", "-n", "3", "-f", "--since", "1 hour ago", "-o", "json", "-b", "-1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, arg := range args {
		flag := strings.SplitN(arg, "=", 2)[0]
		if strings.HasPrefix(flag, "--") && !strings.Contains(string(help), flag) {
			t.Fatalf("restricted journal helper emits an unsupported journalctl option: %s", flag)
		}
	}
}
