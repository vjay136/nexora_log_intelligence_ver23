//go:build linux

package nodeterminal

import "testing"

func TestRuntimeCheckRunsDedicatedSyntheticShellWithoutClosingExistingSession(t *testing.T) {
	m := rootTestManager(t, nil)
	id := "existing-runtime-check-12345"
	if _, err := m.Open(id, 80, 24); err != nil {
		t.Fatal(err)
	}
	if err := CheckRuntime(m.cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Input(id, 1, []byte("printf 'EXISTING_STILL_LIVE\\n'\n")); err != nil {
		t.Fatal(err)
	}
	waitOutput(t, m, id, "EXISTING_STILL_LIVE\r\n")
}
