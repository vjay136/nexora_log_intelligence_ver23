//go:build !linux

package nodeterminal

func resolveAccount(cfg Config) (platformAccount, Config, error) {
	return platformAccount{}, cfg, ErrUnsupported
}
func startProcess(Config, platformAccount, string, uint16, uint16) (localProcess, error) {
	return nil, ErrUnsupported
}

func cleanupSystemdSessions() error { return ErrUnsupported }
