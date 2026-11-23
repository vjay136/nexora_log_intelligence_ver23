//go:build !linux

package nodeterminal

func CheckRuntime(Config) error { return ErrUnsupported }
