//go:build !linux

package terminalrpc

import (
	"errors"
	"os"
)

func openHostPolicy(string) (*os.File, error) { return nil, errors.New("node terminal requires Linux") }
