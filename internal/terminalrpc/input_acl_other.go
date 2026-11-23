//go:build !linux

package terminalrpc

import (
	"context"
	"errors"
)

const InputDirectory = "/var/log/nli/input"

func refreshInputACL(context.Context) error { return errors.New("node terminal requires Linux") }
