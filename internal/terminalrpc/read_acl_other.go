//go:build !linux

package terminalrpc

import (
	"context"
	"errors"
)

func refreshReadAccess(context.Context) error { return errors.New("node terminal requires Linux") }
