//go:build !linux

package terminalrpc

import (
	"net"
	"os"
)

func rootOwned(os.FileInfo) bool { return false }
func trustedPeer(net.Conn) bool  { return false }
