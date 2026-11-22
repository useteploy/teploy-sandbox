//go:build !linux

package access

import (
	"errors"
	"net"
)

const peerCredentialsSupported = false

func peerCredentials(net.Conn) (int, int, error) {
	return 0, 0, errors.New("unix socket peer credentials are only read on Linux")
}
