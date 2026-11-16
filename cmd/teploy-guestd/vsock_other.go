//go:build !linux

package main

import (
	"errors"
	"io"
)

// vsock is the guest side of a Linux VM. On other systems the agent only
// serves --listen-unix, which is what its tests use.
func listenVsock(uint32) (func() (io.ReadWriteCloser, error), error) {
	return nil, errors.New("vsock needs Linux; use --listen-unix")
}
