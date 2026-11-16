//go:build !linux

package vm

import (
	"errors"
	"net"
	"os"
	"syscall"
)

var errLinuxOnly = errors.New("the vm driver confines hypervisors with Linux facilities")

func confinedProcAttr(uint32, uint32, []uint32, *os.File) (*syscall.SysProcAttr, error) {
	return nil, errLinuxOnly
}

func landlockABI() (int, error) { return 0, errLinuxOnly }

func socketOwner(net.Conn) (uint32, error) { return 0, errLinuxOnly }
