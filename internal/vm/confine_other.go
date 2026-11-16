//go:build !linux

package vm

import (
	"errors"
	"os"
	"syscall"
)

var errLinuxOnly = errors.New("the vm driver confines hypervisors with Linux facilities")

func confinedProcAttr(uint32, uint32, []uint32, *os.File) (*syscall.SysProcAttr, error) {
	return nil, errLinuxOnly
}

func landlockABI() (int, error) { return 0, errLinuxOnly }
