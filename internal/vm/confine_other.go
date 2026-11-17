//go:build !linux

package vm

import (
	"errors"
	"net"
)

var errLinuxOnly = errors.New("the vm driver confines hypervisors with Linux facilities")

func landlockABI() (int, error) { return 0, errLinuxOnly }

func socketOwner(net.Conn) (uint32, error) { return 0, errLinuxOnly }

func seccompAvailable() error { return errLinuxOnly }

func mountSocketDir(string) error   { return errLinuxOnly }
func unmountSocketDir(string) error { return errLinuxOnly }
func probeSocketDir(string) error   { return errLinuxOnly }
