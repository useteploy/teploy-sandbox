//go:build !linux

package vm

import "os"

func openTap(string) (*os.File, error) { return nil, errLinuxOnly }

func tunAvailable() error { return errLinuxOnly }

func inNamespace(name string, fn func() error) error {
	if name == "" {
		return fn()
	}
	return errLinuxOnly
}
