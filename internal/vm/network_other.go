//go:build !linux

package vm

import "os"

func openTap(string) (*os.File, error) { return nil, errLinuxOnly }

func tunAvailable() error { return errLinuxOnly }
