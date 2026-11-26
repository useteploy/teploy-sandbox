//go:build !linux

package vm

func realMountOps() mountOps {
	return mountOps{
		bind:   func(string, string) error { return errLinuxOnly },
		unbind: func(string) error { return errLinuxOnly },
	}
}

func mountSharedDir(string) error { return errLinuxOnly }
