//go:build !linux

package vm

import (
	"os"
	"os/exec"
)

func jailCommand(jailSpec, *os.File, string, []string) (*exec.Cmd, error) {
	return nil, errLinuxOnly
}
