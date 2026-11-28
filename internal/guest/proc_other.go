//go:build !unix

package guest

import (
	"os"
	"os/exec"
)

// Without process groups only the shell itself can be ended. The agent
// runs on Linux; this exists so the package builds everywhere.
func ownProcessGroup(*exec.Cmd) {}

func terminateGroup(cmd *exec.Cmd) { killGroup(cmd) }

func killGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

func groupGone(cmd *exec.Cmd) bool { return cmd.Process == nil }

func exitCode(state *os.ProcessState) int { return state.ExitCode() }
