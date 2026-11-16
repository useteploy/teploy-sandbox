//go:build unix

package guest

import (
	"os"
	"os/exec"
	"syscall"
)

// ownProcessGroup starts the command in its own process group, so a
// timeout or a vanished caller ends the whole tree and nothing else.
func ownProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func terminateGroup(cmd *exec.Cmd) { signalGroup(cmd, syscall.SIGTERM) }
func killGroup(cmd *exec.Cmd)      { signalGroup(cmd, syscall.SIGKILL) }

func signalGroup(cmd *exec.Cmd, sig syscall.Signal) {
	if cmd.Process != nil {
		// Negative pid: the group the command leads.
		_ = syscall.Kill(-cmd.Process.Pid, sig)
	}
}

// exitCode is the shell's view of how a process ended: its exit status, or
// 128 plus the signal that killed it.
func exitCode(state *os.ProcessState) int {
	if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	return state.ExitCode()
}
