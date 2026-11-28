package run

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The exec wrapper runs inside whatever image the run uses, so it must work
// with BusyBox's `timeout` (Alpine) as well as coreutils'. These stand-ins
// accept exactly what each real tool accepts and report a deadline kill the
// way each real tool does, and the script runs in a real shell.
func TestExecTimeoutScriptWorksWithBusyBoxAndCoreutils(t *testing.T) {
	// Each stand-in: refuses any option but `-k N` (BusyBox has no long
	// options), then either runs the command or, when the command is
	// "deadline", sleeps past the duration and exits as that tool does
	// after TERMing it at the deadline.
	standIn := func(deadlineExit int) string {
		return "#!/bin/sh\n" +
			"[ \"$1\" = -k ] || { echo \"timeout: unrecognized option: $1\" >&2; exit 1; }\n" +
			"case \"$2\" in *[!0-9]*) echo bad kill secs >&2; exit 1;; esac\n" +
			"secs=$3; shift 3\n" +
			"case \"$secs\" in *[!0-9]*) echo bad secs >&2; exit 1;; esac\n" +
			"if [ \"$3\" = deadline ]; then sleep $((secs + 1)); exit " + strconv.Itoa(deadlineExit) + "; fi\n" +
			"\"$@\"\n"
	}
	tools := []struct {
		name         string
		deadlineExit int
	}{
		{"busybox", 143}, // the watcher TERMs the command itself
		{"coreutils", 124},
	}
	for _, tool := range tools {
		t.Run(tool.name, func(t *testing.T) {
			bin := t.TempDir()
			if err := os.WriteFile(filepath.Join(bin, "timeout"), []byte(standIn(tool.deadlineExit)), 0o755); err != nil {
				t.Fatal(err)
			}
			run := func(secs, cmd string) (int, string) {
				c := exec.Command("sh", "-c", execTimeoutScript, secs, "sh", "-c", cmd)
				c.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
				out, err := c.CombinedOutput()
				var exit *exec.ExitError
				if errors.As(err, &exit) {
					return exit.ExitCode(), string(out)
				}
				if err != nil {
					t.Fatal(err)
				}
				return 0, string(out)
			}

			if code, out := run("5", "echo ok; exit 7"); code != 7 || strings.TrimSpace(out) != "ok" {
				t.Errorf("a command's own exit: code %d, output %q; want 7 and ok", code, out)
			}
			if code, _ := run("5", "exit 143"); code != 143 {
				t.Errorf("a command's own 143 before the deadline: code %d, want 143 passed through", code)
			}
			start := time.Now()
			code, out := run("1", "deadline")
			if code != 124 {
				t.Errorf("a kill at the deadline: code %d (output %q), want 124 so it is classified as a timeout", code, out)
			}
			if c, timedOut := classifyExit(code, time.Second); !timedOut {
				t.Errorf("classifyExit(%d) did not call it a timeout", c)
			}
			if time.Since(start) > 10*time.Second {
				t.Errorf("deadline case took %s", time.Since(start))
			}
		})
	}

	// No timeout tool at all: refuse rather than run unbounded.
	empty := t.TempDir()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	c := exec.Command(sh, "-c", execTimeoutScript, "5", "sh", "-c", "echo ran")
	c.Env = []string{"PATH=" + empty}
	out, _ := c.CombinedOutput()
	if c.ProcessState.ExitCode() != 127 || strings.Contains(string(out), "ran") {
		t.Errorf("no timeout tool: exit %d, output %q; want 127 and the command not run", c.ProcessState.ExitCode(), out)
	}
}
