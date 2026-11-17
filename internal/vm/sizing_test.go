package vm

import (
	"fmt"
	"strings"
	"testing"
)

func TestSizingWarnings(t *testing.T) {
	host := func(conntrack, aio int64, files uint64) sizingHost {
		return sizingHost{
			sysctl: func(path string) (int64, error) {
				switch {
				case strings.HasSuffix(path, "nf_conntrack_max"):
					return conntrack, nil
				case strings.HasSuffix(path, "aio-max-nr"):
					return aio, nil
				}
				return 0, fmt.Errorf("no %s", path)
			},
			nofile: func() (uint64, error) { return files, nil },
		}
	}
	config := Config{MaxRuns: 64, NetConnections: 4096, Warm: WarmConfig{Sizes: []WarmSize{{2, 2048, 3}, {4, 8192, 1}}}}
	needs := config.Needs()
	if needs.Conntrack != 64*4096 || needs.Files != 64*4096*2+(64+4)*filesPerVM+filesBase || needs.AIO != (64+4)*aioPerVM {
		t.Fatalf("needs: %+v", needs)
	}
	if warnings := sizingWarnings(config, host(needs.Conntrack, needs.AIO, uint64(needs.Files))); len(warnings) != 0 {
		t.Fatalf("a host that is exactly big enough: %v", warnings)
	}
	warnings := sizingWarnings(config, host(262144-1, 65536, 1024))
	var texts []string
	for _, warning := range warnings {
		texts = append(texts, warning.text)
	}
	joined := strings.Join(texts, "\n")
	for _, want := range []string{"nf_conntrack_max is 262143", "RLIMIT_NOFILE) is 1024"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no warning about %q in:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "aio-max-nr is 65536") {
		t.Errorf("aio: 68 VMs need %d, 65536 is enough:\n%s", needs.AIO, joined)
	}
	// Without a limit on runs, only the pool's AIO is checked, and the
	// operator is told why the rest is not.
	unbounded := Config{NetConnections: 4096, Warm: config.Warm}
	warnings = sizingWarnings(unbounded, host(1, 1, 1))
	if len(warnings) != 2 || !strings.Contains(warnings[0].text, "aio-max-nr is 1") || !strings.Contains(warnings[1].text, "no --vm-max-runs") {
		t.Fatalf("unbounded: %+v", warnings)
	}
}
