package run

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// LockDirectory prevents two daemons from reconciling or publishing the same
// cache root. Hold the descriptor for the entire serving lifetime.
func LockDirectory(dir string) (*os.File, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, ".sandbox-owner.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("sandbox directory already owned: %w", err)
	}
	return f, nil
}

// LiveCacheDirs conservatively retains bind mounts of ALL containers, including
// unrelated workloads. Inspection must succeed before deleting orphan volumes.
func (d *DockerRuntime) LiveCacheDirs(ctx context.Context) (map[string]bool, error) {
	out, err := exec.CommandContext(ctx, d.bin(), "ps", "-aq").Output()
	if err != nil {
		return nil, err
	}
	ids := strings.Fields(string(out))
	live := map[string]bool{}
	if len(ids) == 0 {
		return live, nil
	}
	out, err = exec.CommandContext(ctx, d.bin(), append([]string{"inspect"}, ids...)...).Output()
	if err != nil {
		return nil, err
	}
	var containers []struct {
		Mounts []struct{ Type, Source string }
	}
	if err := json.Unmarshal(out, &containers); err != nil {
		return nil, err
	}
	for _, c := range containers {
		for _, m := range c.Mounts {
			if m.Type == "bind" {
				live[filepath.Clean(m.Source)] = true
			}
		}
	}
	return live, nil
}

// ReconcileRuns is startup-only under LockDirectory, before accepting requests.
// Unknown names and every live mount are retained; only daemon ULID directories
// with no Docker owner are reclaimed. A failed inspect must never reach here.
func (c *CacheStore) ReconcileRuns(live map[string]bool) (int, error) {
	c.transaction.Lock()
	defer c.transaction.Unlock()
	entries, err := os.ReadDir(filepath.Join(c.Root, "runs"))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || len(name) != 26 || strings.Trim(name, "0123456789abcdefghjkmnpqrstvwxyz") != "" {
			continue
		}
		path := c.runDir(name)
		if live[filepath.Clean(path)] {
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}
