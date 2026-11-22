package run

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// DiskReporter is implemented by a driver that can say how full the
// storage its runs live on is: GET /v1/capacity's `disk`. Optional, like
// the other driver hooks; an error leaves the field out.
type DiskReporter interface {
	Disk(ctx context.Context) (*DiskUsage, error)
}

// DiskUsage is the storage runs and snapshots are on.
type DiskUsage struct {
	// Kind is "zfs-pool" (the VM driver's pool) or "docker-data-dir"
	// (the filesystem holding Docker's data root).
	Kind string `json:"kind"`
	// Name is the pool, or the data root's path.
	Name      string `json:"name"`
	UsedBytes int64  `json:"usedBytes"`
	FreeBytes int64  `json:"freeBytes"`
}

// Disk reports the filesystem Docker's data root is on: where images,
// snapshots and every container's writable layer live. It asks the
// docker CLI for the path and reads the filesystem from this process, so
// it is only right for a daemon on the Docker host itself (as serve runs);
// a path this process cannot see is an error and the field is left out.
func (d *DockerRuntime) Disk(ctx context.Context) (*DiskUsage, error) {
	root, err := d.dataRoot(ctx)
	if err != nil {
		return nil, err
	}
	used, free, err := statfsUsage(root)
	if err != nil {
		return nil, err
	}
	return &DiskUsage{Kind: "docker-data-dir", Name: root, UsedBytes: used, FreeBytes: free}, nil
}

// Disk is the driver's storage, when it can report it; nil otherwise.
func (m *Manager) Disk(ctx context.Context) *DiskUsage {
	reporter, ok := m.runtime.(DiskReporter)
	if !ok {
		return nil
	}
	usage, err := reporter.Disk(ctx)
	if err != nil {
		m.log.Debug("disk usage unavailable", "error", err)
		return nil
	}
	return usage
}

// dataRootTimeout bounds the one `docker info` that callers share.
const dataRootTimeout = 30 * time.Second

// rootLookup is a `docker info` under way, shared by every caller that
// arrives while it runs.
type rootLookup struct {
	done chan struct{}
	root string
	err  error
}

// dataRoot asks docker for its data root once; a failure is not
// remembered, so a Docker that comes up later is found. No lock is held
// across the command: at most one runs at a time, on its own deadline,
// and each caller waits for it only as long as its own context allows,
// so a wedged Docker costs every capacity call its own timeout at most
// rather than a queue behind the others.
func (d *DockerRuntime) dataRoot(ctx context.Context) (string, error) {
	d.rootMu.Lock()
	if d.rootDir != "" {
		root := d.rootDir
		d.rootMu.Unlock()
		return root, nil
	}
	lookup := d.rootLookup
	if lookup == nil {
		lookup = &rootLookup{done: make(chan struct{})}
		d.rootLookup = lookup
		go d.lookUpDataRoot(context.WithoutCancel(ctx), lookup)
	}
	d.rootMu.Unlock()
	select {
	case <-lookup.done:
		return lookup.root, lookup.err
	case <-ctx.Done():
		return "", fmt.Errorf("docker info: %w", ctx.Err())
	}
}

func (d *DockerRuntime) lookUpDataRoot(ctx context.Context, lookup *rootLookup) {
	ctx, cancel := context.WithTimeout(ctx, dataRootTimeout)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, d.bin(), "info", "--format", "{{.DockerRootDir}}")
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = time.Second
	root := ""
	err := cmd.Run()
	if err != nil {
		err = fmt.Errorf("docker info: %s", strings.TrimSpace(stderr.String()+" "+err.Error()))
	} else if root = strings.TrimSpace(stdout.String()); !filepath.IsAbs(root) {
		err = fmt.Errorf("docker info: data root %q is not a path", root)
	}
	d.rootMu.Lock()
	if err == nil {
		d.rootDir = root
		lookup.root = root
	}
	lookup.err = err
	d.rootLookup = nil
	d.rootMu.Unlock()
	close(lookup.done)
}
