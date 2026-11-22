package run

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
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
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, d.bin(), "info", "--format", "{{.DockerRootDir}}")
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker info: %s", strings.TrimSpace(stderr.String()))
	}
	root := strings.TrimSpace(stdout.String())
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("docker info: data root %q is not a path", root)
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
