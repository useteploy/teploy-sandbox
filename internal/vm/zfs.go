package vm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os/exec"
	"slices"
	"strings"
	"time"
)

// Commander runs a host command and returns its stdout. It is the one
// seam between this package and the host's binaries: the real one shells
// out, tests script it.
type Commander interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// CommandError is a command that ran and failed; Stderr is what it said.
type CommandError struct {
	Command string
	Stderr  string
	Err     error
}

func (e *CommandError) Error() string {
	detail := e.Stderr
	if detail == "" {
		detail = e.Err.Error()
	}
	return e.Command + ": " + detail
}

func (e *CommandError) Unwrap() error { return e.Err }

type execCommander struct{}

func (execCommander) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		command := name
		if len(args) > 0 {
			command += " " + args[0]
		}
		return nil, &CommandError{Command: command, Stderr: strings.TrimSpace(stderr.String()), Err: err}
	}
	return stdout.Bytes(), nil
}

// User properties this driver puts on what it creates. ZFS user property
// names need a colon; snapshots inherit their dataset's.
const (
	// propOwner marks a dataset as created by one daemon identity. Nothing
	// without this daemon's mark is ever destroyed, promoted or changed.
	propOwner = "teploy:owner"
	// propKind is kindRun or kindSnapshot.
	propKind = "teploy:kind"
	// propDead marks a snapshot that is no longer a usable reference and
	// only exists until nothing is cloned from it.
	propDead = "teploy:dead"

	kindRun      = "run"
	kindSnapshot = "snapshot"
)

// Dataset is a volume as the driver needs to see it.
type Dataset struct {
	Name string
	// Origin is the snapshot this volume is a clone of, "" for none.
	Origin string
	Owner  string
	Kind   string
}

// SnapshotInfo is one snapshot of a dataset.
type SnapshotInfo struct {
	// Name is the full name, dataset@snapshot.
	Name string
	// Clones are the datasets cloned from it.
	Clones []string
	Dead   bool
}

// ErrNoDataset is Dataset's answer for a name that does not exist.
var ErrNoDataset = errors.New("dataset does not exist")

// ZFS is the storage boundary: the handful of operations the driver needs,
// small enough to fake faithfully (see fakeZFS in the tests).
type ZFS interface {
	// Dataset describes a volume; ErrNoDataset when there is none.
	Dataset(ctx context.Context, name string) (Dataset, error)
	// Volumes lists every volume under root (root itself excluded).
	Volumes(ctx context.Context, root string) ([]Dataset, error)
	// Snapshots lists a dataset's own snapshots, oldest first.
	Snapshots(ctx context.Context, dataset string) ([]SnapshotInfo, error)
	// Exists reports whether a dataset or snapshot exists.
	Exists(ctx context.Context, name string) (bool, error)
	// Clone creates dataset as a clone of snapshot with the given user
	// properties.
	Clone(ctx context.Context, snapshot, dataset string, props map[string]string) error
	Snapshot(ctx context.Context, name string) error
	// Promote makes a clone the owner of its origin's history: the origin
	// snapshot and every older one move to it, and its old parent becomes
	// its clone.
	Promote(ctx context.Context, dataset string) error
	// Destroy removes one dataset or one snapshot, never recursively. It
	// fails while anything is cloned from what it would remove.
	Destroy(ctx context.Context, name string) error
	SetProperty(ctx context.Context, name, key, value string) error
	// Property is the effective value of a property on a dataset, whether
	// set there or inherited.
	Property(ctx context.Context, name, key string) (string, error)
}

// zfsCLI is ZFS over the zfs(8) command.
type zfsCLI struct {
	bin string
	cmd Commander
	// busyRetry bounds how long Destroy retries "dataset is busy": a
	// volume stays open for a moment after its hypervisor exits, and udev
	// probes every new device node.
	busyRetry time.Duration
}

func newZFSCLI(bin string, cmd Commander) *zfsCLI {
	if bin == "" {
		bin = "zfs"
	}
	return &zfsCLI{bin: bin, cmd: cmd, busyRetry: 10 * time.Second}
}

func (z *zfsCLI) run(ctx context.Context, args ...string) ([]byte, error) {
	return z.cmd.Run(ctx, z.bin, args...)
}

func isMissing(err error) bool {
	var cmdErr *CommandError
	return errors.As(err, &cmdErr) && strings.Contains(cmdErr.Stderr, "does not exist")
}

func isBusy(err error) bool {
	var cmdErr *CommandError
	return errors.As(err, &cmdErr) && strings.Contains(cmdErr.Stderr, "is busy")
}

// field reads one `zfs list -H` column: "-" is ZFS for "no value".
func field(value string) string {
	if value == "-" {
		return ""
	}
	return value
}

const datasetColumns = "name,origin," + propOwner + "," + propKind

func parseDatasets(out []byte) ([]Dataset, error) {
	var datasets []Dataset
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if line == "" {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) != 4 {
			return nil, fmt.Errorf("zfs list: unexpected line %q", line)
		}
		datasets = append(datasets, Dataset{Name: cols[0], Origin: field(cols[1]), Owner: field(cols[2]), Kind: field(cols[3])})
	}
	return datasets, nil
}

func (z *zfsCLI) Dataset(ctx context.Context, name string) (Dataset, error) {
	out, err := z.run(ctx, "list", "-H", "-p", "-t", "volume", "-o", datasetColumns, name)
	if isMissing(err) {
		return Dataset{}, ErrNoDataset
	}
	if err != nil {
		return Dataset{}, err
	}
	datasets, err := parseDatasets(out)
	if err != nil {
		return Dataset{}, err
	}
	if len(datasets) != 1 {
		return Dataset{}, fmt.Errorf("zfs list %s: %d datasets", name, len(datasets))
	}
	return datasets[0], nil
}

func (z *zfsCLI) Volumes(ctx context.Context, root string) ([]Dataset, error) {
	out, err := z.run(ctx, "list", "-H", "-p", "-r", "-t", "volume", "-o", datasetColumns, root)
	if err != nil {
		return nil, err
	}
	datasets, err := parseDatasets(out)
	if err != nil {
		return nil, err
	}
	// A root that is itself a volume lists itself; it is not "under" root.
	kept := datasets[:0]
	for _, dataset := range datasets {
		if dataset.Name != root {
			kept = append(kept, dataset)
		}
	}
	return kept, nil
}

func (z *zfsCLI) Snapshots(ctx context.Context, dataset string) ([]SnapshotInfo, error) {
	out, err := z.run(ctx, "list", "-H", "-p", "-d", "1", "-t", "snapshot", "-s", "createtxg", "-o", "name,clones,"+propDead, dataset)
	if err != nil {
		return nil, err
	}
	var snapshots []SnapshotInfo
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if line == "" {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) != 3 {
			return nil, fmt.Errorf("zfs list: unexpected line %q", line)
		}
		info := SnapshotInfo{Name: cols[0], Dead: field(cols[2]) != ""}
		if clones := field(cols[1]); clones != "" {
			info.Clones = strings.Split(clones, ",")
		}
		snapshots = append(snapshots, info)
	}
	return snapshots, nil
}

func (z *zfsCLI) Exists(ctx context.Context, name string) (bool, error) {
	_, err := z.run(ctx, "list", "-H", "-o", "name", name)
	if isMissing(err) {
		return false, nil
	}
	return err == nil, err
}

func (z *zfsCLI) Clone(ctx context.Context, snapshot, dataset string, props map[string]string) error {
	args := []string{"clone"}
	for _, key := range slices.Sorted(maps.Keys(props)) {
		args = append(args, "-o", key+"="+props[key])
	}
	_, err := z.run(ctx, append(args, snapshot, dataset)...)
	return err
}

func (z *zfsCLI) Snapshot(ctx context.Context, name string) error {
	_, err := z.run(ctx, "snapshot", name)
	return err
}

func (z *zfsCLI) Promote(ctx context.Context, dataset string) error {
	_, err := z.run(ctx, "promote", dataset)
	return err
}

func (z *zfsCLI) Destroy(ctx context.Context, name string) error {
	deadline := time.Now().Add(z.busyRetry)
	for {
		_, err := z.run(ctx, "destroy", name)
		if !isBusy(err) || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (z *zfsCLI) Property(ctx context.Context, name, key string) (string, error) {
	out, err := z.run(ctx, "get", "-H", "-p", "-o", "value", key, name)
	if err != nil {
		return "", err
	}
	return field(strings.TrimSpace(string(out))), nil
}

func (z *zfsCLI) SetProperty(ctx context.Context, name, key, value string) error {
	_, err := z.run(ctx, "set", key+"="+value, name)
	return err
}
