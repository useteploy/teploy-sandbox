package vm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os/exec"
	"slices"
	"strconv"
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

// Streamer is the part of the seam that carries a stream: a command
// whose output, or input, is too large to hold (zfs send, zfs receive).
type Streamer interface {
	// Stream runs a command with stdin as its input (nil for none) and
	// stdout for its output (nil to discard it).
	Stream(ctx context.Context, stdin io.Reader, stdout io.Writer, name string, args ...string) error
}

// streamStderr is how much of a streaming command's complaint is kept.
const streamStderr = 4 << 10

func (execCommander) Stream(ctx context.Context, stdin io.Reader, stdout io.Writer, name string, args ...string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stderr := tailBuffer{limit: streamStderr}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr = stdout, &stderr
	// A command that has exited is not waited on for a pipe someone
	// else still holds open.
	cmd.WaitDelay = 5 * time.Second
	command := name
	if len(args) > 0 {
		command += " " + args[0]
	}
	var fed chan error
	if stdin != nil {
		// Fed by hand rather than through cmd.Stdin: Wait would block on
		// a reader that never ends, and an input that fails must kill
		// the command instead of looking like the end of the stream.
		pipe, err := cmd.StdinPipe()
		if err != nil {
			return err
		}
		fed = make(chan error, 1)
		go func() {
			_, err := io.Copy(pipe, stdin)
			if err != nil {
				cancel()
			}
			_ = pipe.Close()
			fed <- err
		}()
	}
	if err := cmd.Start(); err != nil {
		return &CommandError{Command: command, Err: err}
	}
	err := cmd.Wait()
	var feedErr error
	if fed != nil {
		select {
		case feedErr = <-fed:
		default:
			// Still blocked reading its source; the caller closes that.
		}
	}
	if feedErr != nil && !errors.Is(feedErr, io.ErrClosedPipe) && err != nil {
		// The input is why the command died.
		return feedErr
	}
	if err != nil {
		return &CommandError{Command: command, Stderr: stderr.Tail(streamStderr), Err: err}
	}
	return feedErr
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
	// kindProbe is the scratch volume Preflight tests the host's udev
	// with; it exists only while that check runs.
	kindProbe = "probe"
	// kindRestore is a volume being received from remote storage: not
	// usable, and removed at the next start, until its restore commits.
	kindRestore = "restore"
	// kindBase is a base image received from remote storage: a golden
	// image of another host, which runs restored here are clones of. It
	// goes when nothing is cloned from it any more.
	kindBase = "base"
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
	// CreateVolume creates an empty sparse volume of the given size.
	CreateVolume(ctx context.Context, name string, bytes int64, props map[string]string) error
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
	// Send writes the stream of a snapshot to w: all of it, or with from
	// (a snapshot it descends from) only what changed since.
	Send(ctx context.Context, snapshot, from string, w io.Writer) error
	// Receive creates snapshot (dataset@name, the dataset new) from a
	// stream, as a clone of origin when the stream is incremental, with
	// the given properties. A stream that ends early or is not one
	// creates nothing.
	Receive(ctx context.Context, snapshot, origin string, props map[string]string, r io.Reader) error
	// Space is the bytes available to, and the bytes used by, a dataset
	// and everything under it.
	Space(ctx context.Context, root string) (available, used int64, err error)
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

func (z *zfsCLI) CreateVolume(ctx context.Context, name string, bytes int64, props map[string]string) error {
	args := []string{"create", "-s", "-V", strconv.FormatInt(bytes, 10)}
	for _, key := range slices.Sorted(maps.Keys(props)) {
		args = append(args, "-o", key+"="+props[key])
	}
	_, err := z.run(ctx, append(args, name)...)
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

func (z *zfsCLI) stream(ctx context.Context, stdin io.Reader, stdout io.Writer, args ...string) error {
	streamer, ok := z.cmd.(Streamer)
	if !ok {
		return errors.New("zfs: this command runner cannot carry a stream")
	}
	return streamer.Stream(ctx, stdin, stdout, z.bin, args...)
}

// Send streams a snapshot. Blocks are sent as they are stored (-c), so a
// compressed pool uploads what it holds rather than the expanded data.
func (z *zfsCLI) Send(ctx context.Context, snapshot, from string, w io.Writer) error {
	args := []string{"send", "-c"}
	if from != "" {
		args = append(args, "-i", from)
	}
	return z.stream(ctx, nil, w, append(args, snapshot)...)
}

func (z *zfsCLI) Receive(ctx context.Context, snapshot, origin string, props map[string]string, r io.Reader) error {
	args := []string{"receive"}
	if origin != "" {
		args = append(args, "-o", "origin="+origin)
	}
	for _, key := range slices.Sorted(maps.Keys(props)) {
		args = append(args, "-o", key+"="+props[key])
	}
	return z.stream(ctx, r, nil, append(args, snapshot)...)
}

func (z *zfsCLI) Space(ctx context.Context, root string) (available, used int64, err error) {
	out, err := z.run(ctx, "list", "-H", "-p", "-o", "available,used", root)
	if err != nil {
		return 0, 0, err
	}
	cols := strings.Fields(string(out))
	if len(cols) != 2 {
		return 0, 0, fmt.Errorf("zfs list: unexpected output %q", strings.TrimSpace(string(out)))
	}
	if available, err = strconv.ParseInt(cols[0], 10, 64); err != nil {
		return 0, 0, err
	}
	if used, err = strconv.ParseInt(cols[1], 10, 64); err != nil {
		return 0, 0, err
	}
	return available, used, nil
}
