package vm

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
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

// secretEnv are the daemon's environment variables that hold secrets
// (remote storage's master key and credentials). No host command the
// driver runs has any use for them, and a child's environment is
// readable by whoever can read /proc/<pid>/environ of it.
var secretEnv = []string{
	"SBX_REMOTE_KEY", "SBX_REMOTE_SECRET_KEY", "SBX_REMOTE_SESSION_TOKEN", "SBX_REMOTE_ACCESS_KEY",
	"AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_ACCESS_KEY_ID",
}

// childEnv is the daemon's environment without its secrets: what a host
// command is started with.
func childEnv(environ []string) []string {
	kept := make([]string, 0, len(environ))
	for _, entry := range environ {
		name, _, _ := strings.Cut(entry, "=")
		if !slices.Contains(secretEnv, name) {
			kept = append(kept, entry)
		}
	}
	return kept
}

func (execCommander) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = childEnv(os.Environ())
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
	cmd.Env = childEnv(os.Environ())
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
	// kindImage is a memory image (memory_images.go): a filesystem, not
	// a volume, and never part of a stream.
	kindImage = "image"
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
	// Filesystems lists every filesystem under root (root itself
	// excluded). Run volumes and snapshot holders are volumes; the
	// filesystems are the daemon's memory images (kind image), and
	// whatever came out of a stream that was not a volume's, which only
	// goes.
	Filesystems(ctx context.Context, root string) ([]Dataset, error)
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
	// the given properties. The stream must be the plain stream of one
	// volume's snapshot with the identities expect names: anything else
	// (a filesystem, a replication package, another snapshot) is refused
	// before the pool sees it. A stream that ends early or is not one
	// creates nothing, and nothing received is ever mounted.
	Receive(ctx context.Context, snapshot, origin string, props map[string]string, expect StreamIdentity, r io.Reader) error
	// Space is the bytes available to, and the bytes used by, a dataset
	// and everything under it.
	Space(ctx context.Context, root string) (available, used int64, err error)
}

// imageFS is the part of ZFS memory images need beyond ZFS (see
// memory_images.go): filesystems that are each their own encryption root.
type imageFS interface {
	ZFS
	// CreateFilesystem creates an empty dataset with the properties.
	// key, when not nil, is the raw key of its new encryption root: it
	// reaches zfs on standard input (keylocation is prompt) and is
	// written nowhere.
	CreateFilesystem(ctx context.Context, name string, props map[string]string, key []byte) error
	// Mount mounts a dataset that is not mounted; Unmount unmounts one
	// that is (neither recursively).
	Mount(ctx context.Context, name string) error
	Unmount(ctx context.Context, name string) error
	// LoadKey loads the raw key of a dataset's encryption root from
	// standard input; CheckKey only verifies it, loaded or not.
	LoadKey(ctx context.Context, name string, key []byte) error
	CheckKey(ctx context.Context, name string, key []byte) error
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

var _ imageFS = (*zfsCLI)(nil)

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

// Dataset describes name whether it is a volume or a filesystem: what a
// cleanup looks at must not be blind to a kind of dataset the driver
// never makes.
func (z *zfsCLI) Dataset(ctx context.Context, name string) (Dataset, error) {
	out, err := z.run(ctx, "list", "-H", "-p", "-t", "filesystem,volume", "-o", datasetColumns, name)
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
	return z.list(ctx, "volume", root)
}

func (z *zfsCLI) Filesystems(ctx context.Context, root string) ([]Dataset, error) {
	return z.list(ctx, "filesystem", root)
}

func (z *zfsCLI) list(ctx context.Context, kind, root string) ([]Dataset, error) {
	out, err := z.run(ctx, "list", "-H", "-p", "-r", "-t", kind, "-o", datasetColumns, root)
	if err != nil {
		return nil, err
	}
	datasets, err := parseDatasets(out)
	if err != nil {
		return nil, err
	}
	// The root lists itself; it is not "under" root.
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

// props are -o arguments, sorted so a command line is always the same.
func zfsProps(props map[string]string) []string {
	var args []string
	for _, key := range slices.Sorted(maps.Keys(props)) {
		args = append(args, "-o", key+"="+props[key])
	}
	return args
}

func (z *zfsCLI) CreateFilesystem(ctx context.Context, name string, props map[string]string, key []byte) error {
	args := append([]string{"create"}, zfsProps(props)...)
	args = append(args, name)
	if key == nil {
		_, err := z.run(ctx, args...)
		return err
	}
	// With keylocation=prompt, zfs reads the raw key from standard input.
	return z.stream(ctx, bytes.NewReader(key), nil, args...)
}

func (z *zfsCLI) Mount(ctx context.Context, name string) error {
	_, err := z.run(ctx, "mount", name)
	return err
}

func (z *zfsCLI) Unmount(ctx context.Context, name string) error {
	_, err := z.run(ctx, "unmount", name)
	return err
}

func (z *zfsCLI) LoadKey(ctx context.Context, name string, key []byte) error {
	return z.stream(ctx, bytes.NewReader(key), nil, "load-key", name)
}

func (z *zfsCLI) CheckKey(ctx context.Context, name string, key []byte) error {
	return z.stream(ctx, bytes.NewReader(key), nil, "load-key", "-n", name)
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

// StreamIdentity is what a stream must say it is: the guid of the
// snapshot it creates, and of the snapshot it is incremental against
// ("" for a full stream).
type StreamIdentity struct {
	GUID, FromGUID string
}

// A send stream begins with one DRR_BEGIN record (OpenZFS
// include/sys/zfs_ioctl.h, struct dmu_replay_record; the layout has not
// changed since the format's first version, and was read from the 2.2
// sources): a 32-bit record type and payload length, then struct
// drr_begin — magic, version and features, creation time, the object
// set's type, flags, the guid of the snapshot, the guid of the snapshot
// it is incremental against, and its name — in the sender's byte order,
// which the magic number tells.
const (
	beginRecordBytes = 312
	streamMagic      = 0x2F5bacbac
	// drr_versioninfo's low two bits: a plain stream of one dataset, as
	// opposed to a package of several (zfs send -R, -p).
	streamSubstream = 1
	// dmu_objset_type_t: a volume.
	objsetZvol = 3
)

// checkStreamBegin reads the first record of a stream and refuses
// anything but the plain stream of one volume snapshot with the
// identities expected. What is uploaded is authenticated, so only a
// holder of the fleet's master key can present another stream at all;
// this is what that holder still cannot do with it: have a host receive
// (and mount) a filesystem, a tree of datasets with properties of its
// choosing, or a snapshot other than the one the manifest names.
func checkStreamBegin(header []byte, expect StreamIdentity) error {
	if len(header) < beginRecordBytes {
		return errors.New("the stream is shorter than its first record")
	}
	var order binary.ByteOrder = binary.LittleEndian
	switch {
	case binary.LittleEndian.Uint64(header[8:]) == streamMagic:
	case binary.BigEndian.Uint64(header[8:]) == streamMagic:
		order = binary.BigEndian
	default:
		return errors.New("not a ZFS send stream (no stream magic in its first record)")
	}
	if record := order.Uint32(header[0:]); record != 0 {
		return fmt.Errorf("the stream does not begin with a begin record (record type %d)", record)
	}
	if kind := order.Uint64(header[16:]) & 3; kind != streamSubstream {
		return fmt.Errorf("the stream is a package of datasets (header type %d), not one snapshot's stream", kind)
	}
	if objset := order.Uint32(header[32:]); objset != objsetZvol {
		return fmt.Errorf("the stream is not a volume's (object set type %d)", objset)
	}
	check := func(what, want string, got uint64) error {
		if want == "" {
			if got != 0 {
				return fmt.Errorf("the stream is incremental (against guid %d) where a full one is expected", got)
			}
			return nil
		}
		parsed, err := strconv.ParseUint(want, 10, 64)
		if err != nil {
			return fmt.Errorf("the %s guid %q in the manifest is not a guid", what, want)
		}
		if parsed != got {
			return fmt.Errorf("the stream's %s is guid %d, and the manifest says %s", what, got, want)
		}
		return nil
	}
	if expect.GUID == "" {
		return errors.New("no guid to check the stream against")
	}
	if err := check("snapshot", expect.GUID, order.Uint64(header[40:])); err != nil {
		return err
	}
	return check("incremental source", expect.FromGUID, order.Uint64(header[48:]))
}

func (z *zfsCLI) Receive(ctx context.Context, snapshot, origin string, props map[string]string, expect StreamIdentity, r io.Reader) error {
	header := make([]byte, beginRecordBytes)
	if _, err := io.ReadFull(r, header); err != nil {
		return fmt.Errorf("zfs receive %s: the stream ended inside its first record: %w", snapshot, err)
	}
	if err := checkStreamBegin(header, expect); err != nil {
		return fmt.Errorf("zfs receive %s refused: %w", snapshot, err)
	}
	// -u: whatever is received is not mounted. A volume never is; this
	// is for the stream the check above should have refused.
	args := []string{"receive", "-u"}
	if origin != "" {
		args = append(args, "-o", "origin="+origin)
	}
	for _, key := range slices.Sorted(maps.Keys(props)) {
		args = append(args, "-o", key+"="+props[key])
	}
	return z.stream(ctx, io.MultiReader(bytes.NewReader(header), r), nil, append(args, snapshot)...)
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
