package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/offhost"
	"github.com/useteploy/teploy-sandbox/internal/run"
	"github.com/useteploy/teploy-sandbox/internal/s3"
)

// remoteFlags are the serve flags of off-host storage. All of it is off
// until --remote-endpoint is given.
type remoteFlags struct {
	endpoint      *string
	bucket        *string
	prefix        *string
	region        *string
	pathStyle     *bool
	accessKey     *string
	secretKeyFile *string
	keyFile       *string
	previousKeys  *string
	chunkMB       *int
	parallel      *int
	maxChain      *int
	local         *string
	reserve       *int
	gcInterval    *time.Duration
	gcGrace       *time.Duration
	syncInterval  *time.Duration
	snapshotRetry *time.Duration
	scrubInterval *time.Duration
	transfers     *int
	insecureHTTP  *bool
	unfenced      *bool
}

func addRemoteFlags(flags *flag.FlagSet) *remoteFlags {
	return &remoteFlags{
		endpoint: flags.String("remote-endpoint", envOr("SBX_REMOTE_ENDPOINT", ""),
			"remote storage (vm driver): the URL of an S3-compatible service stopped runs are also kept in, so that any daemon sharing it can resume them (https://s3.example.com); empty keeps snapshots on this host only"),
		bucket: flags.String("remote-bucket", envOr("SBX_REMOTE_BUCKET", ""), "remote storage: the bucket"),
		prefix: flags.String("remote-prefix", envOr("SBX_REMOTE_PREFIX", ""),
			"remote storage: a key prefix inside the bucket; daemons that share one share their stopped runs"),
		region: flags.String("remote-region", envOr("SBX_REMOTE_REGION", "us-east-1"), "remote storage: the signing region"),
		pathStyle: flags.Bool("remote-path-style", envBool("SBX_REMOTE_PATH_STYLE"),
			"remote storage: address the bucket as a path segment (endpoint/bucket/key) instead of a host label (bucket.endpoint/key)"),
		accessKey: flags.String("remote-access-key", firstEnv("SBX_REMOTE_ACCESS_KEY", "AWS_ACCESS_KEY_ID"), "remote storage: the access key"),
		secretKeyFile: flags.String("remote-secret-key-file", envOr("SBX_REMOTE_SECRET_KEY_FILE", ""),
			"remote storage: a file holding the secret key (or set SBX_REMOTE_SECRET_KEY / AWS_SECRET_ACCESS_KEY)"),
		keyFile: flags.String("remote-key-file", envOr("SBX_REMOTE_KEY_FILE", ""),
			"remote storage: a file, readable by the daemon's user only, holding the master key every daemon sharing the storage is given: 32 random bytes as 64 hex digits, as base64, or raw (head -c 32 /dev/urandom | xxd -p -c 64). Everything uploaded is encrypted under keys it wraps (or set SBX_REMOTE_KEY)"),
		previousKeys: flags.String("remote-previous-key-file", envOr("SBX_REMOTE_PREVIOUS_KEY_FILE", ""),
			"remote storage: comma-separated files holding master keys this daemon still opens but no longer wraps with (the state while a key rotation runs); POST /v1/remote/rotate re-wraps what they still protect"),
		chunkMB: flags.Int("remote-chunk-mb", int(envFloat("SBX_REMOTE_CHUNK_MB", offhost.DefaultChunkBytes>>20)),
			"remote storage: the size of one uploaded object, in MiB"),
		parallel: flags.Int("remote-parallel", int(envFloat("SBX_REMOTE_PARALLEL", offhost.DefaultParallel)),
			"remote storage: objects in flight at once; a transfer holds about (this + 1) chunks in memory"),
		maxChain: flags.Int("remote-max-chain", int(envFloat("SBX_REMOTE_MAX_CHAIN", offhost.DefaultMaxChain)),
			fmt.Sprintf("remote storage: how many incremental uploads may follow one another before a stop is uploaded against the base image again, which bounds what a restore has to fetch (1 to %d)", offhost.MaxChainLimit)),
		local: flags.String("remote-local", envOr("SBX_REMOTE_LOCAL", run.LocalKeep),
			"remote storage: what happens to a snapshot's local copy once it is durable: \"keep\" it for a fast resume on this host (dropped when the pool runs short), or \"drop\" it at once"),
		reserve: flags.Int("remote-pool-reserve", int(envFloat("SBX_REMOTE_POOL_RESERVE", 15)),
			"remote storage: the share of the pool, in percent, to keep free: below it, local copies of durable snapshots are dropped, oldest stop first (0 never drops for space)"),
		gcInterval: flags.Duration("remote-gc-interval", envDuration("SBX_REMOTE_GC_INTERVAL", run.DefaultRemoteGCInterval),
			"remote storage: how often objects nothing refers to are looked for"),
		gcGrace: flags.Duration("remote-gc-grace", envDuration("SBX_REMOTE_GC_GRACE", 24*time.Hour),
			fmt.Sprintf("remote storage: how long this daemon must have seen an object as garbage before it deletes it (at least %s); a destroyed run's record is kept thirty times as long", offhost.MinGCGrace)),
		syncInterval: flags.Duration("remote-sync-interval", envDuration("SBX_REMOTE_SYNC_INTERVAL", run.DefaultRemoteSyncInterval),
			"remote storage: how often runs stopped, resumed or destroyed on other daemons are looked for"),
		snapshotRetry: flags.Duration("remote-snapshot-retry", envDuration("SBX_REMOTE_SNAPSHOT_RETRY", run.DefaultSnapshotRetry),
			"remote storage: how long a caller snapshot whose upload failed is retried before it stays on that host only (0: not retried, the old behaviour); shorter than remote-gc-grace"),
		scrubInterval: flags.Duration("remote-scrub-interval", envDuration("SBX_REMOTE_SCRUB_INTERVAL", run.DefaultRemoteScrubInterval),
			"remote storage: how often every stopped run this daemon reports durable is checked again in the bucket (manifest, every chunk, and everything its stream builds on); 0 never"),
		transfers: flags.Int("remote-transfers", int(envFloat("SBX_REMOTE_TRANSFERS", run.DefaultTransfers)),
			"remote storage: uploads and restores at once across all runs; each holds about (remote-parallel + 1) chunks in memory. With more than one, uploads take at most all but one, which is left for restores"),
		insecureHTTP: flags.Bool("remote-insecure-http", envBool("SBX_REMOTE_INSECURE_HTTP"),
			"remote storage: allow a plain http:// endpoint on another host. Object names and sizes then cross the network in the clear and whatever is on the path can answer for the service; only for a network that is itself trusted"),
		unfenced: flags.Bool("remote-unfenced", envBool("SBX_REMOTE_UNFENCED"),
			"remote storage: on a service without conditional writes, still let this daemon resume and delete runs another daemon wrote last. Only when something else guarantees that one daemon at a time acts on a run"),
	}
}

func firstEnv(names ...string) string {
	for _, name := range names {
		if value := os.Getenv(name); value != "" {
			return value
		}
	}
	return ""
}

// secretFrom reads a secret from a file when one is named, else from the
// first of the environment variables that is set. A file anyone but its
// owner can read is refused: the master key opens every stopped run of
// the fleet, and a key file left 0644 is how it gets read by a user who
// was never given it. A variable a secret was read from is removed from
// the daemon's environment, so that nothing it starts inherits it.
func secretFrom(file string, env ...string) ([]byte, error) {
	if file != "" {
		info, err := os.Stat(file)
		if err != nil {
			return nil, err
		}
		if mode := info.Mode().Perm(); mode&0o077 != 0 {
			return nil, fmt.Errorf("%s is readable by others than its owner (mode %04o); chmod 600 it", file, mode)
		}
		return os.ReadFile(file)
	}
	for _, name := range env {
		if value := os.Getenv(name); value != "" {
			_ = os.Unsetenv(name)
			return []byte(value), nil
		}
	}
	return nil, nil
}

// writeFileAtomic replaces path with data: a temp file beside it,
// fsynced, renamed. A crash leaves the old file, the new one or none,
// never part of one.
func writeFileAtomic(path string, data []byte) (result error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		if result != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

// daemonIdentity is this daemon's name among those sharing remote
// storage: random, made once, kept in the state directory. It is what a
// run's record says holds the run, so it has to be the same after a
// restart and different on every host.
func daemonIdentity(stateDir string) (string, error) {
	path := filepath.Join(stateDir, "daemon-id")
	data, err := os.ReadFile(path)
	if err == nil {
		identity := strings.TrimSpace(string(data))
		if len(identity) != 32 || strings.Trim(identity, "0123456789abcdef") != "" {
			return "", fmt.Errorf("%s does not hold a daemon identity; remove it to have a new one made (runs this daemon was running are then another daemon's to take over)", path)
		}
		return identity, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	identity := hex.EncodeToString(raw)
	// Whole or not at all: a file cut short by a crash would refuse every
	// later start, and removing it gives the daemon a new name under
	// which the runs it was running are another daemon's.
	if err := writeFileAtomic(path, []byte(identity+"\n")); err != nil {
		return "", err
	}
	return identity, nil
}

// fleetIdentityFile remembers, in the state directory, the name of the
// bucket prefix this daemon's registry belongs to.
const fleetIdentityFile = "remote-fleet-id"

// checkFleetIdentity makes sure the bucket and prefix this daemon was
// started with are the ones its registry was written against. A
// registry full of runs "in remote storage" pointed at another bucket
// finds none of their records there; that must stop the daemon, not
// start a round of conclusions about the runs.
func checkFleetIdentity(ctx context.Context, store *offhost.Store, stateDir string) error {
	path := filepath.Join(stateDir, fleetIdentityFile)
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	remembered := strings.TrimSpace(string(data))
	if remembered == "" {
		// First use from this state directory.
		fleet, err := store.CreateIdentity(ctx)
		if err != nil {
			return err
		}
		return writeFileAtomic(path, []byte(fleet+"\n"))
	}
	fleet, err := store.Identity(ctx)
	switch {
	case errors.Is(err, offhost.ErrNoIdentity):
		return fmt.Errorf("this daemon's state directory belongs to remote storage named %s, and the bucket and prefix it was started with have no name at all: another bucket or prefix, or one whose objects were lost. Check --remote-bucket and --remote-prefix. If this IS the storage to use from now on, remove %s: stopped runs this host still has a copy of are then published to it again, and the others stay listed as not durable", remembered, path)
	case err != nil:
		return err
	case fleet != remembered:
		return fmt.Errorf("this daemon's state directory belongs to remote storage named %s, and the bucket and prefix it was started with are named %s: check --remote-bucket and --remote-prefix (to move this daemon to that storage on purpose, remove %s)", remembered, fleet, path)
	}
	return nil
}

// validate checks the flags that are numbers and choices.
func (f *remoteFlags) validate() error {
	if *f.chunkMB < 1 || *f.chunkMB > 1024 || *f.parallel < 1 || *f.parallel > 64 || *f.maxChain < 1 || *f.maxChain > offhost.MaxChainLimit ||
		*f.reserve < 0 || *f.reserve > 90 || *f.transfers < 1 || *f.transfers > 64 {
		return fmt.Errorf("remote-chunk-mb must be 1 to 1024, remote-parallel 1 to 64, remote-max-chain 1 to %d (no daemon restores through a longer chain), remote-pool-reserve 0 to 90 and remote-transfers 1 to 64", offhost.MaxChainLimit)
	}
	if *f.local != run.LocalKeep && *f.local != run.LocalDrop {
		return fmt.Errorf("remote-local must be %q or %q, got %q", run.LocalKeep, run.LocalDrop, *f.local)
	}
	if *f.snapshotRetry < 0 {
		return errors.New("remote-snapshot-retry must not be negative")
	}
	if *f.gcInterval <= 0 || *f.syncInterval <= 0 || *f.scrubInterval < 0 {
		return errors.New("remote-gc-interval and remote-sync-interval must be positive, and remote-scrub-interval not negative")
	}
	if *f.gcGrace < offhost.MinGCGrace {
		return fmt.Errorf("remote-gc-grace must be at least %s: it is how long a daemon watches something be garbage before deleting it, and it has to outlast one chunk's write with every retry and the moment between a manifest and the record that names it", offhost.MinGCGrace)
	}
	if *f.snapshotRetry >= *f.gcGrace {
		return fmt.Errorf("remote-snapshot-retry (%s) must be shorter than remote-gc-grace (%s): a snapshot retried for longer is sent against a previous upload that collection may have deleted meanwhile", f.snapshotRetry, f.gcGrace)
	}
	return nil
}

// open builds remote storage from the flags. It returns nil when none is
// configured.
func (f *remoteFlags) open(ctx context.Context, snapshots offhost.Snapshots, stateDir string, log *slog.Logger) (*offhost.Service, error) {
	if *f.endpoint == "" {
		return nil, nil
	}
	if snapshots == nil {
		return nil, errors.New("remote storage is the vm driver's (--driver vm): the docker driver's snapshots are images, which are not sent anywhere yet")
	}
	if stateDir == "" {
		return nil, errors.New("remote storage needs a state directory (--state-dir): the daemon's identity and its runs' places in remote storage are kept there")
	}
	if err := f.validate(); err != nil {
		return nil, err
	}
	secret, err := secretFrom(*f.secretKeyFile, "SBX_REMOTE_SECRET_KEY", "AWS_SECRET_ACCESS_KEY")
	if err != nil {
		return nil, fmt.Errorf("remote-secret-key-file: %w", err)
	}
	rawKey, err := secretFrom(*f.keyFile, "SBX_REMOTE_KEY")
	if err != nil {
		return nil, fmt.Errorf("remote-key-file: %w", err)
	}
	if rawKey == nil {
		return nil, errors.New("remote storage needs a master key (--remote-key-file or SBX_REMOTE_KEY): nothing is uploaded unencrypted")
	}
	master, err := offhost.ParseMasterKey(rawKey)
	if err != nil {
		return nil, fmt.Errorf("remote master key: %w", err)
	}
	keys, err := offhost.NewKeyring(master)
	if err != nil {
		return nil, err
	}
	// Master keys this daemon still opens but no longer wraps with: the
	// state while a rotation runs. Given as files, comma-separated,
	// because a key on a command line is a key in a process listing.
	for _, path := range strings.Split(*f.previousKeys, ",") {
		if path = strings.TrimSpace(path); path == "" {
			continue
		}
		previous, err := secretFrom(path)
		if err != nil {
			return nil, fmt.Errorf("remote-previous-key-file: %w", err)
		}
		master, err := offhost.ParseMasterKey(previous)
		if err != nil {
			return nil, fmt.Errorf("remote-previous-key-file %s: %w", path, err)
		}
		if err := keys.AddPrevious(master); err != nil {
			return nil, fmt.Errorf("remote-previous-key-file %s: %w", path, err)
		}
	}
	token, err := secretFrom("", "SBX_REMOTE_SESSION_TOKEN", "AWS_SESSION_TOKEN")
	if err != nil {
		return nil, err
	}
	sessionToken := strings.TrimSpace(string(token))
	client, err := s3.New(s3.Config{
		Endpoint:  *f.endpoint,
		Region:    *f.region,
		Bucket:    *f.bucket,
		PathStyle: *f.pathStyle,
		Credentials: s3.Credentials{
			AccessKey:    *f.accessKey,
			SecretKey:    strings.TrimSpace(string(secret)),
			SessionToken: sessionToken,
		},
		UserAgent:     "teploy-sandbox/" + version,
		AllowInsecure: *f.insecureHTTP,
	})
	if err != nil {
		return nil, fmt.Errorf("remote storage: %w", err)
	}
	identity, err := daemonIdentity(stateDir)
	if err != nil {
		return nil, fmt.Errorf("daemon identity: %w", err)
	}
	store := offhost.NewStore(client, *f.prefix, keys, log)
	store.ChunkBytes = *f.chunkMB << 20
	store.Parallel = *f.parallel
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	// A daemon that cannot reach its storage does not start: it could
	// not tell whether a run is its to resume, and would report stops as
	// not durable for as long as it ran.
	if err := store.Probe(probeCtx); err != nil {
		return nil, err
	}
	if err := checkFleetIdentity(probeCtx, store, stateDir); err != nil {
		return nil, fmt.Errorf("remote storage: %w", err)
	}
	if !store.Conditional() {
		if *f.unfenced {
			log.Warn("remote storage has no conditional writes and --remote-unfenced is set: nothing here stops two daemons from resuming the same run; whatever places runs must")
		} else {
			log.Warn("remote storage has no conditional writes: stopped runs are uploaded and can be forked anywhere, but this daemon will only resume or delete runs it wrote last itself (--remote-unfenced lifts that when a controller serialises)")
		}
	}
	log.Info("remote storage enabled", "endpoint", *f.endpoint, "bucket", *f.bucket, "prefix", *f.prefix, "daemon", identity,
		"conditionalWrites", store.Conditional(), "chunkMB", *f.chunkMB, "parallel", *f.parallel, "maxChain", *f.maxChain,
		"local", *f.local, "poolReservePercent", *f.reserve, "gcGrace", f.gcGrace.String())
	return offhost.NewService(store, snapshots, offhost.Config{
		Daemon:         identity,
		MaxChain:       *f.maxChain,
		Unfenced:       *f.unfenced,
		GCGrace:        *f.gcGrace,
		ReservePercent: *f.reserve,
	}, log), nil
}
