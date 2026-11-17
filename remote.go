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
	chunkMB       *int
	parallel      *int
	maxChain      *int
	local         *string
	reserve       *int
	gcInterval    *time.Duration
	gcGrace       *time.Duration
	syncInterval  *time.Duration
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
			"remote storage: a file holding the 32-byte master key (raw, base64 or hex) every daemon sharing the storage is given; everything uploaded is encrypted under keys it wraps (or set SBX_REMOTE_KEY)"),
		chunkMB: flags.Int("remote-chunk-mb", int(envFloat("SBX_REMOTE_CHUNK_MB", offhost.DefaultChunkBytes>>20)),
			"remote storage: the size of one uploaded object, in MiB"),
		parallel: flags.Int("remote-parallel", int(envFloat("SBX_REMOTE_PARALLEL", offhost.DefaultParallel)),
			"remote storage: objects in flight at once; a transfer holds about (this + 1) chunks in memory"),
		maxChain: flags.Int("remote-max-chain", int(envFloat("SBX_REMOTE_MAX_CHAIN", offhost.DefaultMaxChain)),
			"remote storage: how many incremental uploads may follow one another before a stop is uploaded against the base image again, which bounds what a restore has to fetch"),
		local: flags.String("remote-local", envOr("SBX_REMOTE_LOCAL", run.LocalKeep),
			"remote storage: what happens to a snapshot's local copy once it is durable: \"keep\" it for a fast resume on this host (dropped when the pool runs short), or \"drop\" it at once"),
		reserve: flags.Int("remote-pool-reserve", int(envFloat("SBX_REMOTE_POOL_RESERVE", 15)),
			"remote storage: the share of the pool, in percent, to keep free: below it, local copies of durable snapshots are dropped, oldest stop first (0 never drops for space)"),
		gcInterval: flags.Duration("remote-gc-interval", envDuration("SBX_REMOTE_GC_INTERVAL", run.DefaultRemoteGCInterval),
			"remote storage: how often objects nothing refers to are looked for"),
		gcGrace: flags.Duration("remote-gc-grace", envDuration("SBX_REMOTE_GC_GRACE", 24*time.Hour),
			"remote storage: how long an object must have been garbage before it is deleted; longer than any upload takes"),
		syncInterval: flags.Duration("remote-sync-interval", envDuration("SBX_REMOTE_SYNC_INTERVAL", run.DefaultRemoteSyncInterval),
			"remote storage: how often runs stopped, resumed or destroyed on other daemons are looked for"),
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
// first of the environment variables that is set.
func secretFrom(file string, env ...string) ([]byte, error) {
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		return data, nil
	}
	if value := firstEnv(env...); value != "" {
		return []byte(value), nil
	}
	return nil, nil
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
	if err := os.WriteFile(path, []byte(identity+"\n"), 0o600); err != nil {
		return "", err
	}
	return identity, nil
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
	if *f.chunkMB < 1 || *f.chunkMB > 1024 || *f.parallel < 1 || *f.parallel > 64 || *f.maxChain < 1 || *f.reserve < 0 || *f.reserve > 90 {
		return nil, errors.New("remote-chunk-mb must be 1 to 1024, remote-parallel 1 to 64, remote-max-chain at least 1 and remote-pool-reserve 0 to 90")
	}
	if *f.local != run.LocalKeep && *f.local != run.LocalDrop {
		return nil, fmt.Errorf("remote-local must be %q or %q, got %q", run.LocalKeep, run.LocalDrop, *f.local)
	}
	if *f.gcGrace <= 0 || *f.gcInterval <= 0 || *f.syncInterval <= 0 {
		return nil, errors.New("remote-gc-grace, remote-gc-interval and remote-sync-interval must be positive: a grace of zero would delete in the very round a snapshot is first seen unreferenced, while a fork may still be naming it")
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
	client, err := s3.New(s3.Config{
		Endpoint:  *f.endpoint,
		Region:    *f.region,
		Bucket:    *f.bucket,
		PathStyle: *f.pathStyle,
		Credentials: s3.Credentials{
			AccessKey:    *f.accessKey,
			SecretKey:    strings.TrimSpace(string(secret)),
			SessionToken: firstEnv("SBX_REMOTE_SESSION_TOKEN", "AWS_SESSION_TOKEN"),
		},
		UserAgent: "teploy-sandbox/" + version,
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
