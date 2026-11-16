// teploy-sandbox — Tier 1 single-box sandbox runner. Isolated ephemeral
// execution environments for agent runs, on the user's own server.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/egress"
	"github.com/useteploy/teploy-sandbox/internal/run"
	"github.com/useteploy/teploy-sandbox/internal/server"
	"github.com/useteploy/teploy-sandbox/internal/vm"
)

const (
	driverDocker = "docker"
	driverVM     = "vm"
)

// version is set by goreleaser at build time.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		if err := serve(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "teploy-sandbox:", err)
			os.Exit(1)
		}
	case "version":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `teploy-sandbox — isolated ephemeral execution for agent runs

Usage:
  teploy-sandbox serve [--addr 127.0.0.1:7439] [--token-file /deployments/sandbox/token]
                       [--egress-allow host,.suffix,host:port] [--egress-proxy-port 7443]
                       [--cache-root /var/lib/teploy-sandbox/cache] [--cache-max-gb 20]
                       [--state-dir /var/lib/teploy-sandbox/state] [--stopped-retention 336h]
                       [--driver docker|vm]
                       [--vm-hypervisor cloud-hypervisor] [--vm-kernel /var/lib/teploy-sandbox/vm/Image]
                       [--vm-pool sbx] [--vm-golden sbx/golden-guestd@v1] [--vm-run-dir /run/teploy-sandbox/vm]
  teploy-sandbox version`)
}

func serve(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := flags.String("addr", "127.0.0.1:7439", "listen address (never bind publicly)")
	tokenFile := flags.String("token-file", "/deployments/sandbox/token", "bearer token path (minted 0600 if absent)")
	reapInterval := flags.Duration("reap-interval", 30*time.Second, "TTL reaper tick interval")
	egressAllow := flags.String("egress-allow", os.Getenv("SBX_EGRESS_ALLOW"),
		"extra allowlist entries for EVERY run (comma-separated host, .suffix, or host:port), appended to the built-in registries; per-run extras go in the create body's egressAllow")
	egressProxyPort := flags.String("egress-proxy-port", "7443", "allowlist proxy port on the egress bridge gateway")
	cacheRoot := flags.String("cache-root", envOr("SBX_CACHE_ROOT", run.DefaultWarmRoot),
		"host directory for the warm per-repo cache (empty disables the `warm` create option)")
	cacheMaxGB := flags.Float64("cache-max-gb", envFloat("SBX_CACHE_MAX_GB", 20),
		"LRU cap across all cache volumes, in GB (0 = unbounded)")
	sandboxUser := flags.String("sandbox-user", envOr("SBX_SANDBOX_USER", run.DefaultSandboxUser),
		"non-root account runs execute as unless the create body says user \"root\"; images without it fall back to root (empty = every run as root)")
	stateDir := flags.String("state-dir", envOr("SBX_STATE_DIR", run.DefaultStateDir),
		"host directory for the durable run registry: stopped runs survive a daemon restart (empty keeps the registry in memory only)")
	stoppedRetention := flags.String("stopped-retention", envOr("SBX_STOPPED_RETENTION", run.DefaultStoppedRetention.String()),
		"how long a stopped run is kept before it and its snapshot are deleted (Go duration, e.g. 336h)")
	driverName := flags.String("driver", envOr("SBX_DRIVER", driverDocker),
		"what a run is: \"docker\" (a container) or \"vm\" (experimental: a Cloud Hypervisor VM on a ZFS volume; needs KVM)")
	vmHypervisor := flags.String("vm-hypervisor", envOr("SBX_VM_HYPERVISOR", vm.DefaultHypervisor),
		"vm driver: the cloud-hypervisor binary (a path, or a name on PATH)")
	vmKernel := flags.String("vm-kernel", envOr("SBX_VM_KERNEL", vm.DefaultKernel),
		"vm driver: the uncompressed guest kernel image every run direct-boots")
	vmCmdline := flags.String("vm-cmdline", envOr("SBX_VM_CMDLINE", vm.DefaultCmdline()),
		"vm driver: the guest kernel command line")
	vmPool := flags.String("vm-pool", envOr("SBX_VM_POOL", vm.DefaultPool),
		"vm driver: the ZFS pool (or a dataset in one) run volumes and snapshots are created under")
	vmGolden := flags.String("vm-golden", envOr("SBX_VM_GOLDEN", ""),
		"vm driver: the golden snapshot runs are cloned from (default <vm-pool>/golden-guestd@v1; see scripts/build-golden.sh)")
	vmRunDir := flags.String("vm-run-dir", envOr("SBX_VM_RUN_DIR", vm.DefaultRunDir),
		"vm driver: directory for each VM's sockets")
	vmBootTimeout := flags.Duration("vm-boot-timeout", envDuration("SBX_VM_BOOT_TIMEOUT", vm.DefaultBootTimeout),
		"vm driver: how long a new VM may take to answer")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *driverName != driverDocker && *driverName != driverVM {
		return fmt.Errorf("driver: must be %q or %q, got %q", driverDocker, driverVM, *driverName)
	}
	if *vmGolden == "" {
		*vmGolden = *vmPool + "/golden-guestd@v1"
	}
	warmUnavailable := false
	if *driverName == driverVM && *cacheRoot != "" {
		// The warm repo cache is bind-mounted host directories, which a VM
		// has no way to mount yet: the store is not opened at all, so a
		// `warm` create is refused instead of handed an empty volume.
		*cacheRoot = ""
		warmUnavailable = true
	}

	// Refuse a retention that is not the configured one: a typo here would
	// otherwise delete stopped runs early, or never.
	retention, err := parseRetention(*stoppedRetention)
	if err != nil {
		return fmt.Errorf("stopped-retention: %w", err)
	}

	// Validate the deployment allowlist before anything else: a typo in
	// SBX_EGRESS_ALLOW would otherwise present as "the allowlist ignores
	// my host" hours later. Refuse to start instead of serving a list
	// that silently isn't the configured one.
	deployAllow, err := egress.ValidateAllowlist(egress.ParseAllowlist(*egressAllow))
	if err != nil {
		return fmt.Errorf("egress-allow: %w", err)
	}

	tokenLock, err := run.LockDirectory(filepath.Dir(*tokenFile))
	if err != nil {
		return err
	}
	defer tokenLock.Close()
	if *cacheRoot != "" {
		absolute, err := filepath.Abs(*cacheRoot)
		if err != nil {
			return err
		}
		*cacheRoot = absolute
	}
	var cacheLock *os.File
	if *cacheRoot != "" {
		cacheLock, err = run.LockDirectory(*cacheRoot)
		if err != nil {
			return err
		}
		defer cacheLock.Close()
	}
	// The default state dir is new in this version. A deployment that never
	// asked for it and cannot write there (it moved --cache-root off /var/lib
	// for that reason) must keep starting as it did: fall back to the
	// in-memory registry and say so. A dir the operator named is a hard
	// requirement, and so is a registry file that exists but cannot be read.
	stateDirDefaulted := false
	if os.Getenv("SBX_STATE_DIR") == "" {
		stateDirDefaulted = true
		flags.Visit(func(f *flag.Flag) {
			if f.Name == "state-dir" {
				stateDirDefaulted = false
			}
		})
	}
	stateDirSkipped := ""
	if *stateDir != "" && stateDirDefaulted {
		if err := probeWritableDir(*stateDir); err != nil {
			stateDirSkipped = fmt.Sprintf("%s: %v", *stateDir, err)
			*stateDir = ""
		}
	}
	if *stateDir != "" {
		absolute, err := filepath.Abs(*stateDir)
		if err != nil {
			return err
		}
		*stateDir = absolute
		// One daemon owns a registry file, as one daemon owns a cache
		// root. A state dir that IS the token dir or the cache root is
		// already locked above (a second flock from this process would
		// refuse itself).
		tokenDir, err := filepath.Abs(filepath.Dir(*tokenFile))
		if err != nil {
			return err
		}
		if absolute != tokenDir && absolute != *cacheRoot {
			stateLock, err := run.LockDirectory(absolute)
			if err != nil {
				return err
			}
			defer stateLock.Close()
		}
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	token, err := server.LoadOrMintToken(*tokenFile)
	if err != nil {
		return fmt.Errorf("token: %w", err)
	}

	// The daemon's identity: a digest of its token file's path. Both
	// drivers mark what they create with it, and their startup sweeps
	// remove only what carries it.
	ownerPath, err := filepath.Abs(*tokenFile)
	if err != nil {
		return err
	}
	owner := sha256.Sum256([]byte(ownerPath))
	ownerID := hex.EncodeToString(owner[:])

	// backend is what a run is. The Docker branch below is the daemon as it
	// always was; the VM branch replaces every Docker call with a VM.
	var backend run.Runtime
	var docker *run.DockerRuntime
	runtimeName := ""
	proxyURL := ""
	var pool *egress.Pool
	if *driverName == driverVM {
		driver, err := vm.New(context.Background(), vm.Config{
			Hypervisor:  *vmHypervisor,
			Kernel:      *vmKernel,
			Cmdline:     *vmCmdline,
			Pool:        *vmPool,
			Golden:      *vmGolden,
			RunDir:      *vmRunDir,
			Owner:       ownerID,
			BootTimeout: *vmBootTimeout,
		}, log)
		if err != nil {
			return err
		}
		// No VM outlives its daemon, exactly as no container does: every
		// VM process and run volume carrying this daemon's mark belongs to
		// a previous life and is unreachable. Stopped runs have neither —
		// they are a registry record and a snapshot, which the sweep keeps.
		processes, volumes, err := driver.Sweep(context.Background())
		if err != nil {
			return fmt.Errorf("orphan sweep: %w", err)
		}
		if processes > 0 || volumes > 0 {
			log.Info("swept orphaned run VMs from a previous daemon life", "processes", processes, "volumes", volumes)
		}
		backend = driver
		runtimeName = "cloud-hypervisor"
		log.Warn("vm driver is experimental: runs have no network, run as root in the guest, and warm caches are unavailable",
			"pool", *vmPool, "golden", *vmGolden, "kernel", *vmKernel)
		if warmUnavailable {
			log.Info("warm repo cache is not available under the vm driver; --cache-root is ignored")
		}
	} else {
		// SBX_RUNTIME=runsc puts gVisor between every run and the host kernel;
		// unset means Docker's default runtime. SBX_SHM_MB sizes /dev/shm for
		// runs that launch a headless browser (Chromium needs 512 MB or more).
		docker = &run.DockerRuntime{Runtime: os.Getenv("SBX_RUNTIME"), ShmMB: int(envFloat("SBX_SHM_MB", 512))}
		docker.Owner = ownerID
		docker.CleanupRoot = filepath.Join(filepath.Dir(*tokenFile), ".sandbox-cleanup")
		if err := docker.RecoverScratch(); err != nil {
			return fmt.Errorf("recover scratch resources: %w", err)
		}
		if err := docker.EnsureEgressNetwork(context.Background()); err != nil {
			// Egress is opt-in per run; a missing bridge only blocks those runs.
			log.Warn("egress network unavailable", "error", err)
		} else {
			// Default-deny egress: the bridge is internal, so this allowlist
			// proxy on its gateway is a run's only path off the box.
			gateway, err := docker.EgressGateway(context.Background())
			if err != nil {
				log.Warn("egress proxy disabled", "error", err)
			} else {
				allow := append(egress.Allowlist{}, egress.DefaultAllowlist...)
				allow = append(allow, deployAllow...)
				// Bind synchronously: if the gateway isn't a host interface
				// (VM-backed Docker on dev machines), runs must not be handed
				// a dead proxy URL — they stay fully sealed instead.
				firewall := &egress.HostFirewall{Bridge: run.EgressBridge, Gateway: gateway, Chain: "TEPLOY-SBX"}
				if err := firewall.Start(); err != nil {
					firewall.Close()
					log.Warn("egress proxy disabled: host firewall unavailable", "error", err)
				} else {
					defer firewall.Close()
					pool = &egress.Pool{Base: allow, Bind: gateway, Log: log, PermitPort: firewall.PermitPort, RevokePort: firewall.RevokePort}
					url, err := pool.Start(*egressProxyPort)
					if err != nil {
						log.Warn("egress proxy disabled — allowlist runs are fully sealed (no allowlisted door)",
							"addr", net.JoinHostPort(gateway, *egressProxyPort), "error", err)
						pool = nil
					} else {
						proxyURL = url
						defer pool.Shutdown()
						log.Info("egress allowlist proxy up", "addr", url, "entries", len(allow))
					}
				}
			}
		}
		// No container outlives its daemon: any we labelled that survived a
		// previous daemon life is an unreachable orphan (the registry file
		// brings back stopped runs only, and those have none). Sweep before
		// serving.
		if swept, err := docker.SweepOrphans(context.Background()); err != nil {
			return fmt.Errorf("orphan sweep: %w", err)
		} else if swept > 0 {
			log.Info("swept orphaned run containers from a previous daemon life", "count", swept)
		}

		backend = docker
		runtimeName = docker.Runtime
	}

	manager := run.NewManager(backend, log)
	manager.ProxyURL = proxyURL
	manager.SandboxUser = *sandboxUser
	if *driverName == driverVM {
		// Every command runs as root inside the guest in this slice; the
		// run object says so (`user: "root"`) rather than naming an account
		// the guest does not use.
		manager.SandboxUser = ""
	}
	manager.StoppedRetention = retention
	if pool != nil {
		manager.Egress = pool
	}
	if *cacheRoot != "" {
		manager.Cache = run.NewCacheStore(*cacheRoot, int64(*cacheMaxGB*(1<<30)))
		live, err := docker.LiveCacheDirs(context.Background())
		if err != nil {
			return fmt.Errorf("inspect cache ownership: %w", err)
		}
		if _, err := manager.Cache.ReconcileRuns(live); err != nil {
			return fmt.Errorf("reconcile cache volumes: %w", err)
		}
		log.Info("per-repo cache enabled", "root", *cacheRoot, "maxGB", *cacheMaxGB)
	}

	if *stateDir != "" {
		// After the sweep: the images a lost running run held can only be
		// deleted once its container is gone. A registry file that cannot
		// be read refuses the start — an empty registry would orphan every
		// stopped run's snapshot without a word.
		stopped, err := manager.LoadState(context.Background(), *stateDir)
		if err != nil {
			return fmt.Errorf("load run registry: %w", err)
		}
		log.Info("durable run registry enabled", "dir", *stateDir, "stopped", stopped, "retention", retention.String())
	} else if stateDirSkipped != "" {
		log.Warn("default state dir is not writable: stopped runs do not survive a daemon restart (set --state-dir)", "error", stateDirSkipped)
	} else {
		log.Warn("no state dir: stopped runs do not survive a daemon restart")
	}

	hostname, _ := os.Hostname()
	srv := &server.Server{
		Manager:    manager,
		Token:      token,
		Version:    version,
		Log:        log,
		ServerName: hostname,
		Runtime:    runtimeName,
		Driver:     *driverName,
		// Not in this slice under either driver: a container gets no
		// /dev/kvm, and nested virtualization in a run's VM is neither
		// configured nor verified yet.
		NestedVirt: false,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return server.Serve(ctx, *addr, srv, *reapInterval)
}

// parseRetention reads --stopped-retention / SBX_STOPPED_RETENTION: a
// positive Go duration, nothing else.
func parseRetention(raw string) (time.Duration, error) {
	retention, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%q is not a duration (use Go syntax, e.g. 336h)", raw)
	}
	if retention <= 0 {
		return 0, fmt.Errorf("%q must be positive", raw)
	}
	return retention, nil
}

func envOr(name, fallback string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return fallback
}

func envFloat(name string, fallback float64) float64 {
	if v := os.Getenv(name); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return fallback
}

func envDuration(name string, fallback time.Duration) time.Duration {
	if v := os.Getenv(name); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return fallback
}

// probeWritableDir reports whether dir can be created and written.
func probeWritableDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	probe, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		return err
	}
	name := probe.Name()
	probe.Close()
	return os.Remove(name)
}
