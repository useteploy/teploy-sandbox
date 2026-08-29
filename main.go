// teploy-sandbox — Tier 1 single-box sandbox runner. Isolated ephemeral
// execution environments for agent runs, on the user's own server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/egress"
	"github.com/useteploy/teploy-sandbox/internal/run"
	"github.com/useteploy/teploy-sandbox/internal/server"
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
                       [--cache-root /var/lib/teploy-sandbox/cache] [--cache-max-gb 20]
  teploy-sandbox version`)
}

func serve(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := flags.String("addr", "127.0.0.1:7439", "listen address (never bind publicly)")
	tokenFile := flags.String("token-file", "/deployments/sandbox/token", "bearer token path (minted 0600 if absent)")
	reapInterval := flags.Duration("reap-interval", 30*time.Second, "TTL reaper tick interval")
	egressAllow := flags.String("egress-allow", os.Getenv("SBX_EGRESS_ALLOW"),
		"extra egress allowlist entries (comma-separated host, .suffix, or host:port), appended to the built-in registries")
	egressProxyPort := flags.String("egress-proxy-port", "7443", "allowlist proxy port on the egress bridge gateway")
	cacheRoot := flags.String("cache-root", envOr("SBX_CACHE_ROOT", run.DefaultWarmRoot),
		"host directory for the warm per-repo cache (empty disables the `warm` create option)")
	cacheMaxGB := flags.Float64("cache-max-gb", envFloat("SBX_CACHE_MAX_GB", 20),
		"LRU cap across all cache volumes, in GB (0 = unbounded)")
	if err := flags.Parse(args); err != nil {
		return err
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	token, err := server.LoadOrMintToken(*tokenFile)
	if err != nil {
		return fmt.Errorf("token: %w", err)
	}

	runtime := &run.DockerRuntime{}
	proxyURL := ""
	if err := runtime.EnsureEgressNetwork(context.Background()); err != nil {
		// Egress is opt-in per run; a missing bridge only blocks those runs.
		log.Warn("egress network unavailable", "error", err)
	} else {
		// Default-deny egress: the bridge is internal, so this allowlist
		// proxy on its gateway is a run's only path off the box.
		gateway, err := runtime.EgressGateway(context.Background())
		if err != nil {
			log.Warn("egress proxy disabled", "error", err)
		} else {
			allow := append(egress.Allowlist{}, egress.DefaultAllowlist...)
			allow = append(allow, egress.ParseAllowlist(*egressAllow)...)
			proxyAddr := net.JoinHostPort(gateway, *egressProxyPort)
			// Bind synchronously: if the gateway isn't a host interface
			// (VM-backed Docker on dev machines), runs must not be handed
			// a dead proxy URL — they stay fully sealed instead.
			listener, err := net.Listen("tcp", proxyAddr)
			if err != nil {
				log.Warn("egress proxy disabled — egress runs are fully sealed (no allowlisted door)",
					"addr", proxyAddr, "error", err)
			} else {
				proxy := &http.Server{Handler: &egress.Proxy{Allow: allow, Log: log}}
				go func() {
					if err := proxy.Serve(listener); err != nil && err != http.ErrServerClosed {
						log.Error("egress proxy failed", "error", err)
					}
				}()
				proxyURL = "http://" + proxyAddr
				log.Info("egress allowlist proxy up", "addr", proxyAddr, "entries", len(allow))
			}
		}
	}
	// Run state is in-memory: any container we labelled that survived a
	// previous daemon life is an unreachable orphan. Sweep before serving.
	if swept, err := runtime.SweepOrphans(context.Background()); err != nil {
		log.Warn("orphan sweep failed", "error", err)
	} else if swept > 0 {
		log.Info("swept orphaned run containers from a previous daemon life", "count", swept)
	}

	manager := run.NewManager(runtime, log)
	manager.ProxyURL = proxyURL
	if *cacheRoot != "" {
		manager.Cache = run.NewCacheStore(*cacheRoot, int64(*cacheMaxGB*(1<<30)))
		log.Info("per-repo cache enabled", "root", *cacheRoot, "maxGB", *cacheMaxGB)
	}

	hostname, _ := os.Hostname()
	srv := &server.Server{
		Manager:    manager,
		Runtime:    runtime,
		Token:      token,
		Version:    version,
		Log:        log,
		ServerName: hostname,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return server.Serve(ctx, *addr, srv, *reapInterval)
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
