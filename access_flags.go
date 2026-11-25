package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/useteploy/teploy-sandbox/internal/access"
	"github.com/useteploy/teploy-sandbox/internal/run"
	"github.com/useteploy/teploy-sandbox/internal/server"
)

// accessFlags are serve's access listener flags. With --access-addr unset
// (the default) access is off and the daemon is what it was without it.
type accessFlags struct {
	addr       *string
	tlsCert    *string
	tlsKey     *string
	clientCA   *string
	unixUID    *int
	unixGID    *int
	config     *string
	streamsMax *int
	edgeConns  *int
	memoryMB   *int
	mbit       *int
	anonMbit   *int
	totalMbit  *int
}

func addAccessFlags(flags *flag.FlagSet) *accessFlags {
	return &accessFlags{
		addr: flags.String("access-addr", envOr("SBX_ACCESS_ADDR", ""),
			"access listener for edges (SSH and published ports): HOST:PORT on a private overlay address (mutual TLS, 7448 by convention), or unix:/path; empty (default) turns access off"),
		tlsCert:  flags.String("access-tls-cert", envOr("SBX_ACCESS_TLS_CERT", ""), "access listener: the daemon's server certificate (PEM), from the daemon-server CA"),
		tlsKey:   flags.String("access-tls-key", envOr("SBX_ACCESS_TLS_KEY", ""), "access listener: the server certificate's key (PEM)"),
		clientCA: flags.String("access-client-ca", envOr("SBX_ACCESS_CLIENT_CA", ""), "access listener: the edge-client CA (PEM), which must not be the CA of the server certificate"),
		unixUID: flags.Int("access-unix-uid", int(envFloat("SBX_ACCESS_UNIX_UID", float64(os.Getuid()))),
			"access listener on a unix socket: the peer uid that may use it (-1: none)"),
		unixGID: flags.Int("access-unix-gid", int(envFloat("SBX_ACCESS_UNIX_GID", -1)),
			"access listener on a unix socket: the peer primary gid that may use it, and the socket file's group (-1: none)"),
		config: flags.String("access-config", envOr("SBX_ACCESS_CONFIG", ""),
			"access configuration file ({audience, issuerKeys, edgeDenylist}); when set it is the only source (PUT /v1/access/config is refused) and SIGHUP rereads it. Unset: the configuration PUT stores in --state-dir"),
		streamsMax: flags.Int("access-streams-max", int(envFloat("SBX_ACCESS_STREAMS_MAX", 0)),
			"access streams the daemon holds at once; 0 is --vm-max-runs x 64, and it must be set when there is no --vm-max-runs"),
		edgeConns: flags.Int("access-edge-conns", int(envFloat("SBX_ACCESS_EDGE_CONNS", 0)),
			"connections one edge may hold at once that do not serve a run yet; a connection serving a run counts instead against that run (at most 8 per edge and run: an edge opens one per run and kind, anonymous or one per grant); 0 is twice the most runs the stream cap allows for"),
		memoryMB: flags.Int("access-memory-mb", int(envFloat("SBX_ACCESS_MEMORY_MB", 0)),
			"memory (MiB) the access listener's worst case may take; the daemon refuses to start when --access-streams-max does not fit it. 0 is a tenth of the host's memory (1024 where that cannot be read)"),
		mbit:      flags.Int("access-mbit", int(envFloat("SBX_ACCESS_MBIT", -1)), "each run's granted access streams, together, each way, in megabits per second; -1 (default) is --vm-net-mbit (200 under the docker driver), 0 no limit"),
		anonMbit:  flags.Int("access-anon-mbit", int(envFloat("SBX_ACCESS_ANON_MBIT", access.DefaultAnonMbit)), "each run's anonymous (public port) access streams, together, each way, in megabits per second; 0 no limit"),
		totalMbit: flags.Int("access-total-mbit", int(envFloat("SBX_ACCESS_TOTAL_MBIT", access.DefaultTotalMbit)), "all access streams of the daemon, each way, in megabits per second; 0 no limit"),
	}
}

// accessSetup is an access listener ready to serve.
type accessSetup struct {
	listener  net.Listener
	h2c       bool
	service   *access.Service
	registry  *access.Registry
	store     *access.Store
	control   *access.Control
	log       *slog.Logger
	manager   *run.Manager
	spec      string
	limits    access.Limits
	edgeConns int
}

// prepare checks the flags, opens the configuration and the listener, and
// turns access on in the manager. nil with access off.
func (f *accessFlags) prepare(driver string, vmMaxRuns, vmNetMbit int, stateDir string, manager *run.Manager, log *slog.Logger) (*accessSetup, error) {
	if *f.addr == "" {
		for name, value := range map[string]string{"access-tls-cert": *f.tlsCert, "access-tls-key": *f.tlsKey, "access-client-ca": *f.clientCA, "access-config": *f.config} {
			if value != "" {
				return nil, fmt.Errorf("%s is set but --access-addr is not: access is off", name)
			}
		}
		return nil, nil
	}
	maxRuns := 0
	if driver == driverVM {
		maxRuns = vmMaxRuns
	}
	streamsMax := *f.streamsMax
	switch {
	case streamsMax < 0:
		return nil, errors.New("access-streams-max must not be negative")
	case streamsMax == 0 && maxRuns == 0:
		return nil, errors.New("access-streams-max: with no --vm-max-runs (or under the docker driver) the daemon's access stream cap must be set explicitly")
	case streamsMax == 0:
		streamsMax = maxRuns * access.DefaultPerRun
	}
	budget := *f.memoryMB
	if budget < 0 {
		return nil, errors.New("access-memory-mb must not be negative")
	}
	if budget == 0 {
		budget = server.HostMemoryMB() / 10
		if budget == 0 {
			budget = 1024
		}
	}
	if err := access.CheckMemory(streamsMax, budget); err != nil {
		return nil, err
	}
	var nofile syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &nofile); err == nil && nofile.Cur < uint64(access.FilesNeeded(streamsMax)) {
		log.Warn("the daemon's open file limit is low for its access streams; raise LimitNOFILE= or lower --access-streams-max",
			"limit", nofile.Cur, "accessNeeds", access.FilesNeeded(streamsMax))
	}
	edgeConns := *f.edgeConns
	if edgeConns < 0 {
		return nil, errors.New("access-edge-conns must not be negative")
	}
	if edgeConns == 0 {
		edgeConns = 2 * max(streamsMax/access.DefaultPerRun, 1)
	}
	if *f.anonMbit < 0 || *f.totalMbit < 0 {
		return nil, fmt.Errorf("access-anon-mbit and access-total-mbit must not be negative (0 is no limit)")
	}
	if *f.mbit < -1 {
		return nil, fmt.Errorf("access-mbit must be a rate, 0 for the default, or -1 for the vm driver's own")
	}
	if host, _, err := net.SplitHostPort(*f.addr); err == nil {
		// A private overlay address, never a public one: the listener is
		// for named and authenticated edges, not the internet, and an
		// unspecified bind is a copy-paste away from exactly that.
		if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
			return nil, fmt.Errorf("access-addr %s: an unspecified address would listen on every interface; name the overlay address the edges reach", *f.addr)
		}
	}
	mbit := *f.mbit
	if mbit < 0 {
		mbit = 200
		if driver == driverVM && vmNetMbit > 0 {
			mbit = vmNetMbit
		}
	}
	store, err := access.OpenStore(stateDir, *f.config)
	if err != nil {
		return nil, err
	}
	limits := access.Limits{Total: streamsMax, GrantedMbit: mbit, AnonMbit: *f.anonMbit, TotalMbit: *f.totalMbit}
	registry := access.NewRegistry(limits, manager.AddAccessBytes, log)
	listener, tls, err := access.Listen(access.ListenSpec{
		Addr:      *f.addr,
		TLS:       access.TLSFiles{Cert: *f.tlsCert, Key: *f.tlsKey, ClientCA: *f.clientCA},
		Unix:      access.UnixPeers{UID: *f.unixUID, GID: *f.unixGID},
		UnixGroup: *f.unixGID,
	}, store, edgeConns, log)
	if err != nil {
		return nil, fmt.Errorf("access listener: %w", err)
	}
	manager.EnableAccess(registry)
	if !manager.CanDialPorts() {
		log.Warn("access is on, but this driver cannot open streams to guest ports yet: connects answer 501", "driver", driver)
	}
	return &accessSetup{
		listener: listener, h2c: !tls, registry: registry, store: store, log: log, manager: manager,
		service:   &access.Service{Manager: manager, Store: store, Registry: registry, Log: log},
		control:   &access.Control{Store: store, Registry: registry, Listener: *f.addr},
		spec:      *f.addr,
		limits:    registry.Limits(),
		edgeConns: edgeConns,
	}, nil
}

// serve runs the access listener until ctx ends, and SIGHUP rereads the
// configuration file. The returned channel closes once it has stopped.
func (a *accessSetup) serve(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go a.registry.Run(ctx)
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		defer signal.Stop(hup)
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				if err := a.store.Reload(); err != nil {
					a.log.Error("access config not reloaded; the previous one stays", "error", err)
				} else if a.store.ManagedByFile() {
					a.log.Info("access config reloaded")
				}
			}
		}
	}()
	go func() {
		defer close(done)
		a.log.Info("access listener up", "addr", a.spec, "tls", !a.h2c, "streamsMax", a.limits.Total, "perRun", a.limits.PerRun,
			"perRunAnon", a.limits.PerRunAnon, "sessionReserve", a.limits.SessionReserve, "edgeConns", a.edgeConns,
			"mbit", a.limits.GrantedMbit, "anonMbit", a.limits.AnonMbit, "totalMbit", a.limits.TotalMbit)
		if err := a.service.Serve(ctx, a.listener, a.h2c); err != nil && !errors.Is(err, net.ErrClosed) {
			a.log.Error("access listener stopped", "error", err)
		}
	}()
	return done
}
