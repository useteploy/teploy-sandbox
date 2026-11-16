# teploy-sandbox

Tier 1 single-box sandbox runner: isolated ephemeral execution
environments for agent runs, on your own server. Each run gets its own
filesystem and network namespace via Docker; state persists between
execs; everything dies at its TTL, unless the run asked to be stopped
there instead (see Persistent runs).

```sh
teploy-sandbox serve            # 127.0.0.1:7439; token minted to /deployments/sandbox/token
```

## API (bearer token on everything except /health)

| Route | Does |
|---|---|
| `POST /v1/runs` | `{image, env?, ttlSec?, network?, egressAllow?, limits?, warm?, user?, labels?, onExpire?}` → the run: `{id, server, state, expiresAt, user, onExpire, usage, labels?, warm?}` — network `none` (default), `allowlist` or `open` (see Egress); defaults 1 CPU / 1 GB / 256 pids, never the `teploy` app network; `user` `default` (absent) or `root` (see Run user); `warm: {repo, path?}` gives the run a private volume for the repo (below) |
| `POST /v1/runs/{id}/exec` | `{cmd, cwd?, timeoutSec?, env?, owner?, generation?, outputEncoding?}` (`env`: name → value, set in the command's environment; POSIX names, no NUL, ≤64 vars / 64 KiB, else 400; values reach the container through a private (0600, removed after) `--env-file`, never argv and never the docker CLI's own environment; so no line breaks) → SSE: `stdout`/`stderr` chunks, then `exit` `{exitCode, timedOut}`; while the run holds a lease, only the holder's `owner`+`generation` may exec (409 otherwise) |
| `PUT/GET /v1/runs/{id}/files/{path}` | Confined to `/work`; traversal rejected. PUT takes the lease credential as `?owner=&generation=` query and is fenced like exec; GET is open, lease or not |
| `DELETE /v1/runs/{id}` | Destroy now (the reaper enforces TTLs regardless, default 30 min); on a stopped run, deletes the record and its snapshot |
| `POST /v1/runs/{id}/stop` | Capture the filesystem, remove the container, keep the run → the run, `state: "stopped"` (see Persistent runs) |
| `POST /v1/runs/{id}/resume` | `{ttlSec?}` → the same run, same `id`, `state: "running"`, new deadline |
| `POST /v1/runs/{id}/fork` | `{ttlSec?, labels?, onExpire?}` → 201, a new run started from this one's filesystem and settings, with `forkedFrom` |
| `GET /v1/capacity` | `{server, driver, runtime, cpus, memoryMb, runs: {running, stopped}, allocated: {cpus, memoryMb}}` — the host's size and the sum of running runs' limits |
| `GET /v1/runs`, `GET /health` | List; `{status, version}` |

Run IDs are ULIDs and every response carries a `server` field — nothing
assumes one box, so the Tier 2 fleet scheduler fronts N daemons without
API rework.

## Persistent runs

A run can outlive its container. `stop` commits the filesystem to an
image the daemon owns, removes the container and keeps the run in the
list as `stopped`; `resume` recreates the container from that image under
the same `id`. A stopped run costs disk and nothing else. This is what a
caller did by hand before — snapshot, destroy, create from the snapshot —
as one lifecycle, with the run's identity kept.

Every run carries, in every response that returns one:

| Field | Meaning |
|---|---|
| `state` | `running` or `stopped` |
| `labels` | The caller's own metadata from create: at most 16; keys `^[a-z0-9]([a-z0-9._-]{0,62})$`; values at most 256 bytes, no control characters. Anything else is a 400 |
| `onExpire` | `destroy` (default: the run is removed at its deadline, as always) or `stop` (it is stopped there instead). Anything else is a 400 |
| `usage.runningSec` | Seconds spent `running`, summed across every stop and resume, current stretch included |
| `stoppedAt`, `retainUntil` | Only while stopped. At `retainUntil` the run and its snapshot are deleted |
| `forkedFrom` | The source run's `id`, on a fork |

**Stop** needs an idle run, like snapshot: 409 `busy` while an exec, a
write, a capture or a removal is in flight. It captures exactly as
snapshot does (a warm volume is baked into the image), then removes the
container, closes the run's private egress proxy, releases its warm
volume and clears its lease. There is no half state: if the capture
fails nothing has changed, and if the container cannot be removed after
a good capture the run stays `running` and the capture is deleted.
Stopping a stopped run is a 409.

**Resume** boots the stop snapshot with what the run was created with:
env, network tier, `egressAllow`, limits, user and warm volume. `image`
on the run is still the image it was created from. A warm run takes the
snapshot-restore path — an empty volume seeded from the image, never the
repo template merged underneath. The deadline is now + `ttlSec`, with
create's default and maximum. A resume that fails leaves the run stopped
with its snapshot intact. Lease generations keep counting across a
stop, so a credential from before it never passes the fence again.
Resuming a running run is a 409.

**Fork** captures a running source (same idle rule; the source keeps
running) or borrows a stopped source's snapshot, and starts a new run
from it with the source's env, network, `egressAllow`, limits, user and
warm request. `labels` and `onExpire` are the source's unless the body
gives them.

**While stopped,** exec, files, snapshot, lease and warm calls answer 409
and say to resume. A stopped run ignores its old `expiresAt`; the reaper
deletes it at `retainUntil`, which is stop time plus
`--stopped-retention` / `SBX_STOPPED_RETENTION` (a Go duration, default
`336h`; a malformed or non-positive value refuses to start). A run with
`onExpire: "stop"` whose stop fails at the deadline is retried on every
reaper tick for one hour — so a run that is busy at every tick outlives
its deadline until one finds it idle. After that hour it is destroyed
like any other expired run: a container that can never be captured does
not hold the host forever.

The images behind all this belong to the daemon, not the caller: they
are not returned, `DELETE /v1/snapshots` refuses them with a 409, and
each is deleted when the last run using it lets go. Docker will not
delete an image while a container created from it exists, so a stop
snapshot outlives the resume that used it and goes when that container
does — at the next stop, or at destroy. The same holds for the capture
behind a fork, which goes with the child.

### Surviving a restart

`serve --state-dir` / `SBX_STATE_DIR` (default
`/var/lib/teploy-sandbox/state`) holds the registry as one JSON file,
replaced atomically on every change to a stopped run. It is `0600` in a
`0700` directory because it holds each stopped run's env, which is where
callers put tokens. One daemon owns a state directory.

- On start, stopped runs are loaded and can be resumed. Running runs are
  not: no container outlives its daemon (the startup sweep removes them
  all, as before), and the images only those runs held are deleted.
- On graceful shutdown, runs with `onExpire: "stop"` are stopped and
  written to the file; every other run is destroyed, as before. A crash
  stops nothing — a running run's state is lost with its container.
- A state file that cannot be read or parsed refuses the start. Starting
  empty would orphan every stopped run's snapshot without a word.
- A state dir you name (flag or env) must be usable or the daemon
  refuses to start. The default one is tried: if it cannot be created or
  written, the daemon starts with the registry in memory and logs why.
- An empty `--state-dir` keeps the registry in memory. Stop, resume and
  fork still work; nothing stopped survives a restart, and the snapshots
  are left behind for the operator.

## VM driver (experimental)

`serve --driver vm` (`SBX_DRIVER=vm`) runs each run as a virtual machine
with its own kernel instead of a container: Cloud Hypervisor on KVM, one
ZFS volume per run cloned from a golden image, and an in-guest agent
(`teploy-guestd`) reached over vsock, so exec and file transfer need no
guest networking. The default driver is still `docker`, and nothing about
it changed.

What works, through the same HTTP API: create, exec (stdout, stderr, exit
code, env, cwd, timeout), file write and read, snapshot, stop, resume
after a daemon restart, fork of a running run, destroy.

What is refused with a 400 rather than faked, in this first slice:

- any `network` other than `none`, and `egressAllow` (a VM has no guest
  network yet);
- `warm` (no warm repo cache);
- `limits.pids` (a VM is bounded by its memory and CPUs);
- an `image` that is neither `golden` nor a snapshot this driver took.

Also not built yet: a pool of pre-booted VMs (every create is a cold
boot), nested virtualisation inside a run, and memory reclaim policy.

Host requirements, checked at start; the daemon refuses to start and
names what is missing: `/dev/kvm`, the `cloud-hypervisor` binary
(`--vm-hypervisor`), an uncompressed guest kernel (`--vm-kernel`), a ZFS
pool (`--vm-pool`) with `volmode=dev` set on it, and a golden snapshot
(`--vm-golden`). Build the golden with `scripts/build-golden.sh` from a
volume holding a bootable systemd root filesystem. `GET /v1/capacity`
reports `driver` and `nestedVirt`.

Guest disks and the host. `zfs set volmode=dev POOL` is what keeps the
host kernel from scanning a guest's disk for partitions: every volume
under the pool inherits it, so no guest partition becomes a block device
on the host. Setting it on each volume as it is cloned is not enough (on
ZFS 2.2 the device node can be created before the property applies), so
the daemon requires it on the pool and checks each run's device before
booting from it.

The whole disk is still a block device on the host for as long as the
volume exists, and udev probes it like any other disk. A guest that
writes a filesystem signature over the start of its disk gets a
`/dev/disk/by-label` or `by-uuid` link on the host with a label of its
choosing. The daemon does not prevent this. A host that mounts anything
by label or UUID should stop udev from probing ZFS volumes, for example
with `/etc/udev/rules.d/59-zvol-noprobe.rules` containing
`KERNEL=="zd*", ENV{UDEV_DISABLE_PERSISTENT_STORAGE_RULES_FLAG}="1"`
(it applies to every ZFS volume on the host; the `/dev/zvol` links stay).

A VM's console and its hypervisor's output are kept in the daemon's
memory, the last 64 KiB of each; nothing a guest can make grow is written
to `--vm-run-dir`.

Test against a real hypervisor (needs root, KVM and ZFS; CI has neither
and only vets it):
`CGO_ENABLED=0 go test -c -tags vmintegration -o vm.test . && sudo ./vm.test -test.run TestVM -test.v`

## Writable leases

A human takes exclusive writable ownership of a run while its agent is
paused; execs and file writes by anyone else are refused with 409 until
the lease is released or lapses. Reads stay open to everyone.

| Route | Does |
|---|---|
| `POST /v1/runs/{id}/lease` | `{owner, ttlSec}` → `{lease: {holder, generation, expiresAt}}` — grants the lease; every grant (fresh, regrant after expiry, or re-acquire by the same owner) bumps the `generation` |
| `POST /v1/runs/{id}/lease/renew` | `{owner, generation, ttlSec}` → extended expiry; a stale generation gets 409 `superseded` |
| `POST /v1/runs/{id}/lease/release` | `{owner, generation}` → 204; mismatches get 409 |

Semantics: the `generation` is the fencing token. Execs and writes pass
either when no lease is held (the pre-lease path — existing callers are
unaffected) or when they carry the active lease's exact `owner`+
`generation`. Expiry frees the run lazily (no sweeper); the next grant
bumps the generation, so a holder whose lease lapsed cannot renew,
release, or write under their old credential — they learn via 409
`superseded`. The lease is visible on the run's list JSON
(`lease: {holder, generation, expiresAt}`) and dies with the run.

Takeover safety: `acquire` is refused with 409 `busy` while any exec or
file write is in flight — takeover happens only between execs, never
under one. Residual limits, deliberate in this slice: a long-running
exec delays a takeover up to its timeout (there is no mid-exec kill),
and lease expiry does not interrupt an in-flight exec either — it only
stops its renewal. A caller that keeps execing can therefore hold off a
takeover indefinitely.

Clients: `SandboxExecutor` in `@neutron-build/agents` (the pinned wire
contract); a Go client package follows with the Phase B agent product.

## Egress

Three tiers, on `POST /v1/runs`:

| `network` | What a run can reach |
|---|---|
| `none` (default) | Nothing. No interface but loopback. |
| `allowlist` | Only allowlisted hosts, and only through the daemon's HTTP proxy. `egress` is a still-supported alias; the response normalizes it to `allowlist`. |
| `open` | Everything the host can route. No proxy, no filter. |

`egressAllow: ["rubygems.org", ".hex.pm", "forge.example.com:49152"]`
adds entries for ONE run, on top of the built-in list — the entries
live on a private proxy that is created with the run and closed when it
dies. Its URL carries a random proxy credential; discovering the listener
port grants no extra policy. Both HTTP and CONNECT require that credential. Entry
grammar is the same as `SBX_EGRESS_ALLOW`: `host` (ports 80/443),
`.suffix` (the host and its subdomains, two labels minimum — `.com` is
refused), or `host:port` (that port only). A malformed entry is a 400,
never a silent drop. `egressAllow` on `none` or `open` is a 400 too:
there is no allowlist there to extend.

`SBX_EGRESS_ALLOW` (or `serve --egress-allow`) does the same thing
deployment-wide, and a malformed value now refuses to start rather than
serving a list that isn't the configured one.

### What is on the default list

npm/yarn/Node, PyPI, Go, cargo + rustup, RubyGems, Maven Central +
Gradle (portal, wrapper, Adoptium, `google()`), Composer, NuGet +
`dotnet-install`, Hex, pub.dev, Hackage + ghcup, Debian, Ubuntu
(including `ports.ubuntu.com` for arm64), Alpine, GitHub/GitLab/
Bitbucket/Codeberg, and anonymous pulls from Docker Hub, GHCR, Quay and
MCR. `internal/egress/proxy.go` carries a comment per entry.

Where a registry puts publishing on its own hostname, only the download
host is listed — `crates.io`, `hex.pm`, `www.nuget.org`, `packagist.org`
and Sonatype are all deliberately absent while their download hosts are
present. Where it does not (RubyGems, npm, Hackage, the Gradle portal,
every OCI registry), the entry is marked two-way in the source: allowing
the install allows the upload, and that is a knowing trade.

Three deliberate refusals worth knowing about, because they mean a
working ecosystem is still one `egressAllow` away:

- **`storage.googleapis.com`** — plain Dart works, but the **Flutter
  SDK** fetches engine artifacts from it. A generic object store is an
  exfiltration channel with a package manager's excuse, so it is opt-in.
- **`registry.k8s.io`** — redirects even manifests to a regional
  `*.pkg.dev` or a `prod-registry-k8s-io-*` S3 bucket, so there is no
  single host to allow.
- **`aka.ms`** — a redirector to anywhere on Microsoft's estate.

### What the allowlist tier cannot do

The `teploy-sbx-egress-v2` bridge is internal with inter-container
communication disabled. Linux `iptables` admits only active proxy listeners
on its gateway and denies other host services; IPv6 is disabled in allowlist
containers. Runs find the proxy through `HTTP_PROXY` / `HTTPS_PROXY`.
The daemon requires permission to manage its dedicated `TEPLOY-SBX` INPUT
chain. If it cannot enforce the firewall, allowlist creation is refused.
Existing workloads on the older bridge keep their lifecycle; new runs use v2.
Everything follows from that:

- **Only proxy-aware tools get out at all.** curl, git-over-https, npm,
  pip, go, cargo, apt, gem, composer and friends read the proxy env.
  Anything that ignores it — a raw socket, a database driver, a JVM
  that was not given `-Dhttp.proxyHost` — has no route and fails with a
  network error rather than a 403.
- **SSH git remotes and `git://` can never work.** `git@github.com:...`
  is SSH on port 22 and `git://` is port 9418; neither speaks HTTP
  CONNECT, and neither has a route. Rewrite to https, or use `open`.
  This is not an allowlist entry away — no entry helps.
- **Ports: 80 and 443 only,** unless an entry names a port explicitly
  (`forge.example.com:49152`). A port-scoped entry opens that port and
  nothing else.
- **Denials are 403s from the proxy,** and the body names the exact
  `egressAllow` entry and `SBX_EGRESS_ALLOW` value that would have
  admitted the host.

### What `open` actually does

`open` puts the run on Docker's default NAT bridge and injects no proxy
env at all. A raw TCP or UDP connection to any port simply works: SSH
remotes, `git://`, database ports, anything the host can route. That
includes the box's LAN, its tailnet, and any other Docker network the
host routes to — `open` is the absence of a boundary, not a wider
allowlist. It is still never the `teploy` app network. Use it for code
you already trust; `allowlist` is the default answer for agent runs.


## Run user

A run executes as the non-root sandbox account (`ship`, `--sandbox-user` /
`SBX_SANDBOX_USER`; empty runs everything as root) unless the create body
says `"user": "root"`. The Ship sandbox images define the account with uid
1000 and passwordless sudo, which is what GitHub Actions runners and
devcontainers do: suites whose permission tests root would ignore behave,
and root stays one `sudo` away.

- Root runs keep `no-new-privileges` and drop `NET_RAW`, `MKNOD`,
  `AUDIT_WRITE`. Non-root runs drop `no-new-privileges` (it is what stops
  sudo elevating) and keep `AUDIT_WRITE` (sudo warns on every call
  without it). The bounding set is otherwise identical, so the ceiling is
  the root run's.
- An image without the account (older builds, a project's own image) boots
  as root, as before; the create response and the log name the user the
  run actually got.
- Template copies, snapshot seeding and snapshots taken under root land
  files as root, so a non-root run's container is handed `/work` (and a
  warm mount) by a root exec at create and after a seed; only entries not
  already owned are touched.
- Exec, files PUT/GET run as the run's user.

## Never

Bind the API publicly; join runs to the `teploy` network; mount the
Docker socket into a run.

## Testing

`go test ./...` (interface-mocked) · `go test -tags integration ./...`
(real Docker on a disposable box; `SBX_TEST_USER_IMAGE=<image with the
sandbox user>` adds the run-user round trip;
`-run TestRealStopResumeAcrossRestart` is the persistent-runs round trip:
stop, a fresh manager over the same state dir, resume, same bytes).

## Snapshots (M3)

| Route | Does |
|---|---|
| `POST /v1/runs/{id}/snapshot` | Commit the run's filesystem → `{image: "teploy-sbx-snap:<ulid>"}`; a later `POST /v1/runs` with that image boots from it |
| `DELETE /v1/snapshots?image=<ref>` | Delete a snapshot image (only `teploy-sbx-snap:*` refs are deletable) |

Snapshots deliberately survive the TTL reaper — they exist so state can
outlive a container (a parked agent run restores days later). Deletion
is explicit and owned by the caller. `stop`/`resume` (Persistent runs)
is the same idea with the daemon doing the bookkeeping; this route stays
for callers that want the image itself.

## Warm repo cache (SB-A)

Clone+install dominates a scan's fixed cost, so the daemon keeps a warm
per-repo volume: a ready clone with dependencies installed, keyed by
repo slug, invalidated by lockfile change. Enable with
`serve --cache-root` (default `/var/lib/teploy-sandbox/cache`; empty
disables the `warm` option) and cap it with `--cache-max-gb` (LRU
across templates, default 20).

| Route | Does |
|---|---|
| `POST /v1/runs` with `warm: {repo, path?}` | Private volume for the repo (default mount `/work`): copied from the warm template when one exists (`warm.booted: true` + its `lockHash`/`repoDir`), empty otherwise — the repo-setup flow clones cold, then commits |
| `POST /v1/runs/{id}/warm-commit` | `{repo?}` → hash the run volume's lockfiles (go.mod, package-lock.json, pnpm-lock.yaml, Cargo.lock, … the set that exists) and publish it as the repo's template → `{repo, lockHash, repoDir}` |
| `GET /v1/runs/{id}/warm` | The run volume's CURRENT lockfile hash — compare against the manifest after a fetch/checkout; a change means rebuild (re-install, re-commit) |
| `GET /v1/warmcache/{owner}/{name}` | The repo's template manifest, 404 when none |
| `DELETE /v1/warmcache/{owner}/{name}` | Drop the template (forced invalidation) |

Like snapshots, warm commits record nothing — the caller's recorded
step sequence and replay semantics are untouched. Concurrency-safe by
construction: templates are immutable generations (atomic manifest
swap), every run boots its own COPY, and in-use generations are never
evicted — two runs of the same repo cannot corrupt the cache or each
other. The lockfile hash keys on path AND content of the lockfile set
at the repo root (detected at the volume root or its single
lockfile-bearing subdir); a lockfile-less repo hashes deterministically
but never invalidates on lockfile change. LRU eviction runs on the
reaper tick only — a size walk never delays a run's start.

### gVisor snapshots

With `SBX_RUNTIME=runsc`, each container explicitly sets
`dev.gvisor.flag.overlay2=none`. gVisor's default private rootfs overlay is
invisible to `docker commit`; without this setting a snapshot can report success
while losing the repository. The per-container setting retains gVisor isolation
and writes into Docker's container filesystem. It does not change the host's
Docker configuration. See [gVisor filesystem configuration](https://gvisor.dev/docs/user_guide/filesystem/).

Verify the actual runtime, including repository metadata and uncommitted files:
`SBX_TEST_RUNTIME=runsc go test -tags integration -run TestRealSnapshotRetainsWorkspace .`
Set `SBX_TEST_IMAGE` to use a preinstalled image. Bind-mounted warm volumes remain
outside image snapshots; callers must retain those containers across a pause.

### Capture and streaming guarantees

Build with Go 1.25 or newer. The daemon uses rooted filesystem operations to
keep cache reads inside each volume. Lockfiles are regular files of at most
8 MiB; cache copies reject special files and cap files at 512 MiB, trees at
8 GiB and 100,000 entries. Publication and reclamation are serialized. One
daemon owns a cache root, and startup retains every volume still mounted by
any Docker container while reclaiming only unowned sandbox run directories.

Snapshot, warm commit and warm hash require an idle run. Concurrent exec,
write, capture, lease takeover or destroy receives a conflict while a capture
is active. Docker pause covers background writers during capture; the run
resumes even if the request is canceled. Failed removals remain tracked for
TTL retry. Temporary capture resources have a cleanup journal for restart
recovery; final snapshot images remain caller-owned.

The default SSE text protocol keeps the existing `stdout`, `stderr` and
`exit` events. It buffers UTF-8 across pipe writes and retains raw carriage
returns for the pinned upstream line parser; invalid UTF-8 becomes a replacement
character. A standard EventSource parser treats CR as a line delimiter, so
clients requiring safe carriage-return/binary delivery should set the exec
body's `outputEncoding` to `"base64"` for byte-exact output, including carriage
returns and binary bytes. Each stdout/stderr event then carries a base64
string; `exit` retains its JSON schema. Consumers must explicitly request and
decode this mode. Images used for timed execs must provide coreutils timeout.

Before deployment, run `go build ./...`, `go vet ./...`, `go test ./...`,
`go test -race ./...`, and `CGO_ENABLED=0 go test -tags integration ./...`.
Native Linux firewall fixtures need root: build a static integration test
binary with `CGO_ENABLED=0 go test -c -tags integration -o /tmp/sandbox-tests .`
and run `sudo /tmp/sandbox-tests -test.v`. Native Linux
integration covers the host firewall and the Docker peer/host/proxy boundary;
use `SBX_TEST_RUNTIME=runsc` to also verify gVisor snapshot persistence.
