# teploy-sandbox

Tier 1 single-box sandbox runner: isolated ephemeral execution
environments for agent runs, on your own server. Each run gets its own
filesystem and network namespace via Docker; state persists between
execs; everything dies at its TTL.

```sh
teploy-sandbox serve            # 127.0.0.1:7439; token minted to /deployments/sandbox/token
```

## API (bearer token on everything except /health)

| Route | Does |
|---|---|
| `POST /v1/runs` | `{image, env?, ttlSec?, network?, egressAllow?, limits?, warm?}` → `{id, server, expiresAt, warm?}` — network `none` (default), `allowlist` or `open` (see Egress); defaults 1 CPU / 1 GB / 256 pids, `no-new-privileges`, never the `teploy` app network; `warm: {repo, path?}` gives the run a private volume for the repo (below) |
| `POST /v1/runs/{id}/exec` | `{cmd, cwd?, timeoutSec?, env?, owner?, generation?}` (`env`: name → value, set in the command's environment; POSIX names, no NUL, ≤64 vars / 64 KiB, else 400; values reach the container through a private (0600, removed after) `--env-file`, never argv and never the docker CLI's own environment; so no line breaks) → SSE: `stdout`/`stderr` chunks, then `exit` `{exitCode, timedOut}`; while the run holds a lease, only the holder's `owner`+`generation` may exec (409 otherwise) |
| `PUT/GET /v1/runs/{id}/files/{path}` | Confined to `/work`; traversal rejected. PUT takes the lease credential as `?owner=&generation=` query and is fenced like exec; GET is open, lease or not |
| `DELETE /v1/runs/{id}` | Destroy now (the reaper enforces TTLs regardless, default 30 min) |
| `GET /v1/runs`, `GET /health` | List; `{status, version}` |

Run IDs are ULIDs and every response carries a `server` field — nothing
assumes one box, so the Tier 2 fleet scheduler fronts N daemons without
API rework.

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
dies, so nothing leaks to the other runs sharing the bridge. Entry
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

The bridge is `--internal`: no NAT, no default route. The proxy on its
gateway is the only way out, and runs find it through `HTTP_PROXY` /
`HTTPS_PROXY`. Everything follows from that:

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


## Never

Bind the API publicly; join runs to the `teploy` network; mount the
Docker socket into a run.

## Testing

`go test ./...` (interface-mocked) · `go test -tags integration ./...`
(real Docker on a disposable box).

## Snapshots (M3)

| Route | Does |
|---|---|
| `POST /v1/runs/{id}/snapshot` | Commit the run's filesystem → `{image: "teploy-sbx-snap:<ulid>"}`; a later `POST /v1/runs` with that image boots from it |
| `DELETE /v1/snapshots?image=<ref>` | Delete a snapshot image (only `teploy-sbx-snap:*` refs are deletable) |

Snapshots deliberately survive the TTL reaper — they exist so state can
outlive a container (a parked agent run restores days later). Deletion
is explicit and owned by the caller.

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
