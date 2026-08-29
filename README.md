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
| `POST /v1/runs` | `{image, env?, ttlSec?, network?, limits?, warm?}` → `{id, server, expiresAt, warm?}` — network `none` (default) or `egress`; defaults 1 CPU / 1 GB / 256 pids, `no-new-privileges`, never the `teploy` app network; `warm: {repo, path?}` gives the run a private volume for the repo (below) |
| `POST /v1/runs/{id}/exec` | `{cmd, cwd?, timeoutSec?}` → SSE: `stdout`/`stderr` chunks, then `exit` `{exitCode, timedOut}` |
| `PUT/GET /v1/runs/{id}/files/{path}` | Confined to `/work`; traversal rejected |
| `DELETE /v1/runs/{id}` | Destroy now (the reaper enforces TTLs regardless, default 30 min) |
| `GET /v1/runs`, `GET /health` | List; `{status, version}` |

Run IDs are ULIDs and every response carries a `server` field — nothing
assumes one box, so the Tier 2 fleet scheduler fronts N daemons without
API rework.

Clients: `SandboxExecutor` in `@neutron-build/agents` (the pinned wire
contract); a Go client package follows with the Phase B agent product.

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
