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
| `POST /v1/runs` | `{image, env?, ttlSec?, network?, limits?}` → `{id, server, expiresAt}` — network `none` (default) or `egress`; defaults 1 CPU / 1 GB / 256 pids, `no-new-privileges`, never the `teploy` app network |
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
