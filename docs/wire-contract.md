# Wire contract

This page is the HTTP contract of `teploy-sandbox serve`: every route, the
fields a client may rely on, the status codes, and what may change. A
client (the Teploy CLI, an SDK, a control plane proxying execs) should
need nothing else. The README explains the behaviour behind the routes;
where the two disagree, the code is right and both pages are bugs.

## Stability

- **Additive only.** A field, a route or an optional request field may be
  added in any release. Nothing listed here is removed, renamed, retyped
  or given a new meaning without a new path prefix (`/v2`).
- **Clients must ignore what they do not know**: unknown response fields,
  unknown `state` values in a future status object (treat them as "not
  finished, ask again"), unknown SSE event names.
- **Absent is not zero.** A field documented as optional ("only when …")
  is left out when the daemon cannot say. A client must not read its
  absence as 0, false or empty.
- **Defaults do not change behaviour.** A request without a newer
  optional field behaves exactly as before that field existed, byte for
  byte on the exec stream.
- Durations are seconds in integer fields named `…Sec`, times are RFC 3339
  strings, sizes are bytes in fields named `…Bytes`, memory is MiB in
  `memoryMb`. IDs are 26-character ULIDs.

## Transport and authentication

- Plain HTTP on loopback or a private network only (`--addr`, default
  `127.0.0.1:7439`). The daemon must never be reachable from the internet.
- Every route except `GET /health` needs `Authorization: Bearer <token>`.
  A missing or wrong token is 401 on every route listed here.
- Request bodies are JSON (`Content-Type` is not checked). Routes whose body
  is optional accept an empty body.
- Every JSON object response carries `server`: the daemon's host name.
  Nothing assumes a single box.

## Errors

Every error is `application/problem+json`:

```json
{"type": "https://neutron.dev/errors/<kind>", "title": "...", "status": 409, "detail": "human-readable reason"}
```

| Status | `type` suffix | Means | Retry? |
|---|---|---|---|
| 400 | `bad-request` | The request is wrong (validation, a field the driver does not support) | No |
| 401 | `unauthorized` | Token missing or wrong | No |
| 404 | `not-found` | No such run, exec, snapshot, file or template; `detail` says which and why | No |
| 409 | `conflict` | The run is in the wrong state for this now: `busy` (an exec, write, capture or removal in flight), stopped, running, lease held or superseded, held by another daemon | Yes, after the condition clears (backoff) |
| 503 | `at-capacity` | The daemon is full (VM limit, recoverable-exec slots) or remote storage is unreachable | Yes, with backoff, or place elsewhere |
| 500 | `internal` | Anything else | Reads yes; mutations only after `GET` shows they did not happen |

`detail` is for humans; do not parse it. The `type` suffix and the status
are the contract.

## Retry rules

- `GET` routes are safe to retry.
- `DELETE /v1/runs/{id}`: a retry after a lost answer gets 404 when the
  first one worked. Treat 404 as done.
- `POST /v1/runs` and `POST /v1/runs/{id}/fork` are **not** idempotent:
  a retry makes a second run. After a lost answer, list runs (match on
  your own `labels`) before trying again.
- `POST …/stop` and `…/resume`: a retry after success is a 409 saying the
  run is already stopped / running. Read the run to confirm.
- `POST …/exec` without `recoverable` is not retryable after the stream
  started: the command may have run. With `recoverable: true`, never
  re-send; fetch the status and output by the exec ID instead (below).

## The run object

Returned by create, stop, resume and fork, and in `GET /v1/runs`.

| Field | Type | Meaning |
|---|---|---|
| `id` | string | ULID, the run's identity for its whole life (stop and resume keep it) |
| `server` | string | Only on single-run responses |
| `image` | string | What it was created from |
| `network` | string | `none`, `allowlist` or `open` |
| `user` | string | The account commands run as (`root` or the sandbox user) |
| `state` | string | `running` or `stopped` |
| `createdAt`, `expiresAt` | time | `expiresAt` is the running deadline; a stopped run ignores it |
| `onExpire` | string | `destroy` or `stop` |
| `labels` | object | Optional; the caller's own |
| `usage` | object | See below; always present |
| `stoppedAt`, `retainUntil` | time | Only while stopped |
| `forkedFrom` | string | Only on a fork |
| `warm` | object | Only with a warm volume: `{repo, booted, lockHash?, repoDir?}` |
| `lease` | object | Only while a lease is held: `{holder, generation, expiresAt}` |
| `remote` | object | Only with remote storage, on a stopped run: `{state, generation?, snapshot?, local, storedBytes?, uploadMs?, incremental?, durableAt?, error?}`, `state` one of `pending`, `durable`, `failed`, `superseded` |

### `usage`

| Field | Type | Meaning |
|---|---|---|
| `runningSec` | int | Seconds spent running, summed across stop and resume, current stretch included. Always present |
| `cpuSeconds` | number | Optional. CPU time used. Only grows |
| `rxBytes`, `txBytes` | int | Optional. Bytes the run received / sent on its network device. Only grow |
| `diskBytes` | int | Optional. The latest observed size of what the run has written (Docker: the container's writable layer; VM: the volume's ZFS `used`). A level: it falls when files are deleted |
| `sampledAt` | time | Optional. When the observations above were last taken |

The optional fields appear only when the daemon samples usage
(`--usage-interval`, off by default) and the driver could read them.
They are observations, not a billing ledger: usage after the last sample
and before the container went is not in them (a stop takes one last
sample first; a destroy or a crash does not). The counters only grow for
the life of a run on one daemon: they carry across stop and resume
(and a daemon restart, for a stopped run). A fork starts at zero. A run
resumed on another daemon from remote storage starts at zero there, as
`runningSec` does.

## Routes

### Health and capacity

| Route | Success | Body |
|---|---|---|
| `GET /health` (no token) | 200 | `{status: "ok", version}` |
| `GET /v1/capacity` | 200 | See below |

`GET /v1/capacity`:

| Field | Meaning |
|---|---|
| `driver` | `docker` or `vm` |
| `runtime` | OCI runtime or hypervisor; `default` for Docker's own |
| `nestedVirt` | Whether a run can start VMs itself. Always present |
| `cpus`, `memoryMb` | The host's size |
| `runs` | `{running, stopped, stoppedRemote?}`; `stoppedRemote` only with remote storage |
| `allocated` | `{cpus, memoryMb}`: the limits of running runs (and of the warm pool), not measured use |
| `warmPool` | Only with a VM warm pool: `{sizes: [{cpus, memoryMb, target, ready, booting}]}` |
| `disk` | Optional: `{kind, name, usedBytes, freeBytes}`. `kind` `zfs-pool` (VM driver; `name` is the pool) or `docker-data-dir` (Docker; `name` is the data root's path, read from the filesystem it is on). `freeBytes` is what can still be written. Absent when the probe fails or takes over 5 s |

### Runs

| Route | Request | Success | Errors |
|---|---|---|---|
| `POST /v1/runs` | `{image, env?, ttlSec?, network?, egressAllow?, limits?: {memoryMb?, cpus?, pids?}, warm?: {repo, path?}, user?, labels?, onExpire?}` | 201, the run | 400, 503 |
| `GET /v1/runs` | | 200 `{runs: [run…]}` | |
| `DELETE /v1/runs/{id}` | | 204 | 404, 409 |
| `POST /v1/runs/{id}/stop` | | 200, the run (`state: "stopped"`) | 404, 409 |
| `POST /v1/runs/{id}/resume` | `{ttlSec?, takeover?}` | 200, the run | 400, 404, 409, 503 |
| `POST /v1/runs/{id}/fork` | `{ttlSec?, labels?, onExpire?}` | 201, the new run | 400, 404, 409, 503 |

`ttlSec` defaults to 1800 and is at most 86400. `network` defaults to
`none`. Limits default to 1 CPU, 1024 MiB and 256 pids.

### Exec

`POST /v1/runs/{id}/exec`

Request: `{cmd, cwd?, timeoutSec?, env?, outputEncoding?, owner?, generation?, recoverable?}`.

- `cmd` runs under `sh -c` in `/work` (or `cwd`, which must stay inside
  it). `timeoutSec` defaults to 120.
- `env`: name → value, at most 64 variables / 64 KiB, POSIX names, no NUL
  or line breaks.
- `outputEncoding`: absent (UTF-8 text) or `base64` (byte exact).
- `owner` + `generation`: the lease credential, required only while the
  run holds a lease.
- `recoverable`: see below.

Errors before the stream: 400, 404, 409 (stopped, busy, lease), 503
(no recoverable-exec slot). After the 200 the answer is a
`text/event-stream`:

```
event: stdout
data: <chunk>

event: stderr
data: <chunk>

event: exit
data: {"exitCode":0,"timedOut":false}
```

- A chunk with line feeds is split over several `data:` lines; join them
  with `\n`. In text mode, invalid UTF-8 becomes U+FFFD and carriage
  returns are sent raw. In `base64` mode every chunk is one base64 line.
- `exit` is always the last frame. `exitCode` is the command's, 128+n
  when a signal killed it, -1 when the sandbox failed (a `stderr` chunk
  starting `sandbox: ` says why). `timedOut` is true when the timeout
  ended it.
- Without `recoverable`, closing the stream ends the command.

### Recoverable execs

With `"recoverable": true`:

- The 200 carries `X-Exec-Id: <ulid>`. The stream is byte-identical to
  the same exec without the field.
- The command no longer depends on the request: closing the stream (or
  losing the connection, or the client restarting) leaves it running to
  its end or its timeout.
- Offsets: every output byte, stdout and stderr together in the order
  the stream sends them, has an offset counting from 0. In `base64` mode
  the number of decoded bytes a client has received is exactly the
  offset to resume from. In text mode it is exact unless the output had
  invalid UTF-8 or the stream broke inside a multi-byte character, so
  use `base64` when resuming matters.

| Route | Success | Body |
|---|---|---|
| `GET /v1/runs/{id}/execs` | 200 | `{execs: [status…]}`, oldest first: the way back for a client that lost an ID |
| `GET /v1/runs/{id}/execs/{execId}` | 200 | `{exec: status}` |
| `GET /v1/runs/{id}/execs/{execId}/output?since=&limit=` | 200 | `{execId, output}` |

The status object:

| Field | Meaning |
|---|---|
| `id`, `runId` | |
| `state` | `running`, `exited`, `timedOut` or `failed` (the sandbox could not run it to the end: the run was stopped or destroyed under it, the runtime failed) |
| `startedAt` | |
| `finishedAt`, `expiresAt` | Once finished; the record goes at `expiresAt` |
| `exitCode` | `null` while running, as on the `exit` frame after |
| `timedOut` | |
| `signal` | Optional: n when `exitCode` is 128+n and the exec did not time out. Inferred: a command that itself exits 137 looks the same |
| `error` | Optional, on `failed` |
| `detached` | The stream that started it went away before it ended |
| `output` | `{start, end, capBytes}`: offsets still held are `[start, end)`; `end` is every byte written so far |

Output reads:

- `since` (optional): the offset to read from. Without it the read is
  the last `limit` bytes (a tail).
- `limit` (optional): bytes to return, default 65536, capped at the
  buffer size.
- Answer: `{start, next, end, truncated, done, chunks: [{stream, offset, data}]}`.
  `data` is base64. Chunks are split where the stream changes; a read
  returns at most 4096 chunks and stops early. Continue with
  `since=next` until `done` (the command ended and `next == end`).
  `truncated` says bytes from `since` have already left the buffer, so
  `start` is later than asked.
- 400 for a `since` below 0 or past `end`, or a bad `limit`.

Limits and lifetime (constants, not configurable in this release):

- Output: the last 1 MiB per exec (`capBytes`); older bytes are dropped.
- Records: 16 per run and 64 per daemon. A finished record makes room for
  a new one, oldest first; running ones are never evicted, so a
  recoverable exec beyond either bound with every slot running is a 503.
- A finished record is kept 15 minutes. Every record of a run goes when
  the run is destroyed (status lookups for it then answer 404 for the
  run). A stop keeps them.
- **Records are memory only.** A daemon restart loses all of them; a
  lookup then answers at once with 404 and a `detail` saying records are
  lost on restart. A restart also ends every running command (running
  runs do not survive it), so a 404 for an exec you know started means
  "outcome unknown", not "succeeded".

### Files

| Route | Request | Success | Errors |
|---|---|---|---|
| `PUT /v1/runs/{id}/files/{path}` | raw bytes, at most 64 MiB; lease credential as `?owner=&generation=` | 204 | 400, 404, 409 |
| `GET /v1/runs/{id}/files/{path}` | | 200 `application/octet-stream` | 400, 404 (run or file), 409 (stopped) |

`path` is relative to `/work`; traversal is a 400. Reads are at most
64 MiB.

### Leases

| Route | Request | Success | Errors |
|---|---|---|---|
| `POST /v1/runs/{id}/lease` | `{owner, ttlSec}` | 200 `{lease: {holder, generation, expiresAt}}` | 400, 404, 409 |
| `POST /v1/runs/{id}/lease/renew` | `{owner, generation, ttlSec}` | 200 `{lease}` | 400, 404, 409 |
| `POST /v1/runs/{id}/lease/release` | `{owner, generation}` | 204 | 404, 409 |

### Snapshots

| Route | Request | Success | Errors |
|---|---|---|---|
| `POST /v1/runs/{id}/snapshot` | | 201 `{image, remote?: {state, id?, storedBytes?, incremental?, error?}}` | 404, 409 |
| `DELETE /v1/snapshots?image=<ref>` | | 204 | 400 (not a snapshot ref), 409 (an image a run holds), 503 |
| `GET /v1/remote/snapshots` | | 200 `{snapshots: [{id, run?, createdAt, storedBytes}]}` | 400 without remote storage, 503 |

### Warm repo cache

| Route | Request | Success |
|---|---|---|
| `POST /v1/runs/{id}/warm-commit` | `{repo?}` | 201 `{warm: {repo, booted, lockHash, repoDir}}` |
| `GET /v1/runs/{id}/warm` | | 200 `{warm}` |
| `GET /v1/warmcache/{owner}/{name}` | | 200 `{warm: {repo, lockHash, repoDir, gen?, createdAt}}`, 404 when none |
| `DELETE /v1/warmcache/{owner}/{name}` | | 204 |

### Remote storage upkeep (only with remote storage; 400 without)

| Route | Success |
|---|---|
| `POST /v1/remote/sync` | 200 `{remote, changed}` |
| `POST /v1/remote/collect` | 204 |
| `POST /v1/remote/rotate` | 200 `{manifestsRewrapped, manifestsCurrent, manifestsSkipped, recordsRewrapped, recordsCurrent, recordsRunning, recordsConflicted, recordsUnfenced, recordsDestroyed, recordsRunningPrevious, recordsDestroyedPrevious, localKeysRewrapped, localKeysFailed, previousKeyNeeded, previousKeyNeededFor}` |
| `POST /v1/remote/scrub` | 200 `{checked, notWhole, unreachable}` |

## Not promised

- Ordering of `GET /v1/runs` and of anything in a list except `execs`.
- The text of `detail`, log lines and `title`.
- That a run's container or VM keeps the same internal name.
- Anything about a run after a daemon crash beyond what the README's
  "Surviving a restart" says.
