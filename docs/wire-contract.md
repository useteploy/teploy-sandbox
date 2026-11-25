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
| `access` | object | Only when the daemon has access on (`--access-addr`): `{epoch, ports: [{port, visibility, protocol}], streams}`. See [Access](#access) |

### `usage`

| Field | Type | Meaning |
|---|---|---|
| `runningSec` | int | Seconds spent running, summed across stop and resume, current stretch included. Always present |
| `cpuSeconds` | number | Optional. CPU time used. Only grows |
| `rxBytes`, `txBytes` | int | Optional. Bytes the run received / sent on its network device. Only grow |
| `diskBytes` | int | Optional. The latest observed size of what the run has written (Docker: the container's writable layer; VM: the volume's ZFS `used`). A level: it falls when files are deleted |
| `sampledAt` | time | Optional. When the observations above were last taken |
| `accessRxBytes`, `accessTxBytes` | int | Only with access on. Bytes the guest received / sent through access streams (they do not cross the run's network device, so `rxBytes`/`txBytes` do not count them). Only grow; carried across stop, resume and a daemon restart |
| `accessAnonRxBytes`, `accessAnonTxBytes` | int | Only with access on. The part of the two above that went through streams opened without a grant (public ports) |

The optional fields appear only when the daemon samples usage
(`--usage-interval`, off by default) and the driver could read them.
`diskBytes` is sampled on the first round and every tenth after it (it
is the expensive read), not at a stop; the rest every round.
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
| `access` | Only with access on: `{enabled: true, streams, streamsMax}` |
| `disk` | Optional: `{kind, name, usedBytes, freeBytes}`. `kind` `zfs-pool` (VM driver; `name` is the pool) or `docker-data-dir` (Docker; `name` is the data root's path from `docker info`, statfs'd on the daemon's own filesystem: right only for a daemon on the Docker host, wrong or absent against a remote Docker or a Docker VM). `freeBytes` is what can still be written. Absent when the probe fails or takes over 5 s |

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
- The response headers (with `X-Exec-Id`) are sent at once, before the
  command has printed anything.
- `timeoutSec` may be at most the daemon's
  `--exec-recoverable-max-timeout` (default 3600); more is a 400. Plain
  execs have no such cap.
- Offsets: every output byte, stdout and stderr together in the order
  the stream sends them, has an offset counting from 0. **A client that
  wants to resume must ask for `outputEncoding: "base64"`**: then the
  number of decoded bytes it has received is exactly the offset to
  resume from. In text mode there is no offset guarantee (bytes are
  held back across split UTF-8 characters and invalid bytes are
  replaced); a text-mode client can only re-read from a tail or from 0.

| Route | Success | Body |
|---|---|---|
| `GET /v1/runs/{id}/execs` | 200 | `{execs: [status…]}`, oldest first: the way back for a client that lost an ID |
| `GET /v1/runs/{id}/execs/{execId}` | 200 | `{exec: status}` |
| `DELETE /v1/runs/{id}/execs/{execId}` | 202 | `{exec: status}`: ends a running command. Idempotent: on one that already ended it changes nothing. The status turns `cancelled` once the runtime has returned; poll it |
| `GET /v1/runs/{id}/execs/{execId}/output?since=&limit=` | 200 | `{execId, output}` |

The status object:

| Field | Meaning |
|---|---|
| `id`, `runId` | |
| `state` | `running`, `exited`, `timedOut`, `cancelled` (by DELETE, or by the daemon before an expiry or shutdown stop of the run) or `failed` (the sandbox could not run it to the end: the run was stopped or destroyed under it, the runtime failed) |
| `startedAt` | |
| `finishedAt`, `expiresAt` | Once finished; the record goes at `expiresAt` |
| `exitCode` | `null` while running, as on the `exit` frame after |
| `timedOut` | |
| `signal` | Optional: n when `exitCode` is 128+n and the exec did not time out. Inferred: a command that itself exits 137 looks the same |
| `error` | Optional, on `failed` and `cancelled`: why |
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
- Records: 8 per run and 64 per daemon, so one run can hold at most an
  eighth of the daemon's slots. A finished record makes room for
  a new one, oldest first; running ones are never evicted, so a
  recoverable exec beyond either bound with every slot running is a 503.
- Cancelling: under the VM driver the guest kills the command's process
  group. Under the Docker driver the `docker exec` client is killed and
  the record and the run are released at once, but the process inside
  the container runs on until its own `timeoutSec` (Docker has no way to
  signal an exec's process from outside) or until the run stops.
- Before a stop the daemon makes on its own (a run's `onExpire: "stop"`
  deadline, or a graceful shutdown) it cancels the run's running
  recoverable execs and waits up to 10 s for them, so a detached exec
  cannot keep the run from being stopped and lose its state. A stop a
  caller asks for still answers 409 `busy` while an exec runs.
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

## Access

SSH and published ports reach runs through an **edge** (a separate
program, not part of this release) that opens byte streams on the
daemon's **access listener**. Everything in this section exists only
when the daemon is started with `--access-addr`; without it there are
no access routes, no `access` field and no access usage, and the daemon
is byte for byte what it was. The control API never carries access
traffic, and the access listener never serves the control API.

### Access grants

An access grant is

```
tsg1.<base64url(payload JSON)>.<base64url(Ed25519 signature)>
```

base64url without padding; the signature is over the ASCII bytes
`tsg1.` followed by the payload's base64url text. The algorithm is fixed
(there is no `alg`). The payload is at most 1024 bytes. The Go package
`github.com/useteploy/teploy-sandbox/accessgrant` signs and verifies
grants; it has no dependencies.

| Claim | Type | Meaning |
|---|---|---|
| `v` | int | `1`. A verifier rejects any other value |
| `kid` | string | The issuer key that signed it, `[A-Za-z0-9._-]{1,64}` |
| `iss` | string | Who issued it, for logs (`cloud`, `edge:<name>`, `op:<name>`) |
| `aud` | string | The user-content domain it is for; must equal the daemon's configured audience |
| `run` | string | The run ID |
| `scp` | [string] | 1-16 scopes, none repeated: `ssh`, `http:<port>`, `http:*`, `tcp:<port>`, `tcp:*` (port 1-65535, no leading zero). Any other value makes the grant malformed |
| `ep` | int | The run's access epoch **as the issuer read it from the run** (the run object's `access.epoch`, or the access listener's lookup). Never the issuer's clock. 0 to 2^53-1 |
| `cnf` | string | Optional: binds the grant to one SSH public key, `sha256:` + unpadded standard base64 of the SHA-256 of the key's wire encoding |
| `own`, `ref` | bool, string | Optional, together: an owner proof (lifetime at most 60 s) vouching for the grant whose `jti` is `ref`. An owner proof is not an access grant anywhere |
| `iat`, `exp` | int | Unix seconds; `exp - iat` at most 31 days; `iat` at most 5 minutes in the future |
| `jti` | string | The grant's ID, `[A-Za-z0-9._-]{1,64}` |
| `org` | string | Optional, opaque, for logs only |

Verification is strict: the signature is checked against the configured
keys before the payload is parsed; the payload must be one JSON object
with no duplicate key (unicode escapes included) and no key that differs
from a claim's name only in case; every claim must have exactly its type
(integers in plain decimal, no `null`); an optional claim (`cnf`,
`own`, `ref`, `org`) is either absent or not empty — `"cnf":""`,
`"own":false`, `"ref":""` and `"org":""` are malformed; unknown claims
are ignored. A keyring may not hold one public key under two `kid`s. A
claim that restricts what a grant allows is never added without raising
`v`, because a verifier that ignores it would drop the restriction.

What a grant allows depends on where it is presented:

| Presented at | Accepts | Refuses |
|---|---|---|
| The edge's HTTPS front | `http:<port>` for the port, or `http:*` | a grant with `cnf`; a grant with any `ssh` or `tcp:` scope |
| An SSH session channel | `ssh`, with `cnf` (checked against the authenticated key) | no `cnf` |
| An SSH `direct-tcpip` channel | `tcp:<port>` or `tcp:*`, with `cnf` | a grant with any `http:` scope; no `cnf` |
| The daemon's `connect` | `http:` or `tcp:` covering the port | `ssh` alone |
| The daemon's `session` (later) | `ssh` | everything else |

An owner proof is accepted nowhere.

### The access epoch

`access.epoch` is an opaque, strictly increasing integer per run. A
grant is accepted only while its `ep` is at least the run's epoch, so
raising the epoch revokes every grant issued before. It is never
compared with a clock:

- a new run (create or fork) starts at the unix time of its creation;
- a revoke sets it to `max(now, epoch + 1)` and answers the new value
  (two revokes in one second, or a clock set back, still raise it);
- a resume takes `max(epoch, accessEpoch)` when the caller passes one;
- a run that **moved** (any resume of a run this daemon read from its
  remote record: stopped on another daemon, taken over, or brought back
  from its last stop after a restart lost it) resumes with
  `max(epoch + 1, accessEpoch + 1, now)`: strictly above anything a grant
  can have copied, so moving a run revokes all of its grants;
- with remote storage, the epoch and the ports travel in the run's remote
  record: a revoke and a port change write them there before they
  answer, and a resume of a run this daemon already holds (a takeover)
  writes the epoch its move raised there before the run boots;
- a revoke or port change while a stop is publishing the run's first
  record answers 502 `access-write-through` (busy), and one made while
  the run has no record this daemon knows of (its first publish failed,
  or its answer was lost) answers 200 without a write. Both still reach
  the record: every publish, once its record lands, writes whatever the
  newest record lacks of the run's access state. The change is in the
  registry file before it is answered, so a daemon that restarts in
  between publishes it at its next upkeep (or, if another daemon wrote
  the record meanwhile, merges it as below);
- the epoch never goes down: when a daemon takes a newer remote record
  of a run it holds stopped, it keeps the higher of its own epoch and
  the record's, and a daemon that drops a run whose epoch was ahead of
  its record keeps that epoch should the run come back. The ports are the
  record's, unless they were changed on this daemon since it last wrote
  or took a record (a change answered 502): then a port is public only if
  both say so. Whatever is ahead of the record is written to it;
- a running copy of a run that another daemon took over (`remote.state`
  `superseded`) keeps running, but its access streams are closed and no
  more are admitted once this daemon sees the takeover — at its next
  sync, or the next request that reads the run's record. Until then it
  serves the access state it had.

These guarantees assume a run's records in remote storage only move
forward. **Never roll a bucket back while daemons use it**: a bucket
restored from an older backup can let a daemon adopt a record below a
revoke or unpublish already answered with success. Stop the fleet to
restore storage, then revoke and set the ports again.

A caller that stores epochs (a control plane minting grants) stores the
epoch from every run object it receives and passes it as `accessEpoch`
on every resume.

### Control routes (control API, bearer token; only with access on)

| Route | Request | Success | Errors |
|---|---|---|---|
| `PUT /v1/runs/{id}/ports/{port}` | `{visibility: "public"\|"private", protocol?: "http"\|"h2c"}` | 200, the run | 400 bad port or field, or more than 16 public ports; 404; 500 `access-not-persisted`; 502 `access-write-through` |
| `DELETE /v1/runs/{id}/ports/{port}` | | 200, the run | 404; 500 `access-not-persisted`; 502 `access-write-through` |
| `POST /v1/runs/{id}/access/revoke` | | 200, the run with the new `access.epoch` | 404; 500 `access-not-persisted`; 502 `access-write-through` |
| `GET /v1/access/config` | | 200 `{audience, kids, edgeDenylist, listener, enabled, managedByFile}` | |
| `PUT /v1/access/config` | `{audience, issuerKeys: [{kid, ed25519, notAfter?}], edgeDenylist: [names]}` | 204 | 400; 409 when `--access-config` manages it |
| `POST /v1/runs/{id}/resume` | gains `accessEpoch?` | as before | 400 when negative or above 2^53-1 - 2^20 (an epoch at the maximum could never be raised again) |

A write-through holds the run for up to 30 s: execs, writes, stops and
lease acquires on it meanwhile answer 409 `busy`, and a revoke or port
change made while a stop, resume, fork or delete holds the run answers
502 and is to be repeated.

Ports are data and may be set while the run is stopped. Making a public
port private, or deleting it, closes that port's anonymous streams. A
revoke closes all of the run's access streams. A 502
`access-write-through` means the epoch was raised and the streams closed
on this daemon, but the new epoch is not in remote storage; its body
carries `epoch`. Revoke again: it raises the epoch once more and retries
the write. On a port route it means the same of the port change: it
holds on this daemon and is not in remote storage; repeat it. A 500
`access-not-persisted` (body with `epoch`) means the change holds on
this daemon but the registry file could not be written, so a restart
before the next good write would undo it; repeat it once the state
directory is writable. Unknown fields in these routes' bodies are 400. The
configuration is stored 0600 in `--state-dir`; `ed25519` is a base64
public key, and `GET` shows key IDs only. A fork's child starts with a
fresh epoch and no ports.

### Access listener

`--access-addr HOST:PORT` (7448 by convention) speaks HTTP/2 over TLS
1.3 with a client certificate required and verified during the
handshake, before any HTTP is read: it must chain to `--access-client-ca`
(the edge-client CA, which must not be the CA of the daemon's own
certificate), name exactly one edge as `URI:teploy-edge://<name>`, and
the name must not be on the denylist. `--access-addr unix:/path` (Linux)
speaks h2c on a 0660 socket and admits peers by uid or gid (SO_PEERCRED).
TCP without TLS is refused at start. HTTP/1.1 is accepted too, for
debugging.

One connection serves one run and one kind of stream: anonymous (no
`Teploy-Grant`), or the streams of one grant (by its `jti`). The first
admitted stream binds it, and a stream for another run, or of another
kind, on it is 421 `wrong-connection`. Open one connection per run and
kind, so that a public port's visitors, or one share link's holders,
never share flow control with the owner's streams.

A connection counts against its edge's `--access-edge-conns` (default:
twice the runs the stream cap allows for) only until its first stream
binds it to a run; from then on it counts against that run's
connections from that edge: at most 2 anonymous and 6 granted ones, so
grant holders cannot lock a public port's visitors out. Past that, a new
connection's stream is 429 `run-connections`. Any refusal on a
connection that serves no run yet closes it once the answer is out
(GOAWAY), so refused requests cannot fill the edge's cap. No run, and no
tenant's grants, can use up the connections another run needs.

An edge's HTTP/2 receive window for one daemon connection must cover 16
streams at the edge's per-stream window: a stalled anonymous stream is
only detected toward the guest (below), so a visitor that does not read
holds the edge's window, not the daemon's.

A connection holds only as long as the certificate it was opened with:
at the earliest `notAfter` of its verified chain the daemon closes it,
ending its streams, and a stream asked for on it after that is 403
`edge-expired`. The expiry is also checked against the wall clock on
every read and by the periodic sweep, so a clock corrected forward ends
the streams too. Denylisting an edge ends its open streams at once. Removing an issuer key from the configuration, or
replacing it under its `kid`, closes the streams it admitted; a key's
`notAfter` brought forward ends them by then.

| Route | Headers | Success | Errors (`type` suffix) |
|---|---|---|---|
| `GET /v1/access/runs/{id}` | | 200 `{id, state, epoch, publicPorts: [{port, protocol}]}` | 404 `not-here` |
| `POST /v1/access/runs/{id}/connect?port=P` | `Teploy-Grant?`; `Teploy-Edge-Request?` | 200, then raw bytes both ways | 400 `bad-request`; 401 `grant-invalid`, `grant-expired`, `revoked`; 403 `scope`, `not-public`, `edge-denied`, `edge-expired`; 404 `not-here`; 409 `stopped`; 421 `wrong-connection`; 429 `run-streams`, `anon-streams`, `run-connections`; 502 `refused`, `guest-agent`; 503 `at-capacity`; 501 `unsupported-driver` |

A lookup binds no connection. One answered 404, or answered for a run
that is not running, on a connection that serves no run yet closes it,
as every refused `connect` on such a connection does, so lookups of
made-up or stopped runs cannot fill the edge's connection cap. An edge should send lookups on one connection of its
own, or on the connection that serves the run.

`connect`: the response body is what the guest sends, the request body
what it receives; the end of the request body is passed to the guest as
a half-close, and the guest closing its side ends the stream. Without
`Teploy-Grant` the port must be public on the run. A granted stream is
closed at its grant's `exp`; every stream of a run is closed on revoke,
stop and destroy; anonymous streams of a port on unpublish. A stream
idle for an hour is closed. An anonymous stream whose write to the guest
has been blocked for 30 seconds (a guest that does not read: the edge's
bytes then sit in the connection's shared window) is closed. A visitor
that does not read (a paused `<video>`) is not a stall: it holds only its
own stream's send window, and is bounded by the idle timeout and the
caps. A guest that reads just often enough (a trickle, one write per
less than 30 s) is not caught; it holds at most its stream's 256 KiB
window, and the 16 anonymous streams of a run at most the anonymous
connection's 4 MiB — that run's visitors, never its owner. Every other path is 404. Problem responses
never echo a grant. `Teploy-Edge-Request` is logged only when it is at
most 64 characters of `[A-Za-z0-9._-]`.

Caps: per run 64 streams, at most 16 without a grant, and 4 of the 64
only for sessions; per daemon `--access-streams-max`. Rates, each way:
granted streams of a run together `--access-mbit`, anonymous streams of
a run together `--access-anon-mbit` (20), all streams
`--access-total-mbit` (2000).

`connect` reaches the guest port on the VM driver only (through the
guest agent; the guest's loopback, `127.0.0.1` then `::1`). An agent
older than guest protocol version 2 answers 502 `guest-agent`, whose
`detail` is fixed text: what the guest agent said is logged (shortened)
and never sent to the edge. The
Docker driver answers 501 `unsupported-driver` in this release, and
`session` (SSH shells) is not built yet.

## Not promised

- Ordering of `GET /v1/runs` and of anything in a list except `execs`.
- The text of `detail`, log lines and `title`.
- That a run's container or VM keeps the same internal name.
- Anything about a run after a daemon crash beyond what the README's
  "Surviving a restart" says.
