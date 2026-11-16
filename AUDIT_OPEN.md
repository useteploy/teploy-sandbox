# Open audit items

Unresolved findings for this repository from the ChatGPT-led audit series (2026-09-09 through 2026-09-11, passes 1-5; register: teploy-neutron-lullmail expanded audit). Every P0/P1 finding has been fixed and verified; the items below are the remaining P2/P3 tail plus one item needing validation. Fields are quoted from the audit register; line references point at the review commits listed per item where recorded.

Open source implementations: 0. One deliberate legacy SSE compatibility residual requires upstream consumer opt-in; deployment acceptance gates are listed below.

## useteploy__teploy-sandbox-05 - P2 - Compatibility residual

**Make SSE output encoding safe for carriage returns and split UTF-8**

- Kind: Confirmed from source
- Evidence: sseWriter.frame splits only on LF and writes raw data after data:. A CR in command output is still a line delimiter in SSE, and arbitrary pipe chunks can split a multibyte character across separately framed events. Writer errors are also discarded.
- Impact: Progress output can be corrupted or interpreted as SSE fields; disconnected streams can continue to appear successfully written.
- Proposed fix: Use a defined JSON/base64 payload per event or a stateful UTF-8-safe encoder that escapes all line terminators. Propagate writer failures so execution/output handling can stop appropriately.
- Acceptance test: Round-trip CR progress output, mixed CRLF, a multibyte code point split across writes, and a writer that fails after one frame.
- Review commit: `00c2d7de021f2e005d53125b833a8ff87033b455` (last reviewed 2026-09-10)


## Resolution log (2026-09-12)

- teploy-sandbox-06, -07, -08: FIXED - bounded reads/uploads (64 MiB each), tunnel registry closed by Pool.Close/Shutdown, duplicate OpenFor now replace-after-close. See audit commits.
- teploy-sandbox-05: PARTIALLY FIXED - writer errors now propagate (a disconnected stream no longer reports successful writes). UPSTREAM: raw CR bytes and UTF-8 chunks split across frames are defined by the pinned SSE frame contract that @neutron-build/agents' SandboxExecutor consumes (it rejoins data: lines with \n); changing the encoding is a contract change owned upstream, not a unilateral fix here.

## 2026-09-19 — gVisor snapshot persistence

Live approval testing found that a cold gVisor run could snapshot successfully
but restore an empty workspace. `runsc` defaults to a private rootfs overlay;
Docker commit does not capture those writes. Explicit per-container
`dev.gvisor.flag.overlay2=none` makes writes visible to the container layer
without replacing gVisor or changing host Docker configuration. The integration
suite now checks repository metadata and uncommitted file bytes after restore,
with `SBX_TEST_RUNTIME=runsc` selecting the real boundary. Warm bind mounts are
still not part of image snapshots; callers must retain them separately.

## Warm-volume snapshot fix — 2026-09-22

Closed: snapshots of warm runs lost the workspace (docker commit skips bind
mounts; the default warm mount IS /work). `2a89f72`+ bake volume bytes into
the image via a create-only staging container, and create-from-snapshot
boots the volume EMPTY (never template-merged) and seeds it from the image
through the live mount; a seed failure fails the create. Recognised by ref
namespace — containerd image stores drop commit labels (measured). Proven
byte-exact on real Docker (compute-1): tracked edits, untracked files, and
a deleted file does not resurrect. Daemon deployed on compute-1 (bak:
`teploy-sandbox.bak-20260922`). The 2026-09-07 Forgejo issue is fixed by
this; verify-and-close it.

Still open, found while proving: (1) `ReadFile`'s `cat | head` pipeline
returns empty-with-no-error for a MISSING file (head eats cat's exit) —
callers cannot distinguish missing from empty; (2) the integration suite's
`TestRealDockerLifecycle` hardcodes alpine:3.20, whose busybox timeout
rejects the exec wrapper's `--kill-after` (pre-existing, fails on this box
independent of this change).

## 2026-10-07 source reconciliation

- S-01: authenticated private proxies; v2 internal bridge with ICC disabled;
  host INPUT denies services outside active proxy listeners. Missing firewall
  enforcement disables allowlist creation. Proxy port grants are revoked.
- S-02: rooted, descriptor-validated, nonblocking regular-file cache reads;
  bounded lockfiles/copies, cancellation-aware copies and frozen capture.
- S-03: retryable teardown preserves registry and mounted volume until Docker
  confirms removal. Failed create/restore rollback remains tracked for reaping.
- S-04: direct bounded file reads preserve missing-file errors and explicitly
  reject cap+1 bytes. Exact-cap and empty files succeed.
- S-05: closing admission synchronizes CONNECT registration and goroutine
  ownership, including a hijack that finishes after shutdown.
- S-06: exclusive cache-root ownership and conservative startup reconciliation
  retain all Docker-mounted volumes and reclaim only unowned run directories.
- S-07: captures exclude API mutation/teardown and pause background writers.
- S-08: independent bounded cleanup, durable scratch ownership and startup
  recovery; cancellation still attempts thaw and every owned cleanup.
- S-09: serialized publication, boot pinning and reclamation prevent stale
  cleaners from deleting the current generation.
- useteploy__teploy-sandbox-05: incremental UTF-8-safe text SSE keeps its event
  schema and raw CR bytes, propagates write failures and adds explicit opt-in
  base64 for safely framed lossless arbitrary bytes. The default raw-CR wire
  contract is deliberately retained. Closing the remaining CR/EventSource
  concern requires the upstream consumer to request/decode base64.
- The standing missing-read and Alpine lifecycle notes are implemented: direct
  head reads preserve errors and the lifecycle fixture uses coreutils timeout.

Acceptance still required before deployment: the complete Docker lifecycle,
warm/cold capture/restore and native Docker host/peer isolation matrix on a
healthy daemon; the gVisor matrix on a host with runsc. Source/unit/race proof
must not be treated as completion of those runtime gates. The native host
firewall has a separate isolated Linux namespace deny/allow/revoke fixture.

Legacy unlabeled containers are retained by scoped startup cleanup. Operators
must drain older workloads when migrating deployment; startup never sweeps
containers belonging to another daemon identity.

## 2026-11-15 — persistent runs (stop / resume / fork, durable registry)

Added, all additive on the wire (no existing field, status or default
changed for a caller that does not use them):

- Run `state` (`running`/`stopped`), `labels`, `onExpire`
  (`destroy`/`stop`), `usage.runningSec`, `stoppedAt`, `retainUntil`,
  `forkedFrom`.
- `POST /v1/runs/{id}/stop`, `/resume`, `/fork`; `GET /v1/capacity`.
  Create, resume and fork share one boot path.
- Reaper: stops instead of destroying when `onExpire` is `stop` (a failed
  stop is retried for one hour past the deadline, then the run is
  destroyed); deletes a stopped run at
  `retainUntil` (`--stopped-retention`, default 14 days).
- Durable registry (`--state-dir`): stopped runs survive a restart; a
  corrupt or unreadable file refuses the start; graceful shutdown stops
  `onExpire: stop` runs instead of destroying them. An unwritable
  DEFAULT state dir falls back to memory with a warning, so an existing
  deployment's flags keep working; a named one refuses the start.

Review of the branch (same day) fixed two state-losing defects: the
reaper acting on a stale copy of a run that was resumed or stopped
during its pass, and a stop discarding its capture when the client
disconnected before the container was removed.

Left open by that review:

- Each stop commits on top of the previous snapshot, so the snapshot's
  layer chain grows by one per cycle. Measured with
  `SBX_TEST_CYCLES=150 go test -tags integration -run TestRealStopResumeSoak .`
  on Docker 29.5 with the containerd image store (`overlayfs`): 150 cycles
  pass, one snapshot image held at a time, none leaked; a stop plus resume
  takes about 0.6 s at first and about 1.1 s by cycle 150. Not measured on
  the older `overlay2` storage driver, which caps an image at about 125
  layers; run the soak there before relying on long-lived runs.
- A crash between a capture and the registry write leaks one image, and
  registry-owned and caller-owned snapshots share the `teploy-sbx-snap:`
  namespace, so nothing can garbage-collect them safely yet.
- Stop answers 200 when the registry write fails (logged, retried on the
  next tick); a restart inside that window loses the run.
- Shutdown stops share the 45-second cleanup budget.

**Run against real Docker 2026-11-15** (Docker 29.5, arm64, `runc`,
Linux 6.8, as root): the whole integration suite passes, including
`TestRealStopResumeAcrossRestart` cold and warm and the host firewall
fixtures. CI runs the same suite as root on an x86-64 runner and passes.
Still unverified: `SBX_TEST_RUNTIME=runsc`, and `TestRealSandboxUser`
(skipped without `SBX_TEST_USER_IMAGE`).
The three assumptions only a real daemon could confirm held on that image
store: an image a container was created from cannot be deleted until the
container is gone, while a snapshot a later one was committed on top of
can; a container can be recreated under the same name straight after
`docker rm -f`; and a warm run's volume directory can be released and
seeded again under the same path.

Known limits, deliberate in this slice:

- A crash between a capture and the registry write leaks that one image:
  nothing on disk names it yet.
- Deleting a stopped run removes the record even when the image delete
  fails (logged with the ref). The alternative is a record that can
  never be deleted once its image is gone.
- Shutdown stops runs one after another inside the existing 45 s cleanup
  budget. Runs it does not reach are lost with their containers, exactly
  as on a crash.
- A run with `onExpire: stop` that has an exec in flight at every reaper
  tick is never stopped and so outlives its deadline.
- The registry file holds env values in the clear (0600, 0700 dir).

## 2026-11-16 — VM driver, first slice (experimental, off by default)

Added: `--driver vm`, `internal/vm` (Cloud Hypervisor on ZFS volumes),
`internal/guest` and `cmd/teploy-guestd` (the in-guest agent),
`scripts/build-golden.sh`. `Runtime` itself did not change: two optional
interfaces let a driver own its snapshot references (`SnapshotNamer`) and
refuse creates it cannot honour (`CreateAdmitter`). `GET /v1/capacity`
gained `driver` and `nestedVirt`. The Docker driver's behaviour and tests
are unchanged.

Run against a real hypervisor 2026-11-16 (`-tags vmintegration`, as
root; Cloud Hypervisor v54.1, ZFS 2.2, Linux 6.8, arm64, inside a VM
with nested KVM): create, exec, 1 MiB file round trip byte-exact, stop,
a new manager loading the registry, resume, fork of a running run,
destroy, with no VM process, volume or snapshot left behind. In that
nested setup a cold boot to agent-ready took 7 to 10 s, an exec round
trip about 10 ms, a stop 0.35 s.

Found by that run and fixed: volumes were created with the default
`volmode`, so the host exposed every guest partition as a block device
and mounted one run's EFI partition as its own `/boot/efi` by label.
Volumes are now `volmode=dev`.

That fix did not hold. `zfs clone -o volmode=dev` sets the property after
the clone exists, and on ZFS 2.2.2 the kernel made the device node first
for clones of a run's own snapshot (a resume, a fork, a snapshot
holder): the property read `dev` and the guest's partitions were block
devices on the host. The pool must now have `volmode=dev`
itself, which a new volume inherits from its first instant; the daemon
refuses to start without it, and refuses a run device the host would
scan. The live suite checks for partition devices after create, resume,
fork and snapshot.

Not verified:

- An x86-64 host, and bare metal. Boot time and density figures from the
  nested arm64 setup say nothing about either.
- More than two VMs at once, memory pressure, a host out of pool space.
- The first attempt at the live suite ended with the test host itself
  unresponsive. The cause was not established (the `/boot/efi` mix-up
  above was present at the time; the run after the fix was clean). Treat
  host stability under this driver as unproven.
- The code in `internal/vm` and `internal/guest` has had no independent
  review.

Deliberately missing: guest networking and the egress tiers, the warm
repo cache, a pool of pre-booted VMs, nested virtualisation inside a
run, memory reclaim policy, and resource accounting beyond what the
Docker driver reports.

Known limits:

- A snapshot volume left by a crash between a capture and the registry
  write is not swept at start (the same gap as the Docker driver's
  image leak); the startup sweep removes only run volumes and VM
  processes the registry does not name.
- The golden image is trusted: the daemon boots whatever
  `--vm-golden` names.
- A run volume's whole-disk device is probed by the host's udev. A guest
  that writes a filesystem signature over the start of its disk gets a
  `/dev/disk/by-label` or `by-uuid` link on the host under a label it
  chose (confirmed: a vfat labelled by hand appeared at once). Closing
  this takes a udev rule on the host (README), which the daemon neither
  installs nor checks.
