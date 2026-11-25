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
  chose (confirmed: a vfat labelled by hand appeared at once). Closed in
  the hardening entry below: the rule is installed by
  `scripts/install-host.sh` and the daemon refuses a host that probes.

## 2026-11-16 — VM driver: host-side hardening

An independent review of the first slice left three things open that
block running strangers' code: the hypervisor ran as root with no
confinement, the host's udev probed every run's disk, and one VM could
use host CPU and memory without bound. All three are now enforced by the
daemon, which refuses to start on a host where any of them cannot be.
`scripts/install-host.sh` sets a host up (idempotent).

What is enforced, and how it was checked on a real hypervisor (Cloud
Hypervisor v54.1, Linux 6.8, ZFS 2.2, arm64, nested KVM; the
`vmintegration` suite, which now starts by requiring the host setup):

- **No root.** Each hypervisor runs under a UID and GID of its own from
  a reserved range (4096 from `--vm-uid-base`), one supplementary group
  (that of `/dev/kvm`), started directly in that identity. Checked from
  `/proc/PID/status` of every VM the suite boots: all four UIDs and GIDs
  equal and non-zero, `CapInh`/`CapPrm`/`CapEff`/`CapAmb` empty,
  `NoNewPrivs: 1`, two VMs with different UIDs, and no process left
  under a VM's UID after destroy. The process is also created in
  network and IPC namespaces of its own (checked: both differ from the
  host's, and the only interface is a loopback that is down). Per-VM UIDs were chosen over one
  shared account because a shared account lets one hypervisor open
  another run's disk and control socket and signal its process.
- **A private disk node.** The hypervisor gets a 0600 block device node
  of its own for its volume, outside udev's reach, instead of a change
  of ownership on the `/dev/zvol` node (udev resets that on every change
  event). Checked: owner, mode and device number of the node; the
  shared node still root's; node gone after destroy.
- **seccomp and Landlock.** `--seccomp true --landlock`. Checked:
  `Seccomp: 2` on every thread; through the hypervisor's API, attaching
  a file that its own UID owns (mode 0666, in a 0755 directory) is
  refused with `Permission denied`, as is another VM's disk node, while
  pause and resume still work. The same request without `--landlock`
  succeeded when tried by hand, so the refusal is Landlock's. A kernel
  without Landlock is refused at start; there is no fallback.
- **A cgroup per VM**, entered at process creation (`CLONE_INTO_CGROUP`):
  `memory.max`, `memory.swap.max=0`, `pids.max`, `cpu.max`. Checked: the
  group holds exactly the hypervisor and has the expected values while
  the VM runs, is gone after destroy, and is killed and removed by the
  next daemon's startup sweep. With the limit lowered by hand to 640 MiB
  under a 1 GiB guest that then used its memory, the host kernel killed
  the hypervisor (`oom_kill 2`, `memory.peak` 640.0 MiB), the run
  failed at once instead of hanging, and destroy left nothing.
- **udev.** At start the daemon writes a labelled filesystem signature
  to a scratch volume and refuses the host if udev records a filesystem
  or makes a link. Checked both ways: before the rule was installed the
  daemon refused this host, naming the rule and the command; after
  `install-host.sh` it started. In the suite a guest writes a vfat
  filesystem with a label over the start of its own disk; the host's
  `blkid` reads that label from the volume, and `/dev/disk/by-*` is
  unchanged after udev is made to look at the device again.

Measured, the same setup, guests with two vCPUs whose memory was
exhausted from inside (`tail /dev/zero` until the guest's kernel killed
it), after 256 MiB of disk writes. Cgroup figures, so kernel memory
charged to the VM (page tables included) is counted:

| Guest | Idle | Peak | Peak minus guest | Limit | Host OOM kills |
|---|---|---|---|---|---|
| 512 MiB | 292 to 301 MiB | 515.7 to 515.8 MiB | 3.7 to 3.8 MiB | 584 MiB | 0 |
| 2048 MiB | 324 to 328 MiB | 2052.5 to 2054.6 MiB | 4.5 to 6.6 MiB | 2128 MiB | 0 |
| 4096 MiB | 447 to 449 MiB | 4058.2 to 4072.6 MiB | below guest size | 4192 MiB | 0 |

(Three or four runs each. The 4 GiB guest's kernel ran out before every
page had been touched.) The limit is the guest's size plus 64 MiB plus
8 MiB per GiB of guest: roughly ten times the overhead seen, because a
VM at its limit is killed and the cost of headroom is bounded. Tasks:
11 idle, 14 to 20 at peak, against a limit of 136 (128 plus 4 per
vCPU). The guest disk is now opened with direct I/O; before that, the
host's page cache for a booted guest was charged to the VM (166 MiB at
boot in one measurement).

Not verified, or not done:

- An x86-64 host and bare metal: every figure above is from nested arm64.
  The overhead allowance in particular should be measured again there.
- Other Cloud Hypervisor versions. Landlock is used as v54.1 does it
  (rules derived from the command line); which paths a different
  version allows was not looked at.
- The seccomp filter was observed to be installed, not exercised: no
  test makes the hypervisor issue a forbidden system call.
- `cpu.max` is set and read back; that a VM is actually held to its
  vCPUs' worth of CPU under contention was not measured.
- No I/O limit: a guest can saturate the pool's disks. Nothing bounds
  how much pool space one run's volume can take beyond the golden
  image's size.
- A hypervisor escape is still a process on the host: unprivileged,
  seccomp-filtered, Landlock-restricted and in a cgroup, but with
  `/dev/kvm` open and the host kernel's system call surface that the
  filter allows. It shares the host's mount and PID namespaces: it
  sees the host's file tree (Landlock is what stops it opening any of
  it) and the host's process list. Landlock does not cover connecting
  to a unix socket by path: see the review entry below.
- The VM UID range is checked against `/etc/passwd` only; accounts
  that exist only in a directory service are not seen. Two daemons on
  one host may share a range (a UID that owns a live process is never
  handed out), but that check is not atomic between daemons; give each
  its own `--vm-uid-base`.
- The daemon itself still runs as root.
- Boot times during this work were two to four times the 7 to 10 s
  recorded above, with and without confinement (an unconfined
  hypervisor started by hand as root at the same moment took as long),
  so the test host was slow, not the driver; no boot-time claim is made
  for the confinement either way.
- This change has had no independent review.


## 2026-11-16 — VM driver: guest networking and the egress tiers

The VM driver refused every network but `none`. It now serves `allowlist`
(with `egressAllow`) and `open`, on a design that assumes the guest is
hostile: it runs its own kernel and can send any frame. The Docker
driver, its tiers and its tests are unchanged. On the wire nothing
changed either: the same request fields, the same run object.

Design, and why:

- One tap per VM in the host's network namespace, routed (a /32 per VM,
  one gateway address on a dummy interface), no bridge. A bridge with
  port isolation would have put the isolation in a setting; without a
  bridge there is no layer-2 path between guests to isolate.
- The daemon creates the tap and passes the open descriptor to Cloud
  Hypervisor (`--net fd=3`). Nothing of the hypervisor's confinement
  gave: it is still unprivileged and in its empty network namespace,
  with seccomp and Landlock on. Cloud Hypervisor v54.1 cannot read the
  tap's MTU from there (the interface is not in its namespace); it logs
  a warning and does not advertise an MTU, which leaves the guest on
  the default of 1500, the tap's own.
- nftables, in tables of the daemon's own: a `netdev` ingress filter
  per tap for what must be judged before the host's ARP and IP code
  (source MAC and address, ARP, IPv6), and one `inet` table for input,
  forward and masquerade, rewritten atomically from the list of running
  VMs. The Docker tiers keep their iptables chain, which exists because
  the bridge is Docker's; the two never touch the same interfaces.
- The guest gets its address, routes and resolvers through its agent,
  not from DHCP and not from the kernel command line: no DHCP server
  for a guest to talk to on the host, and it works with the images that
  already exist. The same step sets the guest's clock, which was wrong
  before this change (a guest has no clock to read at boot; it came up
  weeks behind and no TLS certificate verified).

What is enforced, and how each was checked on a real hypervisor (Cloud
Hypervisor v54.1, Linux 6.8, arm64, nested KVM; `-tags vmintegration`,
`TestVMNetworkIsolation`, `TestVMNetworkTiers`,
`TestVMNetworkAfterADaemonCrash`). Every refusal has a control: a network
namespace beside the host that answers on a private, a shared, a
link-local (169.254.169.254) and a benchmarking address, reached by the
host before a guest tries, and a TCP and UDP listener bound to every
address of the host, reached by a neighbour that is not a guest.

1. **Guest to guest: nothing.** From an open guest and from an allowlist
   guest (which added itself a default route) to another guest that was
   listening: ICMP, TCP, UDP, frames sent straight to the other guest's
   MAC, to broadcast and to multicast, ARP claims of the other guest's
   address and of the gateway's, the other guest's address taken as a
   second address, and IPv6 link-local (ping, TCP, all-nodes,
   all-routers) with IPv6 turned back on in both guests. The target
   received nothing, kept its network, and the host's neighbour entries
   did not move.
2. **Guest to the host itself: only its own proxy port.** TCP to the
   listener's port and to 22, UDP and ICMP, on the gateway address, the
   host's own address and its address facing the neighbour namespace:
   nothing answered and the listener saw nothing. An allowlist run
   connects to its proxy port on the gateway; other runs do not connect
   to that port, and a fork cannot use its source's proxy even with the
   source's credential (nor the reverse). Without the credential the
   proxy answers 407, for HTTP and CONNECT.
3. **Ranges.** An open run on a default driver reached the internet
   (name resolution, HTTP, HTTPS, a raw TCP connection) and none of the
   six non-public addresses the host could reach; its private resolver
   only on port 53. With `--vm-open-private` it reached the private and
   shared addresses, still not the link-local one, and never port 25
   (while port 8080 of the same peer answered). An allowlist run reached
   a host on the built-in list and its own `egressAllow` entry through
   its proxy, got 403 for everything else, and got nowhere around the
   proxy, with or without a default route of its own making.
4. **Spoofing.** Of eleven hand-made frames from a guest, the one with
   its own MAC and address reached the peer; the nine with another MAC
   or source address (the other guest's, the host's, the gateway's, an
   outside one, loopback) were dropped at the tap's ingress filter
   (its counter), and the one for 127.0.0.1 went nowhere.
5. **A tier stays with a run.** Stop, resume and fork of an allowlist
   run and stop and resume of an open run: everything in 2 and 3 holds
   again afterwards. A resumed run has a new credential; a fork has its
   own tap, address, MAC, proxy port and credential.
6. **Teardown and restart.** After stop and after destroy: no tap, no
   route, no element in the sets, no ingress filter, no listener on the
   proxy port, no conntrack entry for the address. After a crash (a new
   driver over a live run): the old rules were the run's tier until the
   new driver wrote its table, from then on the leftover guest reached
   nothing, and the sweep removed the VM, its tap and a stray tap with
   this daemon's prefix, while a tap and a table of another daemon
   identity and an unrelated tap were left alone. The crashed daemon's
   own late teardown changed nothing in the new one's table.
7. **The hypervisor's confinement.** The existing confinement checks
   pass on a VM with a network device: unprivileged UID, no
   capabilities, seccomp on every thread, a network namespace holding
   only a loopback that is down. Its descriptor 3 is `/dev/net/tun` and
   its command line names no interface.

Also checked: with the daemon's tables deleted by hand under running
guests, they were back within the two-second watch interval (0.8 and
1.3 s measured) and 1 and 2 held again. And the checks themselves, by weakening
the firewall and running them: with the guest-to-guest rules removed the
suite reported the other guest reachable; with host input accepted, all
nine host probes open; with port 25 not dropped, the port 25 connection;
with the ingress filter passing any IPv4 source, the spoofed frame at
the peer.

Measured in that nested arm64 setup (not a statement about bare metal):
host-side setup per create (tap, sysctls, conntrack, two nft
transactions, link, route, neighbour: nine short commands) 30 to 130 ms
over sixteen creates, most of them 40 to 50 ms; the guest's own setup,
clock included, 0.3 to 1.2 s; a 1 GiB HTTP download from the neighbour
namespace at 260 to 290 MB/s on the open tier and 250 to 300 MB/s
through the allowlist proxy, against 570 to 840 MB/s from the host
itself to the same Python server (two runs of each). A cold boot took
9 to 15 s in the same runs, so the network adds a few percent to a
create.

Different from the Docker tiers, on purpose:

- `open` is the public internet only, without the host itself and
  without port 25. Docker's `open` is everything the host can route.
  `--vm-open-private` gives back the private, shared, documentation and
  benchmarking ranges; never link-local or the host. A caller can
  therefore tell the drivers apart on `open`; the alternative was to
  give strangers' code the host's LAN and metadata service by default.
- Every allowlist run has its own authenticated proxy; Docker shares an
  unauthenticated one between runs without `egressAllow`.
- An allowlist guest has no resolver at all.

Not done, not verified, or known to be weak:

- An x86-64 host and bare metal. Other Cloud Hypervisor versions: the
  hand-over relies on v54.1 tolerating a tap whose interface it cannot
  see.
- A host with another firewall that drops by default (ufw, firewalld,
  Docker's FORWARD chain). The daemon names such chains in its log at
  start and nothing more; no such host was tried, and guests' traffic
  will not pass there until that firewall allows it.
- `net.ipv4.ip_forward=1` is required and is host-wide: the host now
  routes between all of its interfaces. The daemon's table only judges
  traffic from and to its own taps.
- If something removes the daemon's tables, guests are unfiltered until
  the next check, at most two seconds. While the daemon is dead nothing
  checks. A design in which a missing table fails closed was not found
  with nftables alone.
- After a crash an allowlist guest's rule still admits it to its proxy
  port on the gateway, where nothing listens any more; a process that
  bound that port before the restart would be reachable by that guest.
- No limit on a guest's bandwidth, packet rate or number of tracked
  connections. An open guest can fill the host's connection tracking
  table, which is shared with everything else on the host.
- No IPv6 for guests.
- A guest whose image has no `ip` command cannot be given a network;
  the create (or resume) fails and says so. A run that removes iproute2
  and is then stopped can no longer be resumed.
- Packets a process on the host sends to a guest's address are not
  filtered (the answers are dropped).
- The proxy itself is the Docker tiers' proxy: it dials what the
  allowlist names, including a private address behind an allowed name.
- The seccomp filter was not exercised by a forbidden call; that the
  hypervisor serves a tap under it without being killed is what was
  seen.
- The guest's setup time was measured, not explained.
- This change has had no independent review.


## 2026-11-16 — VM driver: independent review of the hardening and networking

A second reader went through the confinement, the udev check, the host
script, the per-run proxy mode and guest networking (the twelve commits
after the first slice), against a guest that is assumed to have taken
over its hypervisor process. Same host as above (Cloud Hypervisor
v54.1, Linux 6.8, arm64, nested KVM).

Found and fixed:

- **The daemon followed whatever was at a VM's socket paths, as root.**
  A VM's runtime dir belongs to the VM's UID, and Cloud Hypervisor's
  Landlock rules give that directory the rights to remove files and
  make links (seen with strace: the rule for the vsock socket's
  directory carries `REMOVE_FILE` and `MAKE_SYM`). A hypervisor that a
  guest took over could therefore replace its own `vsock.sock` or
  `api.sock` with a link to another run's. Shown on the unfixed daemon,
  with the link made by hand under the VM's UID: an exec addressed to
  run A ran in run B and returned B's file. A stop of A would have
  flushed and paused B. The daemon now reads who listens on the socket
  it reached (`SO_PEERCRED`) and closes the connection before writing
  anything unless it is that VM's UID. With the fix the same exec and
  the same stop are refused and name both UIDs.
- **The udev rule left the storage tools' rule files on.** The rule set
  the flag that turns off udev's filesystem probing. A stock Ubuntu
  server also ships `69-bcache.rules`, which probes every block device
  whose filesystem type udev did not record (every guest disk, once
  the first flag is set) and registers a match with the host kernel's
  bcache driver; the LVM, kpartx and udisks rule files are gated by the
  same second flag (`DM_UDEV_DISABLE_OTHER_RULES_FLAG`), not the first.
  Found by reading the host's rule files; no disk was made to trigger
  it. The rule now sets both flags and the start check refuses a host
  whose udev handled the scratch volume without both (checked: the new
  daemon refused this host with the old rule and started after
  `install-host.sh`, whose second run changed nothing).
- **A guest could make the daemon log two errors every two seconds.** A
  guest that powers off takes its tap along, the kernel removes the
  tap's ingress chain with it, and the watch took that for a filter
  something else had removed, for as long as the run existed. Seen on
  the unfixed daemon; the watch now leaves a tap that is gone alone.

Looked at and found sound: nothing of the daemon's is open in a
hypervisor (its descriptors are its own pipes, the tap, `/dev/kvm`, its
disk node and its sockets); the cgroup's files
are root's; a UID is given back only after its cgroup is empty; the
`/proc/PID` owner the UID pool reads is the effective UID even for a
process that made itself undumpable (tried); the generated ruleset as
`nft list ruleset` prints it matches the description, including the
drop of everything that is not IPv4; the Docker driver takes the same
path through the proxy pool as before (a pool exists there only with a
shared proxy URL, which is the condition the new branch excludes).

Open, and what closing each would take:

- **No private file tree for the hypervisor.** It runs in the host's
  mount namespace. Its UID, its supplementary group and its empty
  network namespace do not stop it connecting to the host's unix
  sockets that anyone may connect to: tried from a process with a VM's
  identity in an empty network namespace, the system D-Bus, journald's
  sockets and the resolver's socket all accepted. Landlock as this
  kernel has it does not judge a connect to a socket by path, so the
  hypervisor's seccomp filter is the only layer between a taken-over
  hypervisor and those services, and the resolver is a way to send
  names out of a run on network `none`. The same holds for device nodes
  the `/dev/kvm` group can open on a stock host (`/dev/vhost-net`,
  `/dev/vhost-vsock`, `/dev/udmabuf`), where Landlock is the only layer.
  Closing it needs a jailer step: the hypervisor started in mount and
  PID namespaces of its own, with a root that holds only its binary,
  the kernel image, its disk node, `/dev/kvm` and its socket directory.
- **The firewall fails open.** Admitted above for a removed table (two
  seconds, or for as long as the daemon is dead). Also: the watch looks
  for the tables and the per-tap chains, not their contents, so a table
  that was flushed rather than deleted is not put back. While the
  tables are gone an allowlist guest reaches every service on the host
  (its tap's forwarding switch keeps it from being routed, nothing
  keeps it from the host's own addresses) and an open guest is routed
  to private and link-local addresses. A design that fails closed needs
  the taps out of the host's main routing: a network namespace or a VRF
  for guests, so that without the rules there is no route to the host's
  services at all.
- **A destroy closes the run's proxy before its VM is gone.** For up to
  the removal's 15 seconds (longer if it has to be retried) the guest
  is still admitted to its old port on the gateway, which the kernel may
  have given to another run's proxy. That proxy asks for its own
  credential, which is all that stands there.
- **A rule file that honours neither udev flag** would still run on a
  guest's disk; the start check sees a filesystem record, a label link
  or a missing flag, nothing else.
- Leftovers that are not swept: the per-identity directories themselves
  (the cgroup, the device node dir and the runtime dir of a daemon
  identity that is never started again stay, empty).
- The VM UID range is not checked against `/etc/subuid` either.
- A hypervisor's resource limits are the daemon's: nothing sets its
  core dump limit (0 where this was run, from the shell that started
  the daemon; a service manager may set it otherwise, and a core of a
  hypervisor is its guest's memory handed to the host's dump handler).


## 2026-11-16 — VM driver: the hypervisor's jail, and a network that does not need its firewall

The review above left two structural gaps: a hypervisor shared the
host's file tree, and the firewall was all that kept a guest from the
host's services. Both are closed by taking the thing away rather than by
forbidding it. Same host as above (Cloud Hypervisor v54.1, statically
linked; Linux 6.8; arm64; nested KVM); the whole `vmintegration` suite
passes on it (eleven tests, one run after the last change to the code;
its figures are below).

### What is enforced

**A jail per hypervisor.** The daemon starts its own binary again as a
helper (`/proc/self/exe` under the name `teploy-sandbox-vm-jail`; the
code runs from an `init` in `internal/vm`, so the same binary serves and
no jailer is installed) in new mount, PID, network, IPC, UTS and cgroup
namespaces, directly in the VM's cgroup. As root, the helper makes the
mount tree private, mounts a 64 KiB tmpfs, bind-mounts seven paths into
it under the names they have on the host, `pivot_root`s into it,
detaches the old root, remounts the new one read-only, sets the host
name, the core limit and an empty capability bounding set, changes to
the VM's GID, group and UID, sets `no_new_privs` and executes the
hypervisor. The UID, cgroup, seccomp and Landlock layers are as before;
the `SO_PEERCRED` check on the VM's sockets is unchanged (the socket
directory is the host's own, bound in). The tap is still a descriptor.

**A network namespace per run.** Not one namespace for all guests, which
is what the review sketched: with one shared namespace a guest is kept
from another guest, and from another run's proxy port, by rules again.
With one namespace per run there is nothing to forbid. An allowlist
run's namespace holds its tap, the gateway address and the run's proxy
listener (a socket the daemon makes from a thread inside that namespace,
through a new `Listen` hook on the proxy pool) and has no link to
anywhere. An open run's namespace has one veth link to the host; in it,
unreachable routes cover every range that is not the public internet,
the guests' subnet and each of the host's addresses, and an unreachable
routing rule covers TCP port 25. IPv6 is disabled in the namespace,
reverse-path filtering is strict, and the namespace answers no ping.
The nftables rules remain, as the second layer, in two places: a
ruleset in every run's namespace (default drop, ingress filter at the
tap) and the host's table for the open runs' links. The watch compares
the kernel's listing of each with the listing taken when it was written
and rewrites what differs.

### How it was verified (live)

The jail, from `TestVMConfinement` and every other test that inspects a
VM (each runs `inspectJail`):

- Namespaces: the hypervisor's `mnt`, `pid`, `net`, `ipc`, `uts` and
  `cgroup` links all differ from the host's; `NSpid` is its host PID and
  1; no other process on the host has its PID namespace.
- Mounts, from `/proc/PID/mountinfo`, exactly these eight: `/`
  `ro,nosuid,nodev,noexec`; the binary `ro,nosuid,nodev`; the kernel
  image `ro,nosuid,nodev,noexec`; the disk node, `/dev/kvm` and
  `/dev/urandom` `ro,nosuid,noexec`; the socket directory
  `rw,nosuid,nodev,noexec`.
- From inside, as the VM's UID: a thread of the test joins the
  hypervisor's mount, network, IPC and UTS namespaces and takes its UID,
  GID and group. Its listing of `/` is the whole jail (below). `connect`
  to the system D-Bus, the four journald and systemd sockets, the
  resolver's socket and both snapd sockets: `no such file or directory`
  for each. `stat` of `/proc`, `/sys`, `/etc`, `/etc/passwd`,
  `/run/dbus`, `/run/systemd`, `/var`, `/home`, `/root`, `/tmp`,
  `/dev/net/tun`, `/dev/vhost-net`, `/dev/vhost-vsock`, `/dev/udmabuf`,
  `/dev/zvol` and the other VM's disk node, socket directory and API
  socket: the same. Its own disk node, `/dev/kvm` and `/dev/urandom`
  open read-write. Creating a file in `/` fails with a read-only file
  system.
- Through the hypervisor itself (its API, `vm.add-disk`): a file outside
  the jail that its UID owns, and the other VM's disk node, are `No such
  file or directory` (before the jail both were `Permission denied`: they
  existed and Landlock refused them). A file inside the jail, in its own
  socket directory, owned by its UID and mode 0666, is still `Permission
  denied`: Landlock holds separately.
- Core limit: `Max core file size 1 1 bytes` in `/proc/PID/limits`.
- A real jail entered by the unit test binary itself
  (`TestJailHoldsNothingOfTheHost`, root only): PID 1, the given UID and
  group, host name `vm`, only its own directory writable, nothing mounted
  on the host afterwards. `TestJailRunsADynamicallyLinkedProgram` runs
  `ls` in a jail with the host's library directories: `/` lists `dev etc
  lib tmp usr`, `/etc` lists `ld.so.cache`, there is no `/run`.

One jail, as the test printed it:

```
/dev
/dev/kvm
/dev/teploy-sandbox
/dev/teploy-sandbox/f285481bdff2a71a
/dev/teploy-sandbox/f285481bdff2a71a/teploy-sbx-01m7kcgh6p5yh2t7v6nt99x7sb
/dev/urandom
/opt
/opt/sbx
/opt/sbx/Image
/opt/sbx/cloud-hypervisor
/run
/run/teploy-vmtest
/run/teploy-vmtest/f285481bdff2a71a
/run/teploy-vmtest/f285481bdff2a71a/teploy-sbx-01m7kcgh6p5yh2t7v6nt99x7sb
/run/teploy-vmtest/f285481bdff2a71a/teploy-sbx-01m7kcgh6p5yh2t7v6nt99x7sb/api.sock
/run/teploy-vmtest/f285481bdff2a71a/teploy-sbx-01m7kcgh6p5yh2t7v6nt99x7sb/api.sock.lock
/run/teploy-vmtest/f285481bdff2a71a/teploy-sbx-01m7kcgh6p5yh2t7v6nt99x7sb/vsock.sock
```

The network without its firewall, from `TestVMNetworkFailsClosed`: two
open guests and two allowlist guests running, private ranges opened so
that every refusal has a control beside it. The driver's upkeep is
stopped first (nothing puts a rule back; this is also the state of a
dead daemon). Then every table the daemon wrote is flushed (the host's
table and its set, and both tables in each of the four namespaces), the
probes run; then every table is deleted, the probes run again; the test
checks before and after each round that no rule exists. In both states:

- open guest to open guest: ping, TCP and UDP to a listening port,
  frames at the other guest's MAC, to broadcast and through the gateway's
  MAC, the other guest's address taken as a second address and used as a
  source, IPv6 all-nodes: nothing arrives at the other guest and nothing
  with its source address leaves the host;
- allowlist guest, with a default route it gives itself: the other
  guests, the peer and the internet, by ping and TCP: nothing;
- all four guests to the host itself, on the gateway address, the
  host's own address and its address on another link: TCP to a listener
  bound to every address, TCP 22, UDP, ping: nothing, and the listener
  counts no connection;
- another run's proxy port, from an open guest and from the other
  allowlist guest, with that run's own credential: not there;
- an open guest to the link-local metadata address, to port 25 on a
  peer it otherwise reaches, and to ports 22, 80 and 443 of its
  (private) resolver: nothing. These three are held by the routes and
  the routing rules alone.

Controls in the deleted state: the allowlist guest reaches its
allowlisted peer through its own proxy, and the open guest reaches the
peer on port 8080 (the peer routes back through the host, so this works
without the masquerade rule). In the flushed state the namespaces'
chains are still there with their default drop, and no guest has any
network; the host's chains accept by default, which is why that state is
checked separately.

The watch, from `TestVMNetworkIsolation`: with three guests running, the
host's table deleted and every namespace's ruleset flushed, and
separately every table emptied in place (`flush table`, `flush set`),
the listing of all four rulesets was byte for byte what it had been
after 0.8 to 1.9 s (two runs of each); the log carries an error for
each. The previous watch did not notice the second case at all.

Everything the earlier entries checked still holds in the new structure
and is still checked: no guest-to-guest path, only the run's own proxy
port, the ranges and port 25, nine spoofed frames dropped at the tap's
ingress hook (now in the run's namespace), the tier across stop, resume
and fork, teardown (no namespace, link, route, set element or tracked
connection left), and the crash case: a new daemon cuts a leftover open
guest off before it sweeps, and the sweep removes this daemon's stray
namespace and link, the taps, gateway device and netdev table that an
earlier version of the driver kept on the host, and nothing of another
daemon identity.

The checks themselves, by building the driver weaker and running
`TestVMNetworkFailsClosed` (it passed the flushed state each time, where
the namespaces' default drop still holds, and failed in the deleted
state):

- without the unreachable routes for the host's own addresses and with
  the namespace answering pings: `open guest b reached the host itself`,
  with TCP to the listener and to port 22 on both of the host's
  addresses and a ping of all three targets open;
- without the unreachable route for link-local: `an open guest reached
  the link-local metadata address`;
- without the routing rule for port 25: `an open guest connected to port 25`.

The jail's checks were not run against a weakened jail; they have
controls instead (the sockets it finds missing accept a connection on
the host; the devices it needs open inside).

### Measured (nested arm64; not a statement about bare metal)

- The jail: a process started and reaped, median of 40, as the driver
  started hypervisors before and through the helper: 11.6 against
  24.7 ms in one run and 7.4 against 16.6 ms in another, so 9 to 13 ms
  more per create. A cold boot was 14 to 18 s in the same run.
- Host-side network setup per create, over eleven creates. Allowlist:
  23 to 51 ms for the namespace and the proxy's listener, made before
  the VM, and 20 to 23 ms for the tap, ruleset and routes: 45 to 75 ms
  together. Open: 70 to 155 ms (the link, the host's table, some thirty
  routes and rules, written as one batch), with one of 510 ms that was
  the first after a boot. Before, with everything on the host, both
  were 40 to 50 ms. So a namespace per run costs an allowlist create
  about 20 ms and an open create 30 to 100 ms.
- Throughput, a 1 GiB download from the neighbour namespace: 179 and
  184 MB/s on the open tier, 169 and 217 MB/s through the allowlist
  proxy, against 353 and 547 MB/s from the host itself. The entry above
  measured 260 to 290 and 250 to 300 against 570 to 840, on the same
  machine on a quieter day. The open tier has one more hop than it had
  (the veth link); how much of the difference that is cannot be told
  from these four numbers.
- The watch: one `nft list` per running networked VM every two seconds,
  besides the host's table. Not timed under load.

### Deviations from what was asked, and why

- **One namespace per run, not one for all guests.** Above. It costs a
  namespace and, for open runs, a veth pair per run, and makes
  guest-to-guest and proxy-port isolation hold without rules.
- **`destroyIf` still closes the proxy first.** Reordering it would
  change the Docker driver, where revoking a run's egress the moment it
  is destroyed (even if the container cannot be removed) was a
  deliberate fix of an earlier audit. The finding itself is closed for
  the VM driver by structure: a proxy's port exists only in its run's
  namespace, another run's proxy is in another namespace, and the port
  number (20000 plus the address slot) is not given out again until the
  namespace that had it has been removed
  (`TestAProxyListenerHoldsItsPlaceUntilAVMHasIt`). The guest of a run
  being destroyed has nothing to reach on that port: no socket listens
  in its namespace again.
- **The core limit is 1 byte, not 0.** Tried on this host, whose
  `core_pattern` pipes to a crash reporter: a process with a limit of 0
  that died of SIGSEGV was handed to the reporter, which wrote a report;
  with a limit of 1 the kernel logged `has RLIMIT_CORE set to 1` /
  `Aborting core` and did not start the reporter. One byte is below any
  dump's size, so no file is written either.
- **Not made non-dumpable.** The flag does not survive `execve` (the
  kernel resets it for a program the process may read), so only the
  hypervisor could set it on itself, and it does not. What the flag
  would have added to the limit above is protection from `ptrace` by the
  same UID, and nothing else has a VM's UID.

### What remains

- **An open guest can be sent to, with both rulesets gone.** With the
  host's table and the run's own ruleset both removed, the host forwards
  to an open guest whatever is routed to it, and nothing drops what is
  not an answer. Only someone who can make the host route to the guests'
  subnet can use it: a neighbour on the host's own segment. Reverse-path
  filtering in the namespace refuses sources in the blocked ranges, so
  with private ranges closed (the default) that neighbour needs a public
  address. Routes cannot express "answers only".
- **A new address of the host** is unreachable from open guests at once
  through the host's table (which drops everything a guest sends to the
  host itself) and through the run's ruleset and routes after the next
  watch, at most two seconds later. With the host's table gone and the
  daemon dead, an address the host gains afterwards has no unreachable
  route in namespaces that already exist.
- **The listing a ruleset is compared with is taken just after it is
  written,** in a second command. A change made between the two would be
  taken for the daemon's own.
- **A VM's socket directory is on the host's `/run`.** It is the one
  writable place in the jail. A hypervisor that a guest took over can
  make entries there as far as its Landlock rules let it (they allow at
  least links), against the inode and size limits of the host's `/run`
  rather than a limit of its own. A small tmpfs per VM, mounted on the
  host and bound into the jail, would bound it; not done.
- **The jail of a dynamically linked hypervisor** holds the host's
  library directories read-only. The path is unit-tested and was run
  with `ls`, not with a hypervisor.
- `/dev/kvm` and `/dev/urandom` are in the jail because the hypervisor
  needs them; the KVM ioctl surface is as exposed as before.
- Still open from the entry above: a udev rule file that honours neither
  flag; the per-identity directories that are never swept.
- Not built for this driver: x86-64 was not run, nor bare metal.


## 2026-11-16 — VM driver: independent review of the jail and the per-run namespaces

A third reader went through the eight commits of the entry above (the
jail helper, the per-run network namespaces, the proxy listener hook,
the subordinate ID check, the host script), against a guest that has
taken over its hypervisor process. Same host (Cloud Hypervisor v54.1,
Linux 6.8, arm64, nested KVM).

Found and fixed:

- **The daemon did not compile for linux/amd64.** `internal/vm` named
  `syscall.SYS_SETNS`, which the `syscall` package has on arm64 and not
  on amd64. Every package of the daemon is one binary, so the Docker
  driver did not build on x86-64 either, and CI (an x86-64 runner) could
  not have passed. Found by cross-compiling; the gates that had been run
  compile for the machine's own architecture. The number is now the
  driver's own per architecture, and CI builds and vets both
  architectures with every build tag. amd64 is still only compiled, not
  run.
- **A hypervisor inherited whatever descriptors the daemon was started
  with.** The daemon's own files are close-on-exec; what its parent left
  open is not, and it passed through the helper into every jail. A
  descriptor is not stopped by a root that has no path to its file: an
  open directory of the host is the host's tree again, for `openat` and
  for a `connect` by relative path, which is what the jail exists to
  take away. Shown on a real hypervisor: with the suite started as
  `exec 8</; exec 9</etc; ./vm.test`, every hypervisor had descriptor 8
  on `/` and 9 on `/etc`; and in the unit test's real jail the jailed
  program read a file of the host through such a descriptor. The helper
  now marks every descriptor above the ones the program is handed (its
  standard three, and the tap) close-on-exec just before the exec, and
  fails closed if it cannot. The live suite holds a stray descriptor on
  `/` for its whole run and checks every hypervisor's descriptors.
- **An open guest could send UDP to the host through a broadcast
  address, with the rules gone.** The namespace had an unreachable route
  for each address of the host, and none for the broadcast addresses of
  the host's subnets, which the host's kernel also delivers to itself on
  whichever interface they arrive. Shown live, with every table of the
  daemon deleted: a datagram from an open guest to the broadcast address
  of the host's own subnet, and one to that of another link of the host,
  were each read by a UDP socket on the host bound to every address
  (TCP and ping to the same addresses got nothing). With the rules in
  place the host's table dropped them. The addresses the host takes for
  itself are now each address, its subnet's broadcast address and its
  subnet's first address; `TestVMNetworkFailsClosed` probes them and
  fails on the driver as it was (`udp datagrams 5`, want 1).

Looked at and found sound:

- The helper before it gives up root. It resolves five paths that only
  root can change (the binary, the kernel image, the device directory,
  `/dev/kvm`, `/dev/urandom`) and the socket directory, which belongs
  to a UID that owns no process until the helper itself takes it (a UID
  is released only after its cgroup is empty). The mount tree is made
  private before the first mount; the root is entered with `pivot_root`
  and the old one detached, and `/proc/PID/mountinfo` of a hypervisor
  lists the root and its six binds and nothing else. The environment is one
  `PATH`. Order: bounding set, groups, GID, UID, a check that no ID is
  0, `no_new_privs`, descriptors, exec. Read from a live hypervisor:
  all five capability sets empty, `NoNewPrivs: 1`, `Seccomp: 2`.
- The hypervisor's seccomp filters, read out of a live process
  (`PTRACE_SECCOMP_GET_FILTER`) and evaluated per thread. The threads a
  guest drives (vCPU, the virtio queues, vsock) may not `clone`, open a
  socket other than the vsock thread's unix one, `mount`, `unshare`,
  `setns`, `ptrace`, `bpf`, `keyctl`, `execve` or change a tap's
  persistence. No thread may `unshare`, `setns`, `mount`, `ptrace`,
  `execve`, `keyctl` or `bpf`. See below for what the main thread may.
- The network threads. A goroutine that enters a namespace keeps its
  thread to itself and ends with it; the Go runtime starts new threads
  from a clean one when the current one is locked, so no other
  goroutine lands in a guest's namespace.
- Port 25 and fragments. A routing rule that matches a port does not
  match a fragment (the kernel does not read ports out of one), and
  with every table deleted a SYN to port 25 sent as two fragments did
  leave the host and was answered by the peer. The answer never reached
  the guest (three retransmitted SYN-ACKs seen on the host's end of the
  link, none delivered; the same exchange on port 8080 completed). As
  the kernel's source reads, that is reverse-path filtering in the
  namespace: it looks the reply's source up with the ports swapped and
  finds the unreachable rule. So no connection to port 25 was made that
  way; one-way fragments can be sent.
- The Docker driver's path through the proxy pool is what it was: with
  no `Listen` hook the pool binds as before.

Open, and what closing each would take:

- **The hypervisor's main thread may make namespaces.** Its seccomp
  filter (the hypervisor's own, not the daemon's) allows `clone` with
  any flags, `clone3`, `io_uring_setup` and `AF_INET` and `AF_NETLINK`
  sockets. Threads share memory, so code execution in any thread is,
  with more work, code execution under that filter. On a host that lets
  unprivileged processes create user namespaces, that is a new user,
  network and mount namespace with full capabilities inside: nothing of
  the host comes into reach by it (the jail's mounts stay locked, the
  cgroup files stay root's), but the kernel's namespaced subsystems
  (netfilter above all) become attack surface from inside a jail. Not
  exercised: it needs code execution in the hypervisor. On the host
  this was run on, AppArmor confines such a namespace
  (`kernel.apparmor_restrict_unprivileged_userns = 1`; writing the UID
  map as a VM's UID failed). Closing it for every host: a seccomp filter
  of the daemon's own, installed by the helper under the hypervisor's
  (no `clone` with a namespace flag, `clone3` answered with `ENOSYS`, no
  `unshare`, no `setns`), or `user.max_user_namespaces = 0` on a host
  that runs nothing else. `install-host.sh` now says which of these a
  host has and changes nothing.
- **The watch gives up for good if it mistakes its table for another
  instance's.** It asks for its marker chain and, when that fails, for
  the table; a marker that cannot be listed beside a table that can is
  read as "another daemon instance took over", after which nothing is
  watched, attached or removed until a restart. A failed `nft` (no
  memory, no process slot) at the first step is enough. Fail-closed for
  new runs, and existing runs keep their rules, routes and namespaces;
  what is lost is the upkeep. Telling the two cases apart needs the
  other instance's marker to be looked for, not the absence of one's
  own.
- **The session keyring of the daemon is the hypervisor's too.** No
  hypervisor thread may call `keyctl`, so it is not reachable today; a
  helper that joined a new session keyring would not depend on that.
- **Local routes that are not addresses.** What the host takes for
  itself is derived from its interfaces' addresses. A host with a
  `local` route for a whole prefix (an "any IP" setup) has destinations
  the namespaces' routes do not know; the host's table still drops
  everything a guest sends to the host itself.
- Still open from the entry above, unchanged: an open guest can be sent
  to with both rulesets gone; the socket directory is on the host's
  `/run`; the jail of a dynamically linked hypervisor was not run with a
  hypervisor; x86-64 and bare metal were not run.


## 2026-11-16 — VM driver: the daemon's own seccomp filter, bounded sockets, disk and network limits

What the review above left open, apart from an x86-64 host with a
hypervisor on it. Same arm64 host (Cloud Hypervisor v54.1, statically
linked; Linux 6.8; OpenZFS 2.2.2; nested KVM); the whole `vmintegration`
suite passes on it (twelve tests, one run after the last change to the
code). The jail, the filter and the socket filesystem were also run on
x86-64, by CI, without a hypervisor.

### What is enforced

- **A seccomp filter of the daemon's own on every hypervisor.** The
  jail helper installs it after `no_new_privs`, before the exec; the
  kernel runs it and the hypervisor's own and takes the stricter
  answer. Classic BPF built in Go (`internal/vm/seccomp.go`), one
  program per architecture, 70 instructions on arm64 and 79 on amd64.
  It checks the architecture first and kills the process on a call
  through another table (and through x32 on amd64). It refuses, with
  `EPERM`: `unshare`, `setns`, `clone` with any namespace flag
  (`clone3` gets `ENOSYS`), `socket` and `socketpair` in any family but
  unix, `io_uring_setup/enter/register`, `mount`, `umount2`,
  `pivot_root`, `chroot` and the new mount calls, `ptrace`,
  `process_vm_readv/writev`, `pidfd_getfd`, `process_madvise`, `kcmp`,
  `keyctl`, `add_key`, `request_key`, `bpf`, `perf_event_open`,
  `userfaultfd`, `memfd_secret`, `init_module`, `finit_module`,
  `delete_module`, `kexec_load`, `kexec_file_load`,
  `open_by_handle_at`, `name_to_handle_at`, `personality`, and the
  administrator's calls (swap, reboot, clocks, quotas, accounting,
  host name; `iopl`, `ioperm`, `modify_ldt` on amd64).
  **A denylist, by choice.** An allowlist would have to be proven
  against everything the hypervisor calls on both architectures, with
  every device and on every path (pause, resume, snapshot, a guest that
  powers off, an error path); one missing call kills a VM. What was
  observed is the calls of one version on one architecture. The
  hypervisor's own filters are allowlists and stay in force for
  everything this list does not name, so the two together are: the
  hypervisor's allowlist, minus this list.
  **io_uring is refused.** v54.1 with its default options probes for it
  on the main thread (`io_uring_setup(1)`, `IORING_REGISTER_PROBE`) and
  then makes a ring of 128 entries per disk; seen with strace. Refused,
  it uses Linux AIO for the disk and boots and runs the same. No
  socket family but unix is needed: with the tap handed over as a
  descriptor the only sockets it opens are `AF_UNIX`.
  This also closes two findings of the review without further code:
  the main thread can make no namespace on a host that lets
  unprivileged processes make user namespaces, and the daemon's session
  keyring is out of reach whatever the hypervisor's filter allows.
- **The socket directory is a filesystem of the VM's own.** A tmpfs of
  64 KiB and 16 inodes, mounted by the daemon on the VM's runtime dir
  before the dir is handed to the VM's UID; the jail binds it. Removed
  with the VM (after its cgroup is empty, before the UID is given
  back), before a dir is reused, and by the startup sweep.
- **Disk I/O per VM.** `io.max` in the VM's cgroup on its volume's
  device number: `--vm-disk-mbps` (256) and `--vm-disk-iops` (16000),
  each for reads and writes separately. The `io` controller is now
  required. **ZFS volumes do honour `io.max`** for direct I/O, which is
  how the guest's disk is opened: tried first by hand on a scratch
  volume (10 MiB/s gave 10.4 and 10.5 MB/s; 200 operations per second
  gave 1000 writes in 4.9 s), then through a guest. So the hypervisor's
  own rate limiter is not used: it would be a hypervisor limiting
  itself.
- **Network per run.** A `tbf` queue (`--vm-net-mbit`, 200) on the
  run's tap (what the guest receives, both tiers) and on an open run's
  link inside its namespace (what it sends). `ct state new ct count
  over N drop` (`--vm-net-connections`, 4096) in the run's ruleset: on
  an open run's forward path and on an allowlist run's way to its
  proxy. The host-side `tc` was chosen over the hypervisor's `--net`
  rate limiter for the same reason as the disk's.
- **The watch stands down only for another instance's mark** in the
  host's table. A table without a mark, or none, is written again; a
  failed `nft` is logged and the next look follows. While the kernel
  cannot be asked nothing new is admitted, and the error says so.
- **Preflight and `install-host.sh`** refuse, each with its reason: an
  architecture without a filter, a kernel without seccomp filters, a
  runtime dir where a tmpfs cannot be mounted, a cgroup without the
  `io` controller, no `tc`, and a trial namespace that cannot take a
  `ct count` rule or a `tbf` queue.

### How it was verified

Unit, on every push (both architectures' programs, on any machine): a
small BPF interpreter evaluates each program on synthetic
`seccomp_data`. Every refused call answers `EPERM` with and without
arguments; `clone3` `ENOSYS`; `clone` with thread flags, as fork and
with only high bits set is allowed, and with each of the seven
namespace flags refused; `socket`/`socketpair` allowed for `AF_UNIX`
and refused for eight other families; 49 calls a hypervisor needs are
allowed and none shares a number with a refused one; another
architecture's value, and x32, kill. The numbers are compared with the
`syscall` package's for the architecture the test is built for.

Root-only unit tests, run on arm64 here and on x86-64 by CI's new
`vm-root` job (which fails if one of them skips itself):

- `TestJailRefusesTheCallsTheFilterNames`: a process that came through
  the jail helper makes every call on the list and the ones judged by
  an argument; the same calls are made by a process with the same UID
  and no filter. arm64, 75 calls; amd64, 83. All as the filter says. Of
  the refused ones, 42 (arm64) and 52 (amd64) succeed or fail
  differently without the filter, so the refusal is the filter's; the
  other 25 and 23 are refused to an unprivileged process by the kernel
  anyway (`init_module`, `reboot`, `swapon` and the like), and for
  those only the BPF evaluation shows the filter. Excerpt (arm64; the
  amd64 lines are the same):

  ```
  clone as fork             under the filter: ok                        without: (not made)
  clone(CLONE_NEWUSER)      under the filter: operation not permitted   without: (not made)
  clone3                    under the filter: function not implemented  without: invalid argument
  io_uring_setup            under the filter: operation not permitted   without: bad address
  keyctl                    under the filter: operation not permitted   without: ok
  setns                     under the filter: operation not permitted   without: bad file descriptor
  socket(AF_INET)           under the filter: operation not permitted   without: ok
  socket(AF_NETLINK)        under the filter: operation not permitted   without: socket type not supported
  socket(AF_UNIX)           under the filter: ok                        without: ok
  socket(AF_VSOCK)          under the filter: operation not permitted   without: ok
  unshare(CLONE_NEWUSER)    under the filter: operation not permitted   without: invalid argument
  ```

- `TestSocketDirIsBounded`: `as uid 70123 in the mounted dir: one file
  took 65536 bytes before "no space left on device"; 14 more names
  before "no space left on device"`; `/run` had 253 blocks and 731
  inodes in use before and after (259 and 836 on the CI runner). The
  control, the same dir with nothing mounted: a file of 1 MiB, and
  `/run` grew by 256 blocks.

Live, on the real hypervisor:

- Every VM any test inspects has `Seccomp: 2` and at least two filters
  (`Seccomp_filters`) on every thread, the `io.max` of its config, and
  its socket directory mounted as `tmpfs … size=64k,nr_inodes=16` in
  the jail and on the host. A thread of the test with the VM's UID,
  inside the jail's namespaces, fills the directory: `one file reached
  65536 bytes (no space left on device), then 11 empty files (no space
  left on device); the host's /run/… had 254 blocks of 4 KiB and 737
  inodes in use before and 254 and 737 with the fill in place`. After
  a destroy, and after a sweep by a new daemon, no mount is left.
- `TestVMLimits`, each limit against the same guest on a driver with
  the limit off (`dd` with direct I/O). From the suite's last run, on a
  host that was slow that hour:

  ```
  disk, no limit (control): 60 MiB written at 70 MiB/s and read at 162 MiB/s; 1600 writes of 4 KiB at 1197 per second, read back at 1646 per second
  disk, 10 MiB/s each way (io.max "230:32 rbps=10485760 wbps=10485760 riops=max wiops=max"): 60 MiB written at 9.3 MiB/s and read at 8.7 MiB/s
  disk, 200 operations per second each way (io.max "230:32 rbps=max wbps=max riops=200 wiops=200"): 1600 writes of 4 KiB at 171 per second, read back at 187 per second
  network, no limit (control): an open run received at 1855 Mbit/s and sent at 275 Mbit/s, an allowlist run received through its proxy at 1624 Mbit/s; of 300 connections opened at once: held 300
  network, 20 Mbit/s each way: an open run received at 19.2 Mbit/s and sent at 15.5 Mbit/s; an allowlist run received through its proxy at 19.1 Mbit/s
  connections, at most 200 tracked per run: of 300 opened at once the guest held 197; after closing them, 50 of 50 more were made; the run's rule counted 618 dropped packets
  ```

  Earlier runs of the same test with higher limits, on a quieter host:
  under 20 MiB/s, 19.6 written and 20.2 read against 349 and 580
  without; under 500 operations per second, 494 and 505 against 3946
  and 5383; under 40 Mbit/s, 38.3 each way and 38.3 through the proxy
  against 3815, 779 and 3237. The limits in the test were lowered
  afterwards because the controls vary that much here (the same guest
  made between 550 and 5400 small writes per second without a limit),
  not because a limit was exceeded: none was, in any run. The 197 of
  200 is the count less what the run already had tracked.
- The watch: unit tests only (`TestTheWatchOnlyStandsDownForAnotherInstancesMark`,
  `TestTheWatchKeepsLooking`), with a host whose `nft` fails. Not
  provoked on a real host.

### Measured (nested arm64)

- Refusing io_uring: with it allowed (a build made for the comparison),
  the same guest wrote 100 MiB at 353 MiB/s and read at 623, and made
  2368 and 2219 small writes and reads per second; with AIO, 349 and
  580, and 3946 and 5383 in one run and 208, 791, 2233 and 1864 in
  another. The difference between the two is inside the difference
  between two runs of one.
- The jail with the filter and the mount: a process started and
  reaped, median of 40, 6.5 ms without a jail and 10.7 ms with one
  here; 4.0 and 6.8 ms on the CI runner.
- A boot reads about 100 MiB in about 3400 operations, so a limit
  below that is felt at create: 10.1 s under 20 MiB/s and 9.3 s under
  500 operations per second on the quieter host, where a create
  without took 9 to 13 s; 20.4 s under 10 MiB/s and 24.3 s under 200
  operations per second in the last run. The defaults are far above
  what a boot needs.
- Per create on the host: one mount, one `io.max` write, and one `tc`
  call per shaped device (one for an allowlist run, two for an open
  one). Not timed separately.

### Deviations from what was asked, and why

- **No per-run override of the limits.** The HTTP contract has a
  `limits` object, but a field there would have to be refused by the
  Docker driver (which was not to change) or silently ignored by it,
  and a caller that can raise its own ceiling makes the ceiling the
  caller's. The limits are flags of the daemon.
- **The rate and the connection count are applied to allowlist runs
  too,** where they are cheap (the tap's queue, the proxy's
  connections), not only to open runs.
- **The live suite does not run in CI.** The runner has `/dev/kvm`
  (`crw-rw---- root kvm`), the `io` controller, `ct count`, `tbf`,
  seccomp and Landlock: `install-host.sh` on it reports one problem,
  no ZFS. Running the suite there needs ZFS installed, a pool on a
  file, the hypervisor, an x86-64 guest kernel and a golden image built
  from a root filesystem. That was not attempted.

### What remains

- **x86-64 with a hypervisor.** The filter is run-checked on x86-64 for
  a jailed test program, not for Cloud Hypervisor: that its x86-64
  build makes no call on the list on a path that matters (it is a
  static musl build like the arm64 one, and the calls are the same
  ones) is inferred. Bare metal was not run either.
- **What an allowlist run sends to its proxy has no rate.** It leaves
  through no device; the proxy would have to pace it.
- **The connection count is of what the run's namespace tracks.** The
  host's table can hold a flow a little longer than the namespace's
  does. UDP and ICMP flows count until they time out, so a guest can
  hold its whole count with one-packet flows and deny itself new
  connections; it cannot exceed the count.
- **A queue that is removed is not put back.** Removing it takes root
  in the run's namespace; the watch compares rulesets, not queues.
- **`io.max` bounds direct I/O at the volume.** What ZFS itself then
  does for a write (checksums, compression, its own queues) is the
  host's and is not charged to the VM.
- **`execve` is not on the list** (the filter is installed before the
  exec); the hypervisor's own filters refuse it once they are in place.
- **The KVM ioctl surface, `/dev/kvm` and `/dev/urandom`** are as
  exposed as before; the hypervisor's own filter is what judges
  `ioctl`.
- Unchanged from the entries above: an open guest can be sent to with
  both rulesets gone; local routes that are not addresses; the jail of
  a dynamically linked hypervisor was not run with a hypervisor; a
  udev rule file that honours neither flag; the per-identity
  directories that are never swept.


## 2026-11-16 — VM driver: independent review of the filter, the socket filesystem and the limits

A review of the entry above by someone who did not write it, on the
same arm64 host. Three defects, each fixed with a test; the whole
`vmintegration` suite passes afterwards (thirteen tests), and CI's
`vm-root` job passes on x86-64.

### Found and fixed

- **A guest could keep its own removal waiting, for as long as it
  liked.** I/O the kernel holds back for `io.max` cannot be taken back,
  and a killed process does not end while it has any (it waits in the
  kernel for its asynchronous I/O to finish). How much is queued is the
  guest's choice. On the real hypervisor, under `--vm-disk-mbps 2`: a
  guest that wrote `1048576` to its disk's `max_sectors_kb` and started
  48 direct writes of 16 MiB had about 760 MiB queued; after the kill
  its hypervisor stayed for 6 min 20 s, with its memory, volume, cgroup
  and UID, and every destroy in that time failed with `hypervisor
  process … did not exit`. With the stock setting and 10 MiB/s a destroy
  took 14.7 s of the 15 it has. A guest with a block driver of its own
  can queue far more than its memory (one request may name the same
  pages many times), so the default of 256 MiB/s was minutes too; a
  daemon that restarted meanwhile would have failed its startup sweep.
  Now a killed VM keeps its limits for `DrainGrace` (3 s) and then has
  them lifted, in `Kill`, in the removal of a cgroup and in the sweep.
  The same guest: destroyed in 3.6 to 4.1 s
  (`TestVMDestroyIsNotHeldByQueuedIO`, live;
  `TestAKilledGroupIsNotHeldByItsDiskLimit`, unit). The price: what is
  left of a killed VM's queue reaches the volume at the volume's speed,
  once. A caller that creates, queues and destroys in a loop gets that
  much unlimited I/O per VM it boots; the alternative was a VM that
  cannot be removed.
- **CI's `vm-root` job passed when a test failed.** The step piped the
  test binary into `tee`, and a step's shell is `bash -e` without
  `pipefail` unless a shell is named (the job's log shows `shell:
  /usr/bin/bash -e {0}`), so the step ended with `tee`'s status. Only a
  failure of one of the four tests whose `PASS` line is looked for
  failed the job. It also only looked for skips of `TestJail*` and
  `TestSocketDir*`. Now `set -o pipefail`, and any skip fails it (none
  of the package's tests skips as root on the runner).
  `TestCIStepsThatPipeFailWithTheirTests` reads the workflow.
- **The filter did not name the newer mount calls.** `open_tree_attr`
  (Linux 6.15; `open_tree` and `mount_setattr` in one call), `statmount`
  and `listmount` (6.8; what is mounted where and from what, which a
  jail without `/proc` otherwise keeps to itself). Without the filter
  each reaches the kernel from a jailed process (`bad address`, on
  x86-64 in CI and, for the two that 6.8 has, on arm64 here); with it,
  `EPERM`. No hypervisor allowlist has them, so this is for the time
  before that filter is installed and for a version that would add
  them. Every number in both tables was compared with the kernel's
  (`arch/x86/entry/syscalls/syscall_64.tbl` and `scripts/syscall.tbl`
  of v6.17) by a script: 66 on amd64 and 58 on arm64, no difference.

### Checked and found sound

- **The filter.** The architecture is checked before anything else and
  x32 before any number is compared. `clone`'s flags and a socket's
  family are read from the low half of the argument, which is all the
  kernel reads of either (`lower_32_bits(clone_flags)`, `int family`):
  nothing in the high half changes what the kernel does. Neither
  architecture has `socketcall` in its 64-bit table; the 32-bit table
  that has it is the one that kills. A later filter cannot weaken an
  answer (the kernel takes the strictest; a user notification ranks
  below `EPERM`). The helper is locked to one thread from before
  `no_new_privs` to the exec.
- **`io.max` on a ZFS volume**, by hand on a scratch volume under
  10 MiB/s: buffered writes with and without `fsync` 10.5 MB/s,
  buffered reads 10.5, direct 10.5 each way, `BLKZEROOUT` of 60 MiB
  6.0 s. A discard is charged as one operation and 512 bytes whatever
  its length (`blkdiscard` of 256 MiB: 0.13 s), so it is bounded by the
  operations limit only; 100 discards under 20 operations per second
  took 4.9 s, and a synchronous write counts as two.
- **`ct count`.** A flood of new flows that the rule or a later one
  drops (195,000 packets per second for 40 s, here, and again in the
  first minute after a boot) leaves nothing behind: the kernel's list
  of counted connections did not grow and the host's slab did not move.
- **The socket filesystem.** Mounted before the chown and the bind, in
  a tree the helper has made private; removed after the cgroup is
  empty; the sweep unmounts only inside this daemon identity's runtime
  dir and never follows a link.
- **The watch.** The host's table is written in one transaction with
  the mark in it, so a table without a mark is never another
  instance's.

### What remains, beyond the entry above

- **With io_uring refused, every VM's disk depends on Linux AIO, and
  `fs.aio-max-nr` is one number for the host** (65536 by default; a VM
  takes 128). A hypervisor that was taken over can take all of it with
  one `io_setup`. Tried here from another UID: VMs created meanwhile
  boot and work (the hypervisor falls back to synchronous I/O), slower.
  Not fixed: a filter cannot count, and a larger sysctl only moves the
  number.
- **The connection count times the number of runs** is what the host's
  connection table and the daemon's descriptors (two per proxied
  connection) have to hold: at the default of 4096, 64 open runs fill a
  table of 262144, and about as many allowlist runs a descriptor limit
  of 524288. Size `nf_conntrack_max` and `LimitNOFILE` for the runs a
  host is to carry, or lower `--vm-net-connections`.
- **What an allowlist run sends** could be given a rate without the
  proxy: a policer on the tap's ingress (`tc filter … action police`)
  is on a device and covers both tiers. Not done.
- **The watch's two questions are not one.** Between asking whose the
  table is and comparing it, another instance may write it; the older
  one then writes its own back and the newer one stands down. It takes
  two daemons with one identity and a window of milliseconds; it was
  there before this change.


## 2026-11-16 — VM driver: a warm pool of pre-booted VMs, and host sizing

A create used to be a cold boot: 8 to 25 s on the nested arm64 test host
(Cloud Hypervisor v54.1, Linux 6.8, OpenZFS 2.2.2). The driver can now
keep VMs booted ahead of creates (`--vm-warm`, off by default), and warns
at start when the host's shared limits are too small for the runs it is
configured for. Same host; the whole `vmintegration` suite (fourteen
tests) passes on it with the pool on (`SBX_VM_WARM=1x512=2,1x1024=1`)
and with it off, one run each with the final code (an earlier run with
the pool on failed one check, which counted the pool's socket
filesystems as a run's; the check now leaves out what a pool holds).

### Design, and why

- **A pool VM is a run's VM that has not been given to a run.** It is
  booted by the same code as a cold create (`Driver.boot`): a volume
  cloned from the golden snapshot, the jail, a UID of its own, both
  seccomp filters, Landlock, the cgroup limits of its size, its socket
  filesystem. Then nothing: no network device, no environment, nothing
  run in the guest; the daemon only pings its agent. A create on the
  golden image whose size matches takes the oldest one, and the claim
  (`Driver.claim`) does everything that is the run's, which is also all
  that happens to a VM booted for a run: the run's network namespace
  and tier (made before, as always, with the proxy's listener), the tap,
  and in the guest the PCI rescan, address, routes, resolvers and clock.
- **Every VM now boots without a network device; a run's is plugged
  in.** This is what makes the two kinds of VM the same. The tap goes to
  Cloud Hypervisor's `vm.add-net` as an `SCM_RIGHTS` descriptor sent
  with the request on the VM's API socket, after the `SO_PEERCRED`
  check every API call already has; v54.1 takes it under its own
  seccomp filter, Landlock and the daemon's filter (no new socket, no
  path: a descriptor arrives on a unix socket it already has). The
  arm64 guest boots from a device tree, so it is not told of a
  hot-plugged device and rescans its PCI bus; the setup script then
  waits for the guest's device manager to finish naming the interface,
  so it ends up with the name it would have had at boot. Checked live: a
  claimed VM and a VM booted for its run show the same PCI devices in
  the same slots (`0000:00:05.0` is the network device in both), the
  same interface name (`enp0s5`) and the same kernel command line. The
  alternative considered first, booting pool VMs with a tap and moving
  it into the run's namespace at claim, would have left a pool VM with a
  device that existed before its run, in a namespace that was not the
  run's; and pinning the hot-plugged device to the slot a boot-time one
  would have had is not possible on this VMM (that slot holds another
  device). The hypervisor is now started with its three standard
  descriptors and nothing else.
- **Once, under a lock.** A VM leaves the pool in `take`, under the
  pool's mutex, to one create; nothing puts a VM back, and a claim that
  fails destroys it. The run's container ID is the VM's own name, so
  nothing is renamed under a running hypervisor (its volume, cgroup,
  device node, runtime dir and the hypervisor's own command line all
  carry it); the run's network place keeps the run's name, which is
  what the proxy listener was made under before the create. The
  registry never holds a pool VM, so the reaper cannot see one.
- **Bounded refill.** One boot per short size in turn, after every
  claim (once the claim is done with the CPU) and every two seconds;
  never while `--vm-warm-boots` boots are under way, counting creates
  that are booting their own VM; never while `MemAvailable`, less what
  the boots under way may take, is short of the new VM's cgroup limit
  plus `--vm-warm-headroom-mb`. A failed boot backs off (1 s doubling to
  a minute). A pool VM that exits is removed and replaced, after the
  same kind of pause (doubling with every VM that dies waiting, until a
  create takes one).
- **Restart and shutdown.** Pool VMs are VMs of the daemon's identity,
  named like any other, so the existing startup sweep removes them; the
  pool only starts after the sweep has succeeded. `Close` removes the
  pool. A second driver of the same identity in one process (the suite's
  "crash") makes the first pool stop booting before it sweeps.
- **Not a memory snapshot.** A pool restored from one saved VM would
  start every guest with the same kernel random state, the same
  addresses for ASLR and the same boot ID. Each pool VM here is its own
  boot.
- **`--vm-max-runs`** caps the VMs runs may have (503 `at-capacity`
  beyond it): the number the sizing below is checked against.
- **Host sizing.** The daemon warns at start, and `install-host.sh`
  reports, when `nf_conntrack_max` < runs × connections, the daemon's
  `RLIMIT_NOFILE` < runs × connections × 2 + (runs + pool) × 8 + 1024,
  or `fs.aio-max-nr` < (runs + pool) × 128. The 128 per VM was measured
  (`fs.aio-nr` with three and four VMs running: 384 and 512).

### Measured (nested arm64; not a statement about bare metal)

Create through the manager until the run's first exec has answered, a 1
vCPU 512 MiB guest, ten of each, pool of two refilled between samples:

| | `none` | `allowlist` | `open` |
|---|---|---|---|
| from the pool, median | 34 ms | 369 ms | 379 ms |
| from the pool, worst | 108 ms | 433 ms | 460 ms |
| cold boot, median | 10.6 s | 11.2 s (3) | 11.5 s (3) |
| cold boot, worst | 10.8 s | 11.2 s (3) | 11.8 s (3) |

(The full run with the pool on. In the full run with it off,
`TestVMWarmPool` brings its own pool, and on a quieter hour of the same
host gave 14, 277 and 202 ms median, 27, 384 and 445 ms worst, against
cold boots of 6.1, 6.6 and 6.7 s median; there the host's part was 19
to 30 ms (allowlist) and 39 to 109 ms (open) and the guest's 123 to
322 ms. In the run before both, which started
the refill's boot at the moment of the claim rather than after it, the
pool's medians were 37, 462 and 485 ms and the worst 57, 639 and
678 ms; cold, 12.1 s median and 15.4 s worst. The change to refill after
the claim came from those figures.)

What a networked claim spends: the host's part (namespace already made
for allowlist runs; tap, ruleset, routes, the hand-over) is 25 to 37 ms
for an allowlist run and 70 to 104 ms for an open one (its link, the
host's table and some thirty routes); the rest is the guest's own setup,
190 to 375 ms, which is the PCI rescan,
waiting for the device and its final name, and the `ip` commands
(timed by hand inside three guests just after their boot, the device
plugged in the way the driver does it: the `vm.add-net` call 3 to 4 ms,
the PCI rescan 157 to 168 ms, `udevadm settle` 48 to 87 ms, the four
`ip` commands 71 to 81 ms). A cold boot is dominated by the guest's
boot itself.
On a real host a cold boot is an order of magnitude shorter than here
and the guest's setup should shrink with it; that is inferred, not run.

A burst of five creates against a pool of two with `--vm-warm-boots 2`:
two claimed, three booted their own VM, and the pool never started a
boot with two already under way (the most it was seen booting at once
was two). With four VMs running (a pool of three 512 MiB and 1 GiB
guests, and one run) the test host's MemAvailable was about 6.1 of 7.9
GiB and `fs.aio-nr` 512.

### How it was verified

Unit (`internal/vm/pool_test.go`, `hypervisor_test.go`, on every push):
the pool fills to its targets and a pool VM is untouched (no device,
no setup, no exec); a create claims the oldest, gets its device and
setup at claim, and the pool refills with a new VM; ten concurrent
creates against a pool of three never share a VM; the bound on boots
with hung boots and a burst of creates; the memory headroom; a VM that
dies in the pool is removed, replaced, and never handed out; a failed
claim destroys the VM; a failed boot backs off; a restart's sweep
removes the old pool and the old pool stops booting; capacity and the
reaper; `--vm-max-runs`; the sizing arithmetic; and `AddNet` on the
wire (the descriptor travels with the request, the body names only the
device and MAC, a socket another UID listens on is sent nothing).

Live (`TestVMWarmPool`, and the whole suite with
`SBX_VM_WARM=1x512=2,1x1024=1`): a pool VM before any claim has its
size's `memory.max` and `cpu.max`, one process, a non-zero UID,
`NoNewPrivs`, `Seccomp: 2`, no capabilities, no tap descriptor, a
network namespace that is not the host's, and no network device in its
hypervisor's own config. A claim on each tier: `none` has no device and
the host's time; `allowlist` reaches its `egressAllow` entry through its
proxy and nothing around it, has no default route, does not reach the
host, has only its own route in its namespace, and passes the whole
confinement and jail inspection; `open` reaches the internet, none of
the six non-public peer addresses and not the host. The claimed VM and a
VM booted for its run look the same from inside. Refill after claims
with VMs no run had; the burst; the empty-pool fallback; capacity over
HTTP (`warmPool` and `allocated` including the pool); a restart whose
sweep removed exactly the two pool VMs (processes, volumes, cgroups)
and filled a new pool; the pool gone after `Close`. In the suite with
the pool on, the network and lifecycle tests were served from the pool
wherever their sizes matched (claims per daemon: lifecycle 1, console
flood 1, cgroup limit 1, isolation 2, tiers 2, fails-closed 3, crash 1,
the pool test 35), and every existing check
held: TestVMNetworkTiers, FailsClosed, Isolation and the crash test
with pool VMs on every tier, and the restart sweeps counting the pool's
VMs among the leftovers.

### Deviations from what was asked, and why

- **The tap is hot-plugged for every run, not only for pooled ones.**
  Above: one way for both is what makes a pooled VM indistinguishable
  from a booted one, and it took the tap off the hypervisor's command
  line and out of its inherited descriptors.
- **Nothing is renamed at claim.** The registry keys the run on the
  VM's name instead; renaming a mounted socket directory, a cgroup with
  a process in it or a volume a hypervisor has open is either refused
  by the kernel or a window for mistakes, for no gain.
- **`--vm-max-runs` is new.** "The configured number of runs" had no
  flag; a number the daemon enforces is a better thing to size a host
  against than one it only reads.
- **Cold creates are not held back by `--vm-warm-boots`;** only the
  pool is. Holding a create would turn a burst into a queue whose
  waiting nobody asked for.
- **The guest's hostname and machine ID are not set at claim:** a VM
  booted for its run does not get them either (they are the golden
  image's), and setting them only for pooled VMs would make the two
  distinguishable.

### What remains

- **x86-64 and bare metal.** Hot-plug is run-checked on arm64 only; on
  x86-64 Cloud Hypervisor announces a hot-plugged device through ACPI,
  and the rescan is then a no-op (inferred). The latencies are nested
  arm64 figures.
- **A pool VM can be distinguished by its uptime,** and by whatever
  its guest logged while it waited (its own timers ran, with no
  network, and its clock was the guest's own until the claim set it).
  Nothing else a run can read was found to differ; not every file of a
  guest was compared.
- **A pool VM ages.** It waits with no limit on how long; the guest's
  own timers run meanwhile (with no network). Recycling after an age is
  not done.
- **The memory guard reads `MemAvailable`,** which counts what a waiting
  VM has touched, not what its cgroup allows it; a host can be
  overcommitted by runs and pool together, as it could by runs alone.
- **The pool's VMs count against the 4096 VM UIDs and against
  `fs.aio-max-nr`,** like runs' VMs; not against `--vm-max-runs`.
- **Hot-plug needs the guest's PCI rescan and its device manager.** A
  golden image without sysfs PCI rescan or with a device manager that
  never settles gets its device later or not at all (the setup gives up
  after about 15 s and the create fails).
- Unchanged from the entries above: everything they list as open.


## 2026-11-16 — VM driver: independent review of the warm pool and the hot-plugged network device

A second reader went through the entry above (`1dbafef..bb42790`) with
the code, the unit suite and the same nested arm64 host. Five defects,
each fixed with a test in its own commit; none of them let one run reach
another, or a run reach the host. One new live test,
`TestVMWarmPoolRaces`. The whole `vmintegration` suite (fifteen tests
now) passes with the pool on (`SBX_VM_WARM=1x512=2,1x1024=1`), with the
final code, on a host that was three times slower than for the entry
above (the machine under it was busy: a cold boot took 14 s median and
up to 23 s). One run in between, on the same busy host, failed two
tests on time alone: a guest command that did not answer within its
minute in `TestVMDestroyIsNotHeldByQueuedIO`, which passed alone and in
the next whole run, and the new test's burst, then nine creates at once
of which six were cold boots that did not finish inside the driver's
two minutes; it is six creates now.

### Defects found and fixed

- **The answer to `vm.add-net` was read without a bound.** `AddNet`
  writes its request by hand (the descriptor has to travel with it) and
  read the answer with `http.ReadResponse` straight off the socket,
  which reads a status line and headers of any length. What answers is
  the VM's own process. A resume or a fork boots a tenant's disk before
  the device is plugged in, so a guest that takes its hypervisor over
  during boot is what answers: a status line that never ends was the
  daemon's memory until the 15 s deadline (64 MiB in 50 ms on a unix
  socket, in the test). The daemon reads at most 64 KiB of the answer
  now. (`Pause` and `Resume` go through `http.Client`, which bounds
  headers itself, and bound the body.) Shown against a real unix socket
  in the unit test, not with a live hypervisor.
- **`--vm-warm-headroom-mb 0` kept the default headroom.** The pool's
  defaults were applied twice, when the driver was made ("none" became
  zero) and when the pool was (zero became 1024 MiB). The flag's "0 is
  none" was never true, and on a small host the pool did not fill.
- **A pool whose VMs die was a boot loop.** A pool VM that exited while
  it waited was replaced at once, and a boot that succeeded cleared the
  pause after boots that failed. VMs that boot, answer once and then
  exit (a golden image that powers off, a host that kills what it has
  no memory for) were cloned, jailed and booted one after another as
  fast as the host could, for ever: 522 boots in 1.5 s against the
  fakes. A death in the pool now pauses the pool's boots as a failed
  boot does, doubling up to a minute, until a create takes a VM. In the
  same code, a failed boot logged the failure count after giving up the
  pool's lock: a data race between two boots failing together (the race
  detector shows it with eight).
- **A size the host has no memory for held back every size after it.**
  The refill stopped at the first size the memory guard refused, so
  with `--vm-warm 4x8192=1,1x512=4` on a host short of the large one's
  memory, the small ones were never booted. Each size is held back, and
  logged, on its own.
- **A full daemon did the work of a create before refusing it.**
  `--vm-max-runs` was looked at in `Create`, after the manager had
  opened the run's proxy: for an allowlist run a network namespace, its
  ruleset and a listener, taken down again for the 503, under the
  network's lock. `AdmitCreate` asks first now; `Create` still decides.
  (A resume or a fork of an allowlist run at capacity still opens its
  proxy before it is refused: they do not pass `AdmitCreate`.)

### Checked and found sound

- **One VM, one run.** A VM leaves the pool in `take`, under the pool's
  lock, and no path puts one back: a failed claim, a dead VM and a
  closing pool all end in `discard`. Live: creates at once over the
  three tiers against a pool of three (nine of them, and six in the
  test as it is kept) each got a different VM, none of them still the
  pool's, each networked one a different address, and none found
  another run's marker file.
- **A claim against everything else** (`TestVMWarmPoolRaces`, live). A
  caller that gives up 1 to 300 ms into a claim, nine times over two
  tiers: every create failed, no run was registered, and afterwards the
  host held the pool and nothing else (no hypervisor, volume, namespace,
  link or admission). The three pool VMs killed at the moment three
  creates took them, on each tier: a create either got a whole run (a
  VM booted for it, when the pool's was already dead) or failed with
  the VM destroyed; nothing half made was left or reachable. The driver
  closed with four claims under way: the pool was gone in 0.1 to 0.3 s, the
  creates finished, and the next start's sweep left the host clean.
- **The descriptor goes to the VM it is for.** `AddNet` dials through
  the same `cell.dial` as every other call, so the `SO_PEERCRED` check
  of who listens is made on the very connection the descriptor is then
  sent on; a socket another UID listens on is sent nothing (unit test).
  The descriptor is the tap the daemon itself just made in the run's
  own namespace, found by the run's name, which the guest and the
  hypervisor have no part in. A VM's UID is its own until its cell is
  released, which is after its process is gone. Descriptors a
  hypervisor might send back are never received: the daemon reads the
  socket without a control buffer.
- **Before the device.** A VM has no network device from its boot to
  the claim, and its hypervisor is in a namespace with no interface.
  The tap is handed over only after `Attach` has returned, which is
  after the namespace's ruleset, the shaping, the routes and (open) the
  host's admission are in place, as before. A run is registered, and
  can be given a command, only after the claim has returned.
- **Restart, shutdown, the reaper.** Pool VMs are swept at start by the
  command line and cgroup that every VM of the identity has; the pool
  starts only after the sweep; the registry never holds one. The HTTP
  contract only gains (`warmPool` in capacity when a pool is
  configured, 503 `at-capacity` when `--vm-max-runs` is set); the
  Docker driver implements neither interface and is untouched.

### What remains, beyond the entry above

- **A create whose pool VM dies under it fails.** It is not retried
  with a VM booted for it; the caller gets a 500 and may ask again. The
  window is the claim itself. (Closed for a VM killed from outside by
  the 2026-11-18 entry below; a VM that dies of its claim still fails
  its create, by design.)
- **One caller can keep the pool empty.** Deferred to Cloud, by
  design, not fixable in the daemon: the daemon's one bearer token
  cannot tell callers apart, so there is nothing to be fair between —
  any limit it invented would throttle every caller together. What the
  churner costs the other callers is bounded at exactly the no-pool
  baseline (a cold boot). What it costs the host is not bounded in
  rate: the pool's boots are bounded in number at once
  (`--vm-warm-boots`, counting creates' own boots) and by the memory
  headroom, and paused with a doubling backoff after failed boots and
  after VMs that die (waiting in the pool or, since the 2026-11-18 entry
  below, as a create claims them), but a claim that succeeds is
  followed by a refill boot at once, so a caller that keeps creating
  and destroying runs has the host boot one VM per create, as fast as
  that many boots at once can go. Per-caller fairness is a start-rate
  limit, which needs caller identity, which Cloud has (limits per
  organization: concurrent runs, starts per minute — the platform
  plan's Phase 5).
- **A closing daemon removes its pool one VM at a time** under the 15 s
  it has for the driver (about 0.1 s each here). What is not removed in
  time keeps running until the next start's sweep, like a run's VM
  whose removal failed. A create still under way when the daemon closes
  can finish after it, and its VM is the next sweep's too (so before
  this change).
- **The counts in `--vm-warm` are checked one size at a time** against
  the 4096 UIDs, not together, and not against the guest addresses.
- **Not run:** x86-64, bare metal, and a hostile hypervisor against
  `AddNet` on a live VM (the bound is unit-tested on a real socket).

## 2026-11-17 — VM driver: stopped runs in object storage (off-host durability)

Added, off unless `--remote-endpoint` is given: `internal/s3` (an S3
client on the standard library), `internal/offhost` (encrypted chunked
snapshots, run records, garbage collection), `internal/vm/transfer.go`
(snapshots as ZFS send streams), and in `internal/run` the lifecycle
around them. `go.mod` still has no dependencies. The Docker driver is
unchanged. On the wire everything is additive: `remote` on a run,
`takeover` in the resume body, `remote` in the snapshot answer,
`runs.stoppedRemote` in capacity (only with remote storage),
`image: "snapshot:<id>"` on create, `POST /v1/remote/sync` and
`POST /v1/remote/collect`, and two new answers on existing routes that
only a daemon with remote storage gives: 409 (the run is held by another
daemon) and 503 (remote storage cannot be reached).

### Design, and why

- **Objects.** `v1/snap/<id>/<attempt>/<index>` chunks,
  `v1/snap/<id>/manifest`, `v1/run/<id>/<generation>` records. Chunks of
  one fixed size (16 MiB by default), each its own object, a few in
  flight: memory is (parallel + 1) chunks whatever the disk's size,
  nothing touches the host's disk, a failed chunk is retried alone, and
  a snapshot is deleted by deleting its manifest first. The manifest is
  written last, in one request; until it is there the snapshot does not
  exist. Each upload writes under its own attempt name, so a retry or a
  second uploader never overwrites a chunk a reader may be fetching.
- **Streams.** `zfs send -c`, incremental (`-i`) against the run's
  previous upload, which the manager now keeps on the host while the run
  runs (it used to be destroyed at resume); otherwise against the golden
  image the volume descends from, found by walking origins. That image
  is uploaded once as `base-<guid>` and received by any daemon whose own
  golden image is a different snapshot. A true full stream of a run is
  the golden image again (866 MiB here) for every run; this is why "full"
  became "against the base image".
- **Chain.** No consolidation in the bucket (it would need a pool).
  Instead the chain is capped: after `--remote-max-chain` increments the
  next upload is against the base again. On restore the streams are
  received as clones of one another and the intermediate ones released,
  which the driver's existing promote-and-destroy unwinding turns into
  one volume.
- **Encryption.** AES-256-GCM per chunk, random nonce, key =
  HKDF-SHA256(run key, snapshot ID), associated data = snapshot, attempt
  and index. Manifests and records sealed the same way with the object's
  name as associated data. The run key is random, stored wrapped
  (AES-256-GCM) by a master key that itself is only used through an HKDF
  step. SHA-256 of each stored chunk and of the whole stream are in the
  (authenticated) manifest. Reordered, truncated, replaced and replayed
  objects fail before any byte of them reaches `zfs receive`.
- **Restore.** Streams go into volumes marked `teploy:kind=restore`,
  which nothing in the driver takes for a snapshot; the final one is
  marked a snapshot last. A failure removes what that restore created;
  a crash leaves volumes the startup sweep removes.
- **Registry and ownership.** A run record is numbered generations, each
  created once with `If-None-Match: *`; the newest is the run's state
  (`stopped`, `running` by a daemon, `forked`, `destroyed`). Every state
  change is "create generation N+1 while N is the newest", checked by a
  read back (a retried conditional write is refused by its own first
  attempt) and a second listing (the slot of a pruned generation is
  empty again). This was chosen over a lease with expiry because it
  needs no clocks and no heartbeat, and over leaving it to a controller
  because it then holds without one. Its price is that a dead holder is
  not noticed: `takeover` is explicit. Daemons learn of runs by listing
  `v1/run/`; a run in step costs nothing beyond the listing.
- **No conditional writes.** Found by a probe at start. Then a daemon
  changes only runs it wrote last (`--remote-unfenced` lifts it).
- **Garbage.** Mark from every run's newest record and every caller
  snapshot, through parents; sweep what is unmarked and older than the
  grace, manifests before chunks. A fork writes a `forked` record naming
  the snapshot it will build on before it boots, which is what keeps
  that snapshot when its source is destroyed.

### Every place a crash between two steps leaves state, and what recovers it

| Between | Left behind | Recovered by |
|---|---|---|
| Stop recorded locally / chunks uploading | Run `pending`, snapshot on the host, chunks without a manifest | Next start's upkeep uploads again (a new attempt); the old chunks go at collection after the grace |
| Manifest written / record written | Manifest nothing names; run `pending` locally | The retry finds the manifest and only writes the record |
| Record written / registry file updated | Bucket says stopped, registry says `pending` | The retry's write conflicts, reads the record, sees its own write for the same snapshot, marks the run durable |
| Run durable / previous upload released locally | One extra snapshot on the host, still named by the registry | Released on the same path as above; a registry entry naming a snapshot that is gone is skipped |
| Durable / local copy dropped (`drop`, or pressure) | `remote.local` says true and the copy is gone, or the reverse | Nothing reads the flag to decide: a resume asks the pool |
| Resume's claim written / registry file updated | Bucket says running by this daemon, registry says stopped at the generation before | Sync: the run stays stopped here, held, `pending`; the upkeep writes "stopped" again |
| Claim / restore finished | The above, and volumes marked as a restore | The above; the startup sweep removes the volumes |
| Restore received / committed | Volumes marked as a restore, some already released | Startup sweep: restore volumes destroyed newest first, released ones by the existing unwinding |
| Booted / registry file updated | As every running run at a crash: the VM is swept | Sync: the run comes back stopped at its last durable stop |
| Failed resume / claim given back | Bucket says running by this daemon; run stopped here, `pending` | Upkeep writes "stopped"; until then other daemons need `takeover` |
| Running run's destroy noted in the registry / its VM removed | A note for a run whose VM the startup sweep then removes | The note is written to the bucket by the upkeep; the run is not brought back |
| "Destroyed" noted / written to the bucket | A pending entry in the registry file | Written on every upkeep round; a run with one is not adopted back |
| Stopped run's "destroyed" written / record deleted locally | Registry lists a run the bucket says is destroyed | Sync drops it and its local copy when its local view is durable; a view that is not (its last stop never uploaded) keeps the unpublished snapshot — the only copy of that state — as superseded, forkable and deletable, until retention |
| Fork's record written / child registered | A `forked` record of a run that does not exist | Sync writes "destroyed" for it |
| Collection deleted a manifest / its chunks | Chunks nothing names | The next collection |
| Takeover's claim written / registry file updated | As "resume's claim written" | The same |

*[2026-11-20: this table is superseded by the one in the entry of that
date. Rows 5, 13 and 14 were wrong or incomplete as written here — a
registry entry whose record was gone was dropped with its local copy,
and a sync could meet a fork's record before the fork was registered —
and rows were missing.]*

### Measured (nested arm64, one VM; daemon, pool and S3 service on the same machine)

Two runs of `TestVMOffHost`, 300 MiB of random guest data (309.7 MiB as
stored), 16 MiB chunks, 4 in flight, versitygw 1.11 on a local
directory over loopback. These are not network figures: they bound what
the daemon itself costs (zfs send, SHA-256 twice, AES-GCM, signing).

- Upload of the base image, 865.7 MiB stored: 2.0 to 4.2 s.
- Upload of the stop with 300 MiB: 0.52 to 0.71 s (440 to 590 MiB/s);
  the whole stop 0.66 to 0.91 s.
- Stop after 4 MiB changed in the guest: 6.8 MiB stored, 65 ms. After a
  few bytes changed: 3.5 MiB.
- Restore on a host with nothing, base image and two streams
  (1182 MiB): 3.0 s; with three streams (1186 MiB): 5.7 s. Boot after
  it 5.5 s. Time to resume from the bucket: 8.6 to 11.2 s, of which the
  boot is the same 5.5 s a local resume takes.
- Restore with the base image already on the host: see the report of
  the run in the pull request; about 320 MiB in under 1 s.
- Collection of six snapshots, 103 objects, 1.19 GiB: 40 ms.

### How it was verified

Unit (`go test ./...`, `-race`): the signer against AWS's published
SigV4 suite and the S3 reference's worked examples; the client against
an in-process service that recomputes every signature; chunk damage of
every kind; manifests and records moved, altered or under another key;
24 writers for one generation; a stale write into a pruned generation;
collection, including that it deletes nothing when a record cannot be
read. And the whole path on fakes (`internal/vm/offhost_test.go`): two
or three managers on the VM driver, each with a fake pool and its own
golden image, on one in-memory bucket.

Live (`TestVMOffHost`, Cloud Hypervisor 54.1, ZFS 2.2, versitygw 1.11
with conditional writes): stop with 300 MiB uploaded; no object holds a
marker the guest wrote 20000 times, a chunk does not compress, an
unsigned `curl` of it is a 403; incremental stop; two daemons resuming
one run at once end with one hypervisor process and one 409; the first
daemon's pool destroyed (`zpool destroy`), then both its stopped runs
resumed on the second with the same SHA-256, and again through a fork;
a flipped bit and a deleted chunk each fail the resume with the pool
listing unchanged and the run still stopped and durable; destroy and
collect leave the bucket prefix empty and the standing pool as found.
The client's own live suite (`-tags s3integration`): objects, listing,
a three-part multipart upload, 16 writers racing one conditional put.
The rest of the vm suite still passes.

The "second host" is a second daemon on the same VM with its own
identity, state directory and ZFS pool. Nothing in the path knows that.

### Deviations from what was asked, and why

- **Multipart upload is in the client and not in the snapshot path.**
  Fixed-size chunk objects give the bounded memory multipart is for,
  plus per-chunk retry, hashes that can be checked before decryption
  and deletion without an upload to abort. Multipart is tested live.
  *[2026-11-20: removed from the client. The daemon never called it and
  its retry path was wrong.]*
- **"Full" uploads are against a shared base image**, above.
- **Chains are capped, not consolidated.**
- **A stop whose upload fails answers 200** with `remote.state:
  "failed"`: the run is stopped, the container is gone, and failing the
  call would say otherwise. The durable/not-durable answer is the field.
- **A received base image is kept** after the last run descending from
  it is gone, until the pool is short: it is most of what a restore
  fetches. A restore that fails removes even that, so that a failed
  restore leaves the pool exactly as it was.
  *[2026-11-20: not so in two cases, see that entry: a commit that
  failed part-way left a holder that blocked every retry (fixed), and a
  base image a failed commit had already marked stays, like any received
  base.]*

### What remains

- **A dead holder is not detected.** A run that was running on a host
  that died is resumable elsewhere only with `takeover`, by someone who
  knows the host is dead. A superseded copy that is still running is
  not killed.
- **Remote storage is in the path of resume and of deleting a stopped
  run**, and a daemon does not start without it. A deployment that
  wants local resumes through a storage outage does not have them.
- **The storage provider can delete or roll back** objects. Tampering
  is detected; a record or snapshot removed is a run that is gone, and
  generations removed from the top roll a run back to an older state if
  its snapshot is still there. Use a bucket only the daemons can write.
- **The master key** is one key for the fleet. Rotation is built now
  (see the rotation entry below); recovery is not: losing the current
  master with no backup loses every stopped run that is only in the
  bucket.
- **Scale.** Every daemon lists every run record each sync and every
  object each collection, and holds every stopped run of the fleet
  (with its env) in its registry. Fine for thousands; not designed for
  more. Collection is safe to run from many daemons but all of them do.
- **Caller snapshots**: a failed upload is reported and not retried,
  and nothing lists the snapshots in the bucket.
- **Docker driver: not built.** It would need the driver's side
  (`offhost.Snapshots`) for images: `docker save` as the stream and
  `docker load` to receive works with what is here but uploads every
  layer every time; doing it properly means storing layers as their own
  content-addressed objects and a manifest of layer digests, plus the
  warm volume baked into the snapshot image as today. The manager,
  store, records and collection would not change.
- **Not run:** a second physical host; any hosted S3 service (only
  versitygw); virtual-host addressing against a real service (unit
  only); a service without conditional writes, takeover, the run that
  comes back after a daemon crash, eviction under pool pressure and a
  storage outage during a stop (all on fakes only); disks of many GiB;
  x86-64; a receiving pool that lacks a feature the sending pool's
  stream uses (`zfs receive` refuses the stream, which is the clean
  failure path, but it was not provoked).
- No independent review of `internal/s3`, `internal/offhost` or the
  manager changes yet.

## 2026-11-17 — off-host storage: first independent review

Two reviewers who did not write the slice went through it against the
fakes and the in-memory bucket (internal/s3 and internal/offhost for
one, internal/run and internal/vm for the other), before the final
gate held for the merge decision.

Found and fixed, each with a test:

- **A create from `snapshot:<id>` left the fetched snapshot on the
  host forever.** The registry never named it — a created run has no
  images — and every cleanup mechanism is scoped to what the registry
  names: the sweep, the sync, the reclaim, the eviction. A boot that
  failed leaked it; a successful one leaked it at destroy, and on a
  host whose pool root differs the ref was not even reachable through
  the API. What a fetch materializes is the run's to release: a failed
  boot gives it back, a destroy drops it (the bucket keeps it), and a
  snapshot the host already had stays — it may be one a caller owns.
- **The give-back's publish went out with its caller.** f892889 made
  publishHeld follow the caller's context; unclaimHeld passed it the
  resume request's context, which is what had just run out — the very
  reason the boot failed. The bucket kept saying "running by this
  daemon" until the next maintenance round, and other daemons needed
  takeover. Detached under its own deadline now, like the give-back
  beside it.
- **The S3 client followed redirects.** A 302 in front of the bucket
  (an http→https upgrader) turned a PUT into a GET of the target that
  reported the write as done. The client never follows one now; a 3xx
  is an error like any other.
- **A listing that repeated its continuation token ran forever**,
  feeding the same page to a growing slice while the maintenance round
  behind it waited. A repeated token, and a listing beyond 1000 pages
  (S3's own bound), is an error.
  *[2026-11-20: S3 has no such bound. The cap failed every pass over a
  large bucket for good and is gone; the repeated token still ends a
  listing.]*
- **Collect aborted when a manifest vanished between its listing and
  its read** — another collector's round, or a caller's delete. That
  object is gone, not unreadable; the round continues. And a parent
  chain that circles (one damaged manifest is enough) would have hung
  every daemon's collector with no diagnostic: the walk is bounded now,
  as Ensure's always was.
- **`--remote-gc-grace 0` was accepted**, which deletes in the very
  round a snapshot is first seen unreferenced — the mid-round race the
  grace exists to cover. The flag must be positive.
- **A Reclaim could take a base image a restore was receiving on.**
  Between the receive's origin lookup and the clone existing, nothing
  on the pool pinned the origin. A restore now holds its origin by name
  until the receive ends, and Reclaim leaves what is held.
- **Runs stopped before remote storage was configured were never
  uploaded**: they carried no remote state, which is what publishPending
  looked for. A stopped run with none is publishable; after the first
  maintenance round of the upgraded daemon it is off the host.

Noted, not fixed:

- On a service without conditional writes, nothing fences a run's
  FIRST record: two daemons writing generation 1 of the same fresh run
  ID both believe they created it. No honest manager flow reaches this
  (first records are written only for freshly minted run IDs); it is
  the one hole in the unfenced mode's claim, and it stays open.
- The start probe's object under `v1/probe/` is collected by nothing;
  a cleanup delete that fails leaks it for good.
- The default transport honours `HTTP(S)_PROXY`: signed requests
  traverse a configured proxy.
- A manifest is read under the 64 MiB object bound: at 16 MiB chunks a
  stream above roughly 10 TiB cannot be restored. Consistent with
  "disks of many GiB not run"; now it has a number.
- A listing's LastModified that does not parse reads as the zero time,
  which every age check takes for ancient. Provider trust, as before.
- A RequestTimeTooSkewed answer now names the clock and the delta; the
  failure itself is unchanged.

Looked for and not found: credential or secret leakage anywhere in the
two packages (URLs, errors, logs); nonce reuse; any TLS-verification
opt-out; any stored field read before it is authenticated — the damage
matrix (reordered, truncated, replaced, replayed, cross-kind objects)
all fails closed into staged volumes that are then discarded; key
confusion between purposes and places (HKDF info and the GCM
associated data both bind them); a lost update or double release under
two daemons interleaving on one bucket (the generation fence, the
tombstone ordering and the release holder checks held under every
interleaving built, including a takeover racing a failed boot and a
give-back after a crash); an eviction that drops a snapshot a fork
booted from. The crash table's rows were walked against the code;
row 13's claim is narrowed above.

*[2026-11-20: the second review contradicts three of these "not found"
claims, and they are withdrawn. (1) "No lost update under two daemons
interleaving": a rotation's unconditional manifest write resurrected a
snapshot another daemon had deleted (A3), a rotation on an unfenced
store replaced a claim (A7), and a sync wrote "destroyed" over a fork
that was booting on the same daemon (B2). (2) "No stored field read
before it is authenticated": true of object contents, and beside the
point — the listing itself (which keys exist, and when they were
modified) is unauthenticated and was trusted to delete by (A2, A5, A6).
(3) "The crash table's rows were walked against the code": the walk
missed that a missing record was handled as a destroyed run (B6) and
that a failed commit left state Discard did not remove (B8). What these
have in common is that every interleaving and every damage case then
built was one in which storage answered correctly and in time. Of the
"noted, not fixed" items above, the unparseable LastModified is fixed
(it ages nothing now).]*

## 2026-11-17 — off-host storage: master-key rotation

The wrapped spelling of every run's data key — in each manifest and
record envelope — is what a master key protects; the chunks are under
keys derived from the data key itself and never move in a rotation.
Built:

- A keyring opens what its previous masters wrapped
  (`--remote-previous-key-file`, comma-separated files) and always
  wraps with the current one. The id embedded in every wrapped key
  says which master opens it, so a wrong key is still reported as
  that and not as corruption.
- A daemon's own writes re-wrap: Service.Upload and Service.Advance
  open the run's key, and if a previous master wrapped it, the
  manifest/record they write and the wrapped key they hand back are
  under the current master.
- `POST /v1/remote/rotate` re-wraps what is standing still: every
  manifest, overwritten in place exactly as a second upload of the
  same snapshot is; and every stopped run's record as its next
  generation, with the state and the owner unchanged (rotation must
  not move ownership, which the unfenced store and a daemon's own
  conflict recovery go by). A record that moved while the pass read
  it is skipped and counted, not raced; a running run's record is
  left to its next write; a destroyed run's is left for collection.
  Collect prunes the generations a pass replaces, and with them the
  last object an old master protects.
  *[2026-11-20: it did not. Collect kept the generation before the
  newest, which is the one a pass replaced (A9); and running runs'
  records and the keys in each daemon's own registry stayed under the
  old master with nothing saying so. See that entry.]*
- The pass takes the same lock as Collect, and a partial pass is
  safe: every previous master the daemons were given still opens
  everything it opened before.

Verified on the fakes and the in-memory bucket: a fleet under one
master with a stopped run, a caller snapshot and a base image moves to
a new master; the daemon carrying both re-wraps its own resume/stop
without any pass; one pass re-wraps the rest while the chunk objects
stay byte for byte (only manifest envelopes change) and the record's
owner stays who it was; a daemon given only the new master then syncs,
resumes the run and boots the caller snapshot; a second pass has
nothing left except the running record it is designed to leave.

Not done: an unfenced store rotates only the records its own daemon
wrote last (the same rule as its resumes); no recovery — a master key
lost with no copy loses what only it opens; the rotation is one pass
on demand, not a fleet-coordinated procedure with a checklist.

## 2026-11-17 — off-host storage: caller snapshots retried, listed, and deletable by ID

The register's open item was "a failed upload is reported and not
retried, and nothing lists the snapshots in the bucket." Both halves,
designed on paper first (two independent reviewers; their findings
shaped every rule below) and then built:

- **A note per snapshot, in the registry file** (additive; a malformed
  one refuses the start, the file's own discipline). It is written
  ahead of the capture and the write is confirmed: a snapshot is not
  taken on a note that did not land, because nothing would retry it.
  States: uploading (owned by the request or upkeep round that is
  uploading now), waiting (retried at the next upkeep), deleting (a
  delete owed). A note read back at startup is never left uploading.
- **Retry**: the upkeep retries waiting notes, oldest first, under a
  15-minute deadline of its own (a caller's own snapshot waits as long
  as publishTimeout; the upkeep must not hold its single flight for
  hours on one wedged retry). A note older than --remote-snapshot-retry
  (24h, 0 disables retry — the old semantics) is dropped loudly: its
  snapshot stays on that host only. The note's base may have been
  released meanwhile; the retry then sends in full against the base
  image — a cost, stated, not a failure.
- **The answer** keeps {durable|failed} — no third state — but always
  carries the snapshot's universal ID, and failed means failed-so-far
  with the error. The listing is how a caller learns a failed one
  landed: membership is the probe.
- **Delete**: a snapshot in the bucket may be named by its ID
  ("snapshot:<id>"), so a snapshot is deletable on a host that never
  held it. A delete while the note is uploading answers 409: the
  manifest is the last request of a multi-request upload, and a delete
  that stepped through that gap would resurrect, permanently and
  bootably, what it removed (nothing collects a caller snapshot).
  Otherwise the note moves to a persisted deleting phase — the delete's
  own write-ahead, like the tombstones — and the upkeep completes it
  after a crash: bucket first, then the local copy, both idempotent.
  What a delete by ID removes is the bucket copy and anything local to
  the host asked; another host's local copy goes by that host's ref.
- **The listing** (GET /v1/remote/snapshots) decrypts every manifest,
  because a snapshot's purpose, run and size are inside the seal and a
  listing by object names would answer with every stopped run's
  snapshot in the fleet — IDs whose bootability dies with the run that
  owned them. The walk is the one a collection or rotation pass already
  pays. No pagination, like GET /v1/runs; caller snapshots are the one
  unbounded set in the bucket, and the listing grows with them.

Crash rows added to the table above's model, all recovered by the note
plus the startup rules: a crash between the note and the capture (the
upkeep drops a note whose snapshot never materialised); between the
capture and the upload (retried); after the upload but before the note
is erased (the retry hits the manifest-exists path — Already, cheap);
anywhere inside a delete (the deleting phase completes); a restart
while a note is uploading (reset to waiting). The startup sweep was
re-checked to leave a live caller snapshot alone — load-bearing for
every one of these, and now asserted by a regression test.

Known limits, deliberate: a snapshot whose host dies before its first
successful upload is lost to the retry (only earlier success fixes
that); the listing is anonymous (nothing in the bucket records whose
snapshot it is; callers keep their IDs); a delete by ID before the
upload lands exists nowhere but the birth host, by rule; and a daemon
writing the registry with an older binary silently reverts to no retry
(the file is not a wire).

What the design reviews found and the build owes them: the
delete-vs-manifest-window (closed by the 409; the heavier parked-deleter
design it replaced is unnecessary exactly because a delete can no longer
proceed during an upload), the delete's missing write-ahead, the
unconfirmed persist, the note born retryable, the cross-daemon
delete-before-upload rule, the rotation-drains-notes runbook line, the
give-up age, and the listing that must decrypt to tell the truth.

*[2026-11-20: "a malformed one refuses the start" was the defect B1:
the daemon itself wrote a note with an empty state when it gave one up,
and then refused its own registry. A note in an unknown state is
dropped, loudly. The default retry is 12h now, inside the grace. And
"a delete while the note is uploading answers 409" held the run as
well as the snapshot for the whole upload (B5); the run is let go once
the capture exists.]*

## 2026-11-17/18 — off-host storage: the live suite on the branch, and what the host taught

The whole vmintegration suite was run on this branch (nested arm64,
Cloud Hypervisor 54.1, ZFS 2.2, versitygw 1.11 on loopback), pool off
and pool on, over 2026-11-17/18.

**Found by the live suite and fixed, each with a fake-level regression
test added:**

- **Deleting a durable snapshot by its ID was refused while any run on
  that host had booted from it** ("belongs to run; delete the run
  instead"). The fakes never hit it because they never booted a
  snapshot before deleting it. The rule is now: the bucket copy is the
  caller's to delete whatever a host booted from it — a run's fetched
  local copy is that run's to release when it ends (the create path's
  own ownership rule); a holder blocks a delete only when the local
  copy is all there is. The upkeep's completion of a crashed delete
  takes a held copy the same way.
- **A FAILED earlier run of the suite left orphan snapshot and base
  volumes on the standing pool that nothing collects** — the sweep
  takes only what a registry names, and a failed run's registries are
  gone; the orphans pin their base images forever and the suite's
  next run fails its own reclaim check. The suite now sweeps
  `teploy-snap-*` and `teploy-base-*` off the standing pool before it
  starts (a fresh host has none), and its base-image check names this
  run's base by its golden's guid instead of any base at all.
- **The new tests' daemons kept warm pools when the suite ran with
  SBX_VM_WARM**, overcommitting the suite's small host; the off-host
  daemons are pinned warm-off (the pool tests are the pool coverage).

**Live-verified on this branch (pool off): the full suite, including
the new TestVMKeyRotation (a fleet's master key rotated: manifests
re-wrapped in place, no chunk moved, the record's owner preserved, a
daemon given only the new master resumes the run by restoring from the
bucket) and TestVMCallerSnapshots (durable before the answer, listed,
booted by universal ID on a pool that never held it, deleted by that
ID from there, the birth host's copy kept until its own ref deletes
it). TestVMWarmPoolRaces failed twice on time alone under a loaded
host and passed quiet, the known flake class recorded on 2026-11-16.**

**Pool on:** the full suite passed everything except the three
S3-dependent tests, which a dead test server (an operator miss, not
the code) kept from starting; re-running just those three on this host
was not completed: the 8 GiB nested guest failed environmentally,
in a chain worth recording because every link is a way to lose a
night — warm pools plus concurrent restores leave little memory
margin; a journald storm (every zfs receive/clone/destroy of hundreds
of restore operations is a uevent) ate a core; a wedged run never ran
its bucket-cleanup defers, so the throwaway S3 server's directory
filled the 15 GB root disk; full disk suspended the standing pool
(zpool clear recovered it, no data errors), then a txg_sync wedge and,
after another reboot, guest boots at several times their healthy
time. None of it implicates the branch — the same binary passed the
whole suite pool-off — but the pool-on trio on THIS branch is
**unverified**: re-run it on a host with headroom (the production
validation box) before the merge decision. The trio now streams its
output (-test.v) so a wedge cannot eat the record again.

## 2026-11-20 — off-host storage: second independent review, and verify-on-publish

Two reviewers who did not write the slice went through the pull request
again, one through `internal/s3` and `internal/offhost` (review A), one
through how `internal/run` and `internal/vm` use them (review B). Each
finding came with a test that passed while the defect was there. They
proved several ways in which **a run reported durable was lost**, and
several in which a daemon damaged its own or another fleet's state.
Every proof is now a regression test that fails without its fix (a
sample of fourteen was checked by taking the fix back out).

**None of what follows has run on a live host.** No hypervisor, pool or
S3 service was available where this was written: everything below is
unit tests and the fakes (`internal/offhost/offhosttest`,
`internal/vm/fakes_test.go`). The live suite last passed on the commit
before these changes (985d2e5), and what must run before anyone's data
depends on this is listed at the end.

### The cause the findings share, and the fix they share

Nothing ever looked. "The manifest is there" stood for "the snapshot is
there" in the upload's short cut, in `ensureBase`, in the choice of a
parent, in rotation, in eviction, and in the word `durable` itself; and
every interleaving and damage case built for the first review was one
in which storage answered correctly and in time.

`Store.Verify` lists a snapshot's upload attempt and compares it with
the manifest — every chunk present, with its recorded size — and does
the same for each snapshot the stream builds on, back to a full stream.
A chunk the listing does not show is asked for by name before it is
called missing, so a listing that is behind is an error to retry and
never a verdict (`ErrIncomplete` is the verdict). It runs:

- in `Store.Upload`, after the manifest is written (own chunks);
- in `Service.Upload`, after that, over the whole chain; a gap takes the
  manifest back, makes sure of the base image again, and starts the
  upload over (three tries);
- in the "already uploaded" short cut, and on the 412 "another upload's
  manifest stands" path;
- for the parent an incremental stream would be sent against, and for
  the base image (`ensureBase`), which is uploaded again when its
  manifest names chunks that are gone;
- in the manager after the run's record names the snapshot
  (`publishHeld`), and before a stop of its own that was never
  acknowledged is called durable (`reconcileRun`);
- before a local copy is dropped (`evictHeld`);
- on a schedule: **the scrub** (`ScrubRemote`, `--remote-scrub-interval`,
  6h, `POST /v1/remote/scrub`) asks again for every stopped run a daemon
  reports durable, and that its record is there. A run that fails is no
  longer reported durable; with a local copy it is uploaded again at the
  next upkeep, without one the log says `STOPPED RUN AT RISK` and the
  run says why. Nothing is deleted on a scrub's word;
- and for nothing: every collection compares each manifest with what it
  listed and logs, fleet-wide, the snapshots that are not whole — caller
  snapshots and base images included, which no daemon's scrub covers.

Verification does not read chunks: a chunk that is present with the
right size and the wrong bytes is found at restore (SHA-256, then the
tag), as before.

### Review A — storage internals

| | Finding | Fix | Test |
|---|---|---|---|
| A1 High | A manifest write whose answer was lost returned an error; the cleanup deleted every chunk; the manifest had landed; the retry answered "already uploaded". Durable, no data | Once the manifest's write has been attempted an upload never deletes its chunks (only on a 412 with another whole attempt standing). A failed write is looked for under its own deadline before it is called failed. `Already` verifies; a snapshot found not whole is uploaded again from the local copy, or reported `ErrRemoteIncomplete` | `TestAManifestWhoseAnswerWasLost`, `TestAlreadyUploadedMeansWhole`, `TestAListingThatIsBehindIsNotAVerdict` |
| A2 High | Chunks without a manifest were aged per object by `LastModified` against the collector's clock: a skewed clock, an unparseable time (the year 1) or an upload slower than the grace got an upload in flight deleted, and the upload succeeded | An attempt is garbage only when the collecting daemon has itself seen it, **not growing**, for the grace, on its own clock at both ends. The service's times are a second condition; one that cannot be read ages nothing (those chunks are kept and counted). Aged per attempt by its newest object. `--remote-gc-grace` is at least 1h. And the upload verifies | `TestACollectorCannotTakeAnUploadInFlight` (clock 25h ahead; times that do not parse; two days between chunks), `TestAnUploadThatLostAChunkIsNotASnapshot`, `TestGarbageWithoutATimeIsNotCollected`, `TestRemoteFlagBounds` |
| A3 High | Rotation read a manifest and wrote it back unconditionally: a snapshot another daemon deleted in between existed again with no chunks, for good if it was a base (`ensureBase` only asked whether the manifest was there) | The pass checks the chunks before the write and after it, and takes its manifest back when they are gone (only if what is there is still what it wrote). `ensureBase` verifies and re-uploads | `TestRotationDoesNotResurrectADeletedSnapshot`, `TestABaseImageThatIsNotWholeIsUploadedAgain` |
| A4 High | A base nothing had referred to for the grace was collected under an upload building on it; the child's manifest protected nothing until a record named the child | Collection marks what **every manifest it is not deleting** builds on. Before deleting any snapshot it lists again, and leaves them for the next round if a manifest or record appeared. The upload verifies its chain after its manifest and again after its record | `TestABaseCollectedUnderAnUploadThatBuildsOnIt` (three orders) |
| A5 Medium | One 404 on a listed manifest and collection deleted that snapshot's chunks though a record named it | The snapshot is skipped, and no snapshot at all is deleted in that round (what it builds on can no longer be told) | `TestOneNotFoundCostsNothing` |
| A6 Medium | Collection trusted a listing to stay inside its prefix: a service ignoring `prefix`, or an operator's prefix nested in the fleet's, got unrelated objects deleted | `Client.List` refuses a key outside the prefix asked for; collection considers only keys of exactly its own shapes (`snap/<id>/manifest`, `snap/<id>/<16 hex>/<8 digits>`, `run/<ulid>/<20 digits>`) and counts the rest; a delete never follows a listing out of its prefix. The store's prefix already ended in `v1/` | `TestCollectLeavesWhatIsNotItsOwn`, `TestAListingOutsideItsPrefixIsRefused` |
| A7 Medium, `--remote-unfenced` | Rotation's record write replaced a concurrent claim | Without conditional writes a record is rotated only when no other daemon may change it at all (this daemon wrote it last and `--remote-unfenced` is off). The rest wait for their own next write, and the answer says so | `TestAnUnfencedRotationLeavesRecordsAlone` |
| A8 Low-medium | `If-None-Match` and `Content-Type` were sent and not signed; plain http was accepted to any host | Every request header is among the signed headers. `http://` to a host that is not this one is refused without `--remote-insecure-http` | `TestConditionalHeadersAreSigned`, `TestAStrippedConditionBreaksTheSignature`, `TestNewRejectsBadConfig`, `TestRemoteOpenRefusals` |
| A9 Low | The generation a rotation replaced survived collection; running records and local registry keys stayed under the old master, and the documentation said the old key could be retired | Collection prunes the generation before the newest when the newest is under another master. `POST /v1/remote/rotate` also re-wraps the data keys in the daemon's own registry, and answers `previousKeyNeeded` with the reasons in words | `TestTheGenerationARotationReplacedIsCollected`, `TestARotationSaysWhetherTheOldKeyIsStillNeeded` |
| A10 Low | (a) canonical query sorted as `name=value` strings; (b) a 1000-page cap that is not S3's, and whole listings in memory; (c) `NoSuchBucket` read as "no object"; (d) a retried probe write refused the start; (e) unused multipart with retry bugs; (f) weak keys accepted; (g) secrets inherited by `zfs` children, key file modes unchecked; (h) `daemon-id` written non-atomically; (i) no owner check on a record envelope | (a) sorted by name, then value; (b) `Walk` streams pages with no cap (a repeated continuation token still ends it), and collection keeps counts per upload attempt, never objects; (c) `ErrNoBucket`; (d) a 412 on the probe's own random name is read back and accepted when it is the probe's write; (e) removed; (f) text, zeros, repeated bytes and short patterns refused, the format documented; (g) a secret read from the environment is removed from it, the commands the vm driver starts get the environment without the secret variables, a key file readable by group or others is refused; (h) temp file, fsync, rename; (i) a record's key must be its run's, a manifest's its run's or its base image's | `TestCanonicalQuerySortsByName`, `TestAListingOfManyPagesIsWalked`, `TestNoSuchBucketIsNotNotFound`, `TestAProbeWhoseFirstWriteWasRetried`, `TestMasterKeyForms`, `TestSecretsAreNotLeftLyingAbout`, `TestHostCommandsAreStartedWithoutTheDaemonsSecrets`, `TestDaemonIdentityIsWrittenOnce`, `TestARecordUnderAnotherRunsKeyIsRefused` |

### Review B — how the daemon uses it

| | Finding | Fix | Test |
|---|---|---|---|
| B1 High | A caller snapshot given up on was persisted with state `""`; the next start refused the registry as corrupt, and told the operator to remove a file holding every stopped run | Expired notes are deleted under the lock, never mutated. `decodeState` drops a note in a state it does not know and says so, loudly; everything else about the file is as strict as it was | `TestAGivenUpSnapshotNoteDoesNotStopTheNextStart`, `TestANoteInAnUnknownStateDoesNotRefuseTheRegistry` |
| B2 High | A sync during a fork's boot saw the child's `forked` record for a run it did not know, took it for a fork a crash lost and wrote `destroyed`; the fork succeeded and its child could never be durable | Child IDs are known as being forked from before their record is written until they are registered or given up; `reconcileRun` leaves them. A conflict with this daemon's own `destroyed` record says so instead of "taken over". Looked for the same shape elsewhere: resume, destroy, give-back and publish all hold the run's exclusivity across the write (the sync answers busy); takeover-then-register is idempotent; create writes no record | `TestASyncDuringAForkLeavesTheChildAlone` |
| B6 High | A missing record was handled like `destroyed`: a wrong prefix or lost objects made a daemon delete its own durable local copies and mark the rest superseded for good | A copy is dropped only on a record that says another daemon runs the run, or that it was destroyed. A run whose record is missing, or older than the one this daemon wrote, is kept, shown `failed` with the reason, and published again. A copy marked superseded recovers when the newest record is this daemon's own. The bucket prefix has a name (`v1/fleet-id`), remembered in the state directory; a daemon started against another, or against none, does not start | `TestAMissingRecordIsNotADestroyedRun`, `TestADestroyedRecordStillDropsTheCopy`, `TestFleetIdentity`, `TestADaemonPointedAtAnotherBucketDoesNotStart` |
| B8 Medium | `Commit` ran under the request's context; cut short between marking the intermediates and the final snapshot it left datasets that failed every retry with "destination exists" until a restart | `Commit` runs under its own two-minute deadline. `Discard`, and `Receive`'s pre-clean, also take a holder under the target name whose snapshot is no longer a usable reference. The startup sweep removes unfinished restores before it reclaims holders, so a crashed commit goes in one start | `TestACommitDoesNotFollowItsCaller`, `TestAFailedCommitDoesNotBlockTheRetry`, `TestACrashedCommitIsSweptInOneStart` |
| B3 Medium | `--remote-max-chain` unbounded; restore walk capped at 32, collector at 64 | One constant, `offhost.MaxChainLimit` (64 increments), for the flag, the upload (enforced in `Store.Upload` and by clamping the service's setting), the restore, verification and collection | `TestOneBoundForEveryChain`, `TestALongChainIsCappedWhereEveryDaemonCanFollowIt`, `TestRemoteFlagBounds` |
| B5 Medium | A caller snapshot held its run for the whole upload | The run is let go once the capture exists. What the upload still reads on the host (the previous upload its stream is sent against) is pinned until it ends, whatever becomes of the run | `TestASnapshotUploadDoesNotHoldItsRun` (the run is destroyed mid-upload; the snapshot lands and boots elsewhere) |
| B7 Medium-low | Nothing bounded uploads and restores across runs | `Manager.Transfers`, `--remote-transfers`, 4 | `TestTransfersAreBoundedAcrossRuns` |
| B4 Low | A refused delete of a run's stop snapshot left a `deleting` note forever | The note is removed on the refusal, by the request and by the upkeep (a note a crash left in between) | `TestADeleteOfAStopSnapshotLeavesNoNote` |
| B9 Low, with remote storage off | `snapshot:<tag>` images refused under the Docker driver | The prefix is resolved only with remote storage | `TestSnapshotColonIsAnImageNameWithoutRemoteStorage` |
| B10 Low | An unknown snapshot ID was a 500 | 404; not an ID, 400; storage unreachable for a snapshot this host does not have, 503 | `TestWhatASnapshotIDMayBoot`, `TestEnsureOfASnapshotThatIsNowhere` |
| R1 Medium | Nothing checked that a received stream was one volume's | The first record of the stream (DRR_BEGIN) is parsed before `zfs receive` is started: begin record, magic in either byte order, a plain substream and not a package, object set type volume, `toguid` the manifest's guid, `fromguid` the parent's (zero for a full stream). `zfs receive -u`. `Commit` asks the pool for the type of what was received and makes nothing usable that is not a volume. `Discard`, the pre-clean and the startup sweep see filesystems. A restore whose streams do not fit in the pool's free space is not started. **The layout was read from the OpenZFS 2.2 sources (`include/sys/zfs_ioctl.h`, `struct dmu_replay_record`, `struct drr_begin`; `dmu_objset_type_t` in `include/sys/fs/zfs.h`) and is tested against records built to it, in both byte orders; it has not met a real stream** | `TestTheFirstRecordOfAStreamIsHeldToItsManifest`, `TestOnlyAVolumeIsReceived`, `TestARestoreThatCannotFitIsNotStarted` |
| R2 Low | A retried snapshot could be written against a parent collection was deleting | The chain is verified after the manifest; a parent that is gone takes the manifest back and the upload starts over against the base image. `--remote-snapshot-retry` must be shorter than the grace (default 12h) | `TestAParentDeletedUnderAnUploadMeansAFullSend`, `TestRemoteFlagBounds` |
| R3 Low | Crash windows missing from the table | A fetch for a create is named in the registry file until its run is, and released at the next start otherwise. Sweep ordering as B8. The table is corrected below | `TestAFetchACrashInterruptedIsReleased`, `TestACrashedCommitIsSweptInOneStart` |
| R4 Low | A race on `note.State`; all due notes set to `uploading` at once; a registry rewritten by an older binary led to "superseded" after the upgrade; any incremental failure re-sent in full | Notes are copied out and changed under the lock only, and claimed one at a time. A conflict with this daemon's own newest record publishes from it instead of calling it a takeover. Only a stream the driver could not produce falls back to a full send | `TestARegistryThatLostItsRemoteFieldsRecovers`, `TestOnlyAnUnusableParentFallsBackToAFullSend`, the suite under `-race` |

### The design points

- **`Maintain` single-flight behind serial 2h uploads.** The upkeep runs
  in two flights that do not wait for one another: the uploads owed, and
  everything else (sync, records and deletes owed, eviction, collection,
  scrub). Uploads owed are still one after another. *Open, as designed.*
- **`restoreMu`/`baseMu` held across whole transfers and not
  context-aware.** A waiter gives up when its caller does. Restores are
  still one at a time, and so are base-image uploads: two restores that
  share a chain would both create it. *Open, stated in the README.*
- **A stop holds the run during its upload**, and `POST /snapshot`
  answers when the upload has. Unchanged: the answer is "durable before
  the answer", and a resume racing a stop's upload has nothing right to
  do. The run is no longer held by a *snapshot's* upload (B5). *Open.*
- **Retention on other daemons' clocks.** A run adopted from another
  daemon's record is kept for the length its writer meant, counted from
  when this daemon first saw it, on this daemon's clock
  (`TestAFastClockDoesNotReapEarly`). The daemon that stopped it reaps
  on time; the others never sooner. A restart of an adopting daemon with
  a fresh state directory starts its count again.
- **Any snapshot ID bootable via `snapshot:<id>`.** Decided: an ID names
  a caller's snapshot only. A run's stop snapshot is refused by ID for
  create (400) and delete (409) on every daemon, whether or not it has
  the run; the way to a run's state is the run (`resume`, `fork`).
- **Eviction trusted the in-memory flag.** It asks the bucket first
  (`TestALocalCopyIsNotDroppedForASnapshotThatIsNotWhole`).

### Where the fix differs from the one recommended, and why

- **A2, a time that cannot be read.** Recommended: treat as now, or
  abort the round. Done: it ages nothing, so such chunks are never
  collected on a service that gives no readable times, and each round
  says how many it kept. The rule that actually stops the defect is the
  other one (a daemon must have watched the attempt stand still for the
  grace); this is the brace beside it.
- **A2, the minimum grace** is enforced where an operator sets it
  (the flag), not in `Store.Collect`: the live suite collects with no
  grace to see the bucket empty, and a store-level floor would have
  hidden what a zero grace does.
- **A3, compare-and-swap.** Not used. `If-Match` on a write is a second
  conditional-write feature a service may or may not have, it would need
  its own probe, and no service was at hand to probe. The post-write
  check and take-back is used everywhere instead; its window is the two
  requests between the write and the check, during which the manifest
  of a deleted snapshot exists and anything that reads it verifies it.
- **A7.** Slightly narrower than "do not rotate records without
  conditional writes": a record this daemon wrote last, with
  `--remote-unfenced` off, is one no other daemon will change, so it is
  rotated.
- **A10, the children's environment.** Recommended: a minimal
  environment for `zfs`. Done: the secrets are removed from the daemon's
  own environment once read, and the vm driver's commands (zfs, the
  udev probe, and the network commands, which the review did not name)
  are started without the secret variables. That covers every child and
  changes nothing else about what they inherit, which a minimal
  environment under a driver with remote storage off would have.
- **B6, republishing a run whose record is missing** brings back a run
  that was destroyed elsewhere if the daemon was away for longer than
  the "destroyed" record is kept. Those records are therefore kept for
  thirty graces (30 days by default) rather than one. *The window that
  remains is open and documented.*
- **R1.** The fallback offered ("the cheap parts, and document the
  parsing") was not taken: the layout could be verified against the
  sources, and the check fails closed — a wrong offset refuses every
  restore, loudly, at the first live run, and loses nothing.

### Found while fixing, of the same kinds

- A rotation rewrote `forked` records like stopped ones, moving the
  generation under a running child whose first stop then conflicted
  with it. Left alone now, like `running`.
- A fork whose record write lost its answer left a child that did not
  know its own record; its first stop was "taken over" by itself. And a
  running run whose record vanished was superseded at its next stop.
  Both publish from where the record is.
- `reconcileRun` called an unacknowledged stop durable on its record
  alone.
- A destroyed run's records were deleted at once on a service whose
  times did not parse.
- An upload that no longer holds its run (a snapshot's, since B5; the
  upkeep's retry of one, always) read a previous upload its run could
  release under it. The full-send fallback covered that by sending
  everything; it is pinned now.
- `ListSnapshots` and rotation held whole listings; an attempt name out
  of a manifest went into object keys unvalidated.
- A `DELETE` of an ID a daemon does not know now looks the run up, as
  the README said it did. With storage unreachable that is a 503 where
  it was a 404.

### Not fixed, and why

- **A4's last window.** A collector that lists, decides a base is due,
  and deletes it after an upload has written its manifest, verified,
  written its record and verified again — all inside the collector's
  second listing and its delete — still wins. That is as wide as the
  collector's second listing and whatever it deletes before the base,
  against at least six sequential requests on the uploader's side; on a
  large bucket it is not small, and it is never zero.
  Closing it needs something neither side can do alone on S3 (a
  conditional delete, or a fence object both honour). The scrub finds
  the result; with `--remote-local keep` it is repaired from the local
  copy, with `drop` the run is lost and said to be. **Recommended:
  `keep` until this has run live under collection load.**
  *[2026-11-21: the fence object both honour is built — the two-phase
  delete, see that entry. The recommendation stands.]*
- **No re-keying.** Rotation does not recover from a leaked master.
- **The first record of a run on a service without conditional writes**
  is still unfenced (first review).
- **A daemon away for longer than thirty graces** republishes runs
  destroyed meanwhile, if it still has copies.
- **A run found not whole with no local copy anywhere** stays listed,
  `failed`, until its retention; other daemons that adopted it still
  call it durable until their own scrub.
- **A process's first environment** stays readable in `/proc` to its own
  user after the variables are removed: key files are the answer.
- The probe's object can leak; the default transport honours
  `HTTP(S)_PROXY`; a manifest is bounded at 64 MiB (first review, all
  unchanged).
- **Cost.** A stop now makes one listing per snapshot in its chain and
  reads each manifest in it, twice; the scrub does it once per durable
  run per interval; collection lists the bucket a second time in rounds
  that delete a snapshot. Not measured.

### With remote storage off

The Docker driver is untouched, and `snapshot:<tag>` is an image name
again (B9). The manager's changed paths are behind `OffHost != nil`.
Under the vm driver three things changed whether or not remote storage
is configured: host commands are started without the seven variables
remote storage's secrets are read from; a single dataset is looked up
with `zfs list -t filesystem,volume` instead of `-t volume`; and the
startup sweep lists filesystems under the pool root once and removes any
that carry this daemon's owner mark (the driver creates none).

### Every place a crash between two steps leaves state (corrected)

| Between | Left behind | Recovered by |
|---|---|---|
| Stop recorded locally / chunks uploading | Run `pending`, snapshot on the host, chunks without a manifest | Next upkeep uploads again (a new attempt); the old chunks go once a daemon has watched them stand still for the grace |
| Manifest write attempted / its answer | A manifest that may or may not be there; the chunks, kept either way | The retry finds the manifest, verifies it and writes the record; or finds none and uploads again |
| Manifest written / verified | A manifest of an upload that lost chunks or its parent | The upload takes it back and starts over; if the daemon died first, the retry's "already uploaded" check finds it not whole and uploads again |
| Manifest verified / record written | Manifest nothing names; run `pending` locally | The retry finds it whole and only writes the record. Collection keeps it, and what it builds on, while it is younger than the grace |
| Record written / verified again | Bucket says stopped; run `pending` or `failed` locally | The retry finds its own record for the same snapshot, verifies, marks the run durable |
| Record written / registry file updated | Bucket says stopped, registry says `pending` | Sync: its own record for the same snapshot, verified, then durable; not whole, then published again |
| Run durable / previous upload released locally | One extra snapshot on the host, still named by the registry | Released on the same path; a registry entry naming a snapshot that is gone is skipped |
| Durable / local copy dropped | `remote.local` and the pool disagree | Nothing reads the flag to decide: a resume asks the pool, and eviction asks the bucket first |
| Resume's claim written / registry file updated | Bucket says running by this daemon, registry says stopped a generation earlier | Sync: this daemon's own record; the run stays stopped here, held, `pending`; the upkeep writes "stopped" again |
| Claim / restore finished | The above, and volumes marked as a restore | The above; the startup sweep removes the volumes |
| Restore received / commit begun | Volumes marked as a restore | Startup sweep |
| Inside a commit (intermediates let go, final not marked) | Holders that are let go, still cloned by a volume marked as a restore | Same process: `Discard` removes both, newest first. After a crash: the sweep removes the restore first, then reclaims the holders, in one start |
| Create: snapshot fetched / run registered | A committed snapshot no run holds; the registry file names it under `fetching` | Next start: released like the images of a run the restart lost |
| Booted / registry file updated | As every running run at a crash: the VM is swept | Sync: the run comes back stopped at its last durable stop |
| Failed resume / claim given back | Bucket says running by this daemon; run stopped here, `pending` | Upkeep writes "stopped"; until then other daemons need `takeover` |
| Running run's destroy noted / its VM removed | A note for a run whose VM the startup sweep then removes | The note is written to the bucket by the upkeep; the run is not brought back. This holds when the VM's removal had *failed* and the caller was told so: a crash then turns the failed destroy into a completed one. Accepted: the caller asked for it |
| "Destroyed" noted / written to the bucket | A pending entry in the registry file | Written on every upkeep round; a run with one is not adopted back |
| Stopped run's "destroyed" written / record deleted locally | Registry lists a run the bucket says is destroyed | Sync drops it and its local copy when its local view is durable; a view that is not keeps the unpublished snapshot as superseded, forkable and deletable, until retention |
| Fork's record written / child registered | Same process: a record of a run the registry does not list yet | The sync leaves a child that is being forked. After a crash: a `forked` record of a run nobody has, for which the next start's sync writes "destroyed" |
| Fork's record write / its answer | A record the child does not know its generation of | The child's first stop meets its own record and publishes from it |
| Collection deleted a manifest / its chunks | Chunks nothing names | A later collection, once watched for the grace |
| Rotation rewrote a manifest / checked it | The manifest of a snapshot deleted in between | The pass takes it back. If the pass died first: reported by every collection as not whole; replaced by the next upload of that snapshot, or collected after the grace when nothing names it |
| Rotation rewrote a record / the generation it replaced | A generation under the previous master | The next collection |
| Takeover's claim written / registry file updated | As "resume's claim written" | The same |
| Snapshot note written / capture | A note for a snapshot that never was | The upkeep drops it |
| Capture / upload; upload / note erased | A `waiting` note; a note for a snapshot already uploaded | Retried; the retry finds it whole |
| Inside a snapshot delete | A `deleting` note | The upkeep completes it; a note for a run's stop snapshot is dropped |
| Scrub marked a run not durable / uploaded again | Run `failed` here; the bucket's record still says stopped, and names a snapshot that is not whole | The next upkeep uploads it again. Until then a resume on another daemon fails on the missing chunk, with the run left stopped |
| `daemon-id`, `remote-fleet-id` being written | The old file or none | Atomic; none is first use again |

### What still has to run live

Nothing in this entry has. In order of what would hurt most if wrong:

1. **`zfs receive` behind the first-record check**: full and incremental
   streams of real zvols, with `-c`, from a clone's origin (the base
   image) and from a previous snapshot, on the ZFS versions in use.
   That `toguid`/`fromguid` in a real stream are the `guid` properties
   the manifests record is the claim to prove. `zfs receive -u` with
   `-o origin=`. `zfs get type`. `zfs list -t filesystem,volume` for one
   dataset.
2. **Signed `If-None-Match` and `Content-Type`** against the service in
   use (versitygw 1.11 passed without them signed) and against a hosted
   S3, which has never been run at all.
3. **Verification against a real service's listings**: sizes as the
   listing reports them equal to what was written; a listing made right
   after a write shows it (the requirement; a service that is behind
   now fails uploads loudly instead of losing them quietly).
4. **Collection with the new rules and a real grace**: two rounds a
   grace apart; that `LastModified` parses; a second daemon collecting
   while the first uploads.
5. **The whole `vmintegration` suite**, pool off and pool on. The
   pool-on trio from 2026-11-18 was never completed on the previous
   commit either. `TestVMOffHost`'s last step expects an empty prefix:
   it does not call the start-up identity check, so `v1/fleet-id` is
   not written there.
6. **The scrub, eviction and rotation** against a real bucket, and what
   the extra requests cost per stop.
7. A commit interrupted by a real signal; a restore into a pool that is
   short; a daemon started against the wrong bucket.

## 2026-11-18 — VM driver: a create whose pool VM is killed under it boots its own

The warm-pool review's open item, closed for the case it was about: a
create that claimed a pool VM whose hypervisor was then killed from
outside (SIGKILL: the host's or the VM cgroup's OOM killer, an
operator's `kill -9`) no longer fails. The fallback is inside
`Driver.Create`, under the admission the create already holds, so no
other create can take its slot in between and it never returns to the
pool: the dead VM is given back (`unclaim`: its process is killed and
reaped, which releases its cgroup, UID and device node; its network
device is unplugged; its volume is destroyed), and the create continues
on the cold-boot path with a VM booted for it under the run's own name.
Once: the VM booted for it is not from the pool, and if that one dies
too the create fails like any other. The manager-level retry the first
version of this change had is gone: it went back through `Create`, which
took the pool's next VM (two dying pool VMs made a 500), and it gave its
admission up and took it again (a concurrent create could take the slot
in between and make a 503).

The line is drawn at how the VM died, not at any claim failure:

- **Killed from outside: replaced.** Only `SIGKILL`, read from the
  hypervisor's wait status (`MachineExit.KilledFromOutside`). It is no
  fault of the run's and would not happen to a VM booted for it.
- **Died of its claim: not replaced.** A hypervisor killed by a seccomp
  filter (`SIGSYS`: on the hot-plug path of an architecture whose list
  lacks a call, say), a guest that panics bringing up the hot-plugged
  device or powers off (the hypervisor exits with a code): a VM booted
  for the run would die the same way, and replacing it would turn one
  fast failure into two slow ones. The create fails, with the exit and
  the hypervisor's diagnostics in the log.
- **Alive: not replaced**, as before (an image without iproute2, say).
- **The caller has given up: not replaced.** Nothing is booted for a
  create whose context is done.

Every death at a claim now counts in the pool's backoff, as a death in
the pool does, and the count is reset when a claim succeeds, not when a
VM is taken. Before, `take` reset the count and the pool's watcher
ignores a claimed VM, so a pool whose every VM died of its claim never
paused: five creates made eleven boots and all failed.

A dead hypervisor's sockets fail at once, but its exit is only seen once
its process has been reaped and its output pipes drained (the daemon
waits up to 5 s for those). A pool VM whose claim failed because its
process did not answer at all (`vmUnreachable`: the vsock or API socket
failed, as opposed to an exit code from the guest or an HTTP answer from
the hypervisor) is given up to 1.5 s, under the cleanup deadline, to be
seen gone before it is judged alive.

An allowlist run keeps its place in the network across the replacement:
its namespace holds the listener of its proxy, which the manager opened
for the run and still holds, so the dead VM's device is unplugged
(`Network.Unplug`: the namespace is sealed again and the tap removed if
anything still holds it) and the replacement's device is attached on
the same proxy. An open run's place has no listener and goes entirely,
as with `Detach`; the replacement gets a new one. The first failure is
logged with its exit, the hypervisor's diagnostics and the claim's
error before the replacement boots.

Verified on the fakes only, race-clean: on none, allowlist and open, a
pool VM killed inside its guest setup gives a working run on a VM booted
for it, the dead VM killed (its confinement released) and its volume
gone, an allowlist run's one proxy kept and its device moved to the new
VM, an open run's place replaced; two pool VMs killed under claims, and
the create still succeeds without taking the second; a VM whose exit is
seen 300 ms after its sockets fail is still replaced; a `SIGSYS` or a
guest's own exit fails the create without a boot, and two of them in a
row leave the pool with two deaths and a paused refill; a given-up
create boots nothing. The wait status is read from real processes in a
unit test, and `Unplug` against the fake host network. **It has not run
against a real hypervisor**: no live host was available for this
change, and `TestVMWarmPoolRaces` (which kills pool hypervisors with
`SIGKILL` as creates take them, and accepts a create that succeeds or
fails) is the live check that goes with the validation host's next
suite run.

## 2026-11-20 — VM driver: independent review of the claim's fallback

A sixth review, of the change above, by reading and on the fakes; again
with no live hypervisor.

Fixed:

- **A rollback ran under a deadline that began with the create.**
  `Create` made its 30 s cleanup context before it booted or claimed
  anything, so a rollback had whatever the boot and the claim had left
  of it. With a boot longer than that (the default `BootTimeout` is
  120 s), or with the second boot the fallback adds, a VM whose claim
  failed was killed under a deadline already passed: nothing of it was
  released there, and it came back as a leftover for the reaper, which
  did converge. Older than the fallback (a slow cold boot had it too),
  made more likely by it. The deadline now starts where the claim
  failed.
- **The fake machine's exit could be read before it was reaped**, which
  a real wait status cannot; and the branch "not seen gone after the
  grace" had no test. Both closed in the tests.

Read and found sound, not proved on a host:

- **Nothing of the dead VM is left when the replacement boots.**
  `unclaim` runs only once the process has been waited for, and `Kill`
  then removes the cgroup (which must be empty to go) before the UID,
  device node and socket directory are given up. The hypervisor is the
  first process of its own PID namespace, so nothing of its tree
  outlives it holding the tap, and the daemon closed its own copy at
  the hand-over. The replacement has another name, so another volume,
  cgroup, device node and socket directory; a UID given out again is
  checked against one cell's sockets only.
- **A re-attached allowlist place is a fresh one.** After `Unplug` the
  namespace has the sealed ruleset (which the watch's baseline is then
  of), its loopback address and its listener, exactly as after
  `Listen`; the tap's filter, queueing discipline, route and neighbour
  entry went with the tap, and `Attach` makes all of them again before
  the new tap is up. The namespace's connection tracker is not flushed:
  nothing reads its state (the proxy's port is admitted by address and
  device, and the connection cap counts from the new ruleset).
- **A VM cannot have itself replaced.** No run's code is in a pool VM
  before its claim succeeds, and a process cannot `SIGKILL` the first
  process of its own PID namespace, itself included. What can is the
  kernel: a pool VM that reaches its cgroup's memory limit at the
  hot-plug would be replaced once and counted.
- **A caller cannot drive the backoff.** A death is counted only when
  the process is seen gone before the daemon kills it; a create that is
  cancelled, or fails for a reason of the run's, leaves a live VM, which
  is discarded uncounted.

Left as they are:

- A VM whose process takes longer than the grace to end (queued disk I/O
  under its limit is what delays a killed hypervisor) fails its create
  as before the change, and that death is not counted.
- A pool VM that was killed and whose claim failed at `Attach` is
  replaced although an allowlist run's place went with the failed
  `Attach`: one boot is spent before the second claim is refused.

## 2026-11-20 — off-host storage: third independent review, of the fixes

A reviewer who wrote neither the slice nor its fixes went through what
the second review's fixes changed (`985d2e5..9d3575e`), after merging
`main` (the warm pool's claim fallback) into the branch. Like the entry
before it, **nothing here has run live**: no hypervisor, pool or S3
service was available, and everything below is unit tests on the fakes,
or reading where it says so. The live list at the end of the previous
entry stands, with the additions at the end of this one.

### The merge of `main`

`README.md` and `AUDIT_OPEN.md` conflicted (both sides appended a
section; both are kept). `internal/vm` merged without conflict. The
fallback's replacement boot is inside `Driver.Create` and only happens
for a create of the golden image (a pool VM is never taken for a
snapshot); no off-host path — resume, fork, `snapshot:<id>` — reaches
it, and what it gives back (`unclaim`: the dead VM's volume, cgroup and
tap) is a clone of the golden image that the restore marks and the
startup sweep's new cases do not concern. Read, and the whole unit suite
of both sides passes together.

### Found and fixed, each with a test that fails without the fix

| | Finding | Fix | Test |
|---|---|---|---|
| C1 Medium-high | **A repair was read as a takeover.** A scrub marks a run that is not whole `failed` on every daemon that looks. The next `stopped` record another daemon wrote — the repair by the daemon with the copy, or the give-back of a resume that failed on the missing chunk — was "the run moved on without this copy": the view was `superseded` for good. On the daemon holding the only whole copy this also ended the repair, and the run resumed nowhere (its data reachable only by a fork on that host). The same from the publish side when the upkeep's upload flight ran before its sync | A newest record that says `stopped` with the snapshot this daemon holds is that same stop, whoever wrote it: verified and adopted, or published again from where the record is (`reconcileRun`, `advanceStopped`). A view that is not durable and has no copy on the host follows the record instead of being kept as superseded | `TestARepairElsewhereIsNotATakeover`, `TestAFailedResumeElsewhereDoesNotStopTheRepair`, `TestAPublishThatMeetsTheSameStopIsNotSuperseded`, `TestAViewWithNoCopyFollowsTheRecord` |
| C2 Medium | **Collection never deleted a snapshot on a busy fleet.** A4's second look gave the whole round up when any record or manifest anywhere was new since the round began, and a round reads every record and manifest in between. A fleet in which some run stops, resumes or is destroyed more often than that takes kept every destroyed run's disk in the bucket for good | The second look reads only what is new and keeps what it names and everything that builds on (`Store.spare`, `CollectStats.Spared`); the rest goes. A change that cannot be read still puts the round off | `TestACollectionIsNotPutOffByWhatDoesNotConcernIt`, `TestARecordWrittenWhileACollectionLooksKeepsItsSnapshot`, the A4 test's third order |
| C3 Medium | **A fresh upload deleted with the snapshot it replaced** (an instance of A4's open window that had a fix). A round deleted a due snapshot's manifest and then everything listed under its name. A base image uploaded again once the manifest was gone lost its new chunks and manifest to that listing, after its upload and the stop built on it had verified | Only the chunks the deleted manifest named go; other attempts are aged like all chunks no manifest names, in the same round. All due manifests are deleted before any chunk | `TestACollectionTakesOnlyTheUploadItDecidedOn`, `TestLeftoversUnderACollectedSnapshotGoToo` |
| C4 Medium | **`destroyed` records could be gone in thirty hours.** They are kept for thirty graces and the grace may be one hour. A daemon down for a weekend republished the runs destroyed meanwhile that it had copies of: a disk its owner deleted, resumable for the rest of its retention | Kept for thirty graces or `--stopped-retention`, whichever is longer (`Store.Tombstones`). A daemon away for longer comes back to copies past their own retention, which its reaper removes | `TestADestroyedRecordOutlivesTheRetention` |
| C5 Medium-low | **A stop snapshot booted by ID after all.** Only `snapshot:<id>` was held to "an ID names a caller's snapshot". A daemon's own reference is the ID between a fixed prefix and suffix; a create given one the host had no snapshot for fetched it from the bucket unasked: another run's stop as a new run | A reference that is not on the host is admitted like an ID | `TestAStopSnapshotIsNotFetchedForACreateUnderAnySpelling` |
| C6 Medium-low | **A restore waited behind every upload.** B7's bound was one pool; as many stops as there are transfers held all of them for up to two hours each, and a resume that had to fetch waited with the run already claimed | With more than one transfer, uploads take at most all but one | `TestARestoreDoesNotWaitBehindEveryUpload` |
| C7 Low | A resume that failed because the snapshot is not whole gave the run back and called it durable again in the same breath | The give-back verifies first (`unclaimHeld`) | in `TestAFailedResumeElsewhereDoesNotStopTheRepair` |
| C8 Low | Collection named a snapshot not whole by its own chunks only. A caller's snapshot whose base image was collected under it (A4's window) has all its chunks, restores nowhere, and no scrub looks at caller snapshots | The chain is followed; the log says which, why and of what purpose | `TestACollectionNamesASnapshotWhoseChainIsBroken` |
| C9 tests | Two of the second review's fixes passed with the fix taken out: the look `publishHeld` takes after the record had no test, and `TestCollectLeavesWhatIsNotItsOwn` planted its foreign objects without a modification time, which nothing collects whatever its name | A test for the first; the objects are written with an old time, and two are under a real snapshot's prefix | `TestAStopIsNotDurableWhenItsBaseWentBeforeTheRecord` |

### Re-verified of the earlier findings

Each by taking its fix out and seeing its test fail: A1 (chunks kept
once the manifest was attempted; `Already` verifies), A2 (watched for
the grace), A3 (rotation's take-back), A4 (marking from manifests not
due), A5, A6 (the listing's prefix, and after C9 the shapes), B1, B2,
B6, B8, R1 (object set type), and eviction's look. All fail without
their fix.

### The departures, looked at

- **Rotation without compare-and-swap** (read). A resurrected manifest
  needs the rotator's write and its check to both fall between a
  collector's listing of the snapshot and that collector's first delete
  under it; with C3 a collector no longer deletes a manifest it did not
  decide on, so such a manifest stays until the next round ages it. It
  is no longer a loss whichever way it falls: everything that would use
  it verifies (`ensureBase`, `usableParent`, `Already`, the restore). A
  caller snapshot resurrected this way is listed again, unrestorable,
  until deleted again. A second rotator only overwrites the same
  document under the same key. One interleaving does lose, and is left:
  a rotator reads a manifest, an upload retracts it and writes another
  attempt, the rotator's write puts the old one back. It needs a whole
  upload inside one listing of the rotator's.
- **Records rotated when fenced** (read): a rotation and a claim both
  create generation N+1 and one is refused; the owner is preserved, and
  the owning daemon's next sync finds its own record at N+1 and
  verifies. A caller can see a spurious 409 on a resume during a pass.
- **Secrets removed from the environment** (read): nothing reads them
  again; there is no reload; the hypervisor's jail re-execs with a
  fixed `PATH` only. The commands that are started with the daemon's
  whole environment (`docker`, and `iptables` for its egress firewall)
  belong to the docker driver, under which remote storage does not
  start. The vm driver's own commands that run before `remote.open`
  (the preflight's `zfs` and udev probe) go through the same wrapper
  and get no secret either. Key files remain the answer for what
  `/proc/<pid>/environ` of the daemon itself still shows.
- **The minimum grace only at the flag**: accepted; C4 is the one place
  a short grace hurt.
- **Tombstones**: see C4.
- **The BEGIN record** (read against the definitions, not run):
  `drr_type` at 0, `drr_payloadlen` at 4, then `drr_begin`: magic 8,
  versioninfo 16, creation time 24, object set type 32 (32 bits),
  flags 36, `toguid` 40, `fromguid` 48, name 56 to 312 — the size of
  `dmu_replay_record_t`. The magic is `0x2F5bacbac`; the header type is
  the low two bits of versioninfo (1 a substream, 2 a package), so the
  feature bits above them (compressed, large blocks, embedded data)
  pass; `DMU_OST_ZVOL` is 3. A stream in the other byte order is read
  in it. A wrong offset refuses every restore and admits nothing.
  Whether `toguid`/`fromguid` equal the `guid` properties the manifests
  record is the first item on the live list, as before.

### The window that is still open (A4), exactly

After C3 it is: a collector's second look (`spare`) passes the place
where an upload's manifest will be, then the upload writes its
manifest, verifies its chain, writes its record and verifies again, and
only then does the collector delete the manifest of what the upload
builds on. The collector's side of that is the rest of one listing and
one delete per due snapshot; it was that plus every chunk of every
snapshot deleted before the base. It reaches only uploads that finish
in that moment on a parent nothing else has referred to for a whole
grace: in practice the first stop on a host whose golden image no
stopped run has used for a day.

`--remote-local keep` does **not** make it harmless: it makes it
repairable. The stop is reported durable and is not, until that host's
next scrub (6h by default) finds the base gone and the upkeep uploads it
and the stop again from the local copy. A host lost inside those hours
loses the run. With `drop` it is lost at once. A caller's snapshot in
the same position has no scrub at all: after C8 a collection names it,
and nothing repairs it though the host that took it still has it.

A fix exists and is not cheap enough to make blind. A two-phase delete:
the collector first copies a due snapshot's manifest to
`snap/<id>/condemned` and deletes `manifest` — from then on every
verification of that snapshot fails — and an upload, before it builds
on a snapshot, writes `snap/<id>/pin/<random>` under it. The collector
then lists the snapshot's own prefix: a pin puts the manifest back, and
everything it builds on with it; none, and the chunks go. Whichever of
the two writes is second sees the first, on a service whose listings
show what was written. Pins and condemned copies are aged like other
garbage, and a later round finishes or undoes what a crashed one left.
It needs a real service to be tried against, and belongs before `drop`
is recommended to anyone.

*[2026-11-21: built, on the fakes only, as the two-phase delete; see
that entry for the protocol, its assumptions, every interleaving and
what it does not cover. `drop` is now refused without conditional
writes and experimental with them; still not recommended.]*

### Not fixed, and why

- **Verification is sizes only, and nothing repairs what only a read
  finds.** A chunk of the right size and the wrong bytes passes every
  check until a restore, which fails closed (SHA-256, then the tag). The
  daemon whose restore failed keeps calling the run durable, and so does
  the daemon that still has a whole copy and could upload it again. A
  provider can always withhold, so this is not a new power of its; it
  is bit rot that goes unrepaired with the repair at hand. Wants a
  scrub that reads (the manifest has every chunk's SHA-256; no key is
  needed beyond the manifest's), and a restore that fails on content to
  tell the run's holder.
  *[2026-11-21: the scrub that reads, the repair and the restore's
  report are built (fakes only); see that entry.]*
- **A service that reports sizes differently from what was written**
  fails every upload after sending it, three times per try, and the
  upkeep tries again every round with no backoff: nothing is lost and
  everything is uploaded continuously. The live check of listings
  (item 3 of the previous entry) has to pass before this is left
  running anywhere.
  *[2026-11-21: the upkeep now backs off on the same failure twice in a
  row; see that entry. The live check of listings still has to pass.]*
- **Two daemons on one state directory** (a cloned image): see the
  README. Each adopts the other's running runs as its own lost ones.
  Nothing detects it.
- **The fleet identity on a service without conditional writes**: two
  daemons that first start in the same moment can each remember a
  different name, and the one whose write lost refuses its next start
  with the "another bucket" message. Fails closed; remove
  `remote-fleet-id` on that host.
- **A caller snapshot that is not whole is not uploaded again**, even
  from the host that still holds it; only stopped runs are repaired.
- A stop still holds its run for its upload; restores and base-image
  uploads are still one at a time; `Maintain`'s uploads are still one
  after another (all as the previous entry says).

### With remote storage off

Checked by reading: the three differences the previous entry lists are
harmless. Host commands lose seven variables none of them reads. A
single dataset is looked up with `-t filesystem,volume`: every caller
goes on to require the daemon's owner mark, which no filesystem has
unless an operator put it there. The startup sweep lists filesystems
under the pool root once (one more `zfs list -r`, of the same cost as
the volume listing beside it) and destroys only those carrying this
daemon's mark; the driver sets that mark on volumes only, and never on
the root, so nothing inherits it. `DELETE` of an unknown ID consults the
bucket only when there is one. Nothing in this entry changes a daemon
without `--remote-endpoint`.

### What has to run live before anyone's data depends on this

The seven items of the previous entry, and:

8. **Collection with the new look** on a bucket that changes under it:
   a stop elsewhere during a round does not put the round off, and a
   record or manifest written during it keeps what it names.
9. **A scrub failure across two daemons**: lose a chunk, scrub both,
   resume on the one without a copy (it fails and the run is reported
   failed, not durable), let the other repair, resume on the first.
   `TestVMOffHost` now expects `failed` after its deleted-chunk resume.
10. **A daemon restarted after `--stopped-retention`** with copies of
    runs destroyed meanwhile: gone within a reaper tick or two, with a
    `destroyed` record still or again in the bucket.
11. **Four stops uploading and a resume that has to fetch**, with the
    default four transfers: the resume does not wait for the uploads.

## 2026-11-21 — VM driver: first run on real x86-64 hardware

The README's runbook ("Validating on a fresh x86-64 host") was followed
for the first time, on bare metal: a 4-core Pentium Silver N5000 laptop,
3.7 GB (about 2.6 GB available beside its owner's desktop session),
eMMC, the pool a 30 GB sparse file on it. Debian 13 with Linux 6.12 and
ZFS 2.3.9 (not the runbook's Ubuntu 24.04, 6.8 and 2.2), Cloud
Hypervisor v54.1 (static), guest kernel `vmlinux-x86_64` of
`ch-release-v7.2.8-20261009`, base image Ubuntu noble's cloud image.
**The host is far below the runbook's 16 GB and has no disk of its own
for the pool: no figure below is representative of a production host.**
The point was correctness and confinement on real x86-64.

### First run (main at `eeb0d54`)

- `install-host.sh`: host ready; every check passed (seccomp filter for
  x86_64, Landlock, cgroup v2 controllers, tbf, connlimit, static
  hypervisor).
- Root-only unit tests: all pass, none skipped.
- Live suite, pool off and on: 6 pass, 9 fail, 3 skip each. Nothing
  failed in a way that let a guest or hypervisor reach anything it should
  not; the failures were the four defects below, plus the warm-pool
  tests, which need more memory than the host has.
- Seccomp kills: none (`type=1326` absent from the kernel log). The
  runbook's `grep -E 'type=1326|seccomp'` matched seven
  `__seccomp_filter` stack frames inside the intended memcg OOM reports
  of `TestVMCgroupLimitIsEnforced`: false positives.

### Defects found, and what was done

- **A. `/var` was in every hypervisor's jail.** The jail bound the
  kernel at its host path, and the default (and documented) kernel path
  is under `/var/lib`; `TestVMConfinement` and four other tests fail on
  `/var inside the jail`. The arm64 runs had the kernel elsewhere.
  *Fixed:* the jail always holds the kernel at `/kernel` (`vm.JailKernel`)
  and the hypervisor is told that path, so its Landlock rules (made from
  its command line) follow; the host path can be anything, and existing
  installs need no change. The confinement test is as strict as before
  and also requires the kernel's host path to be absent from the jail.
  Moving the documented location out of `/var` was the alternative; it
  would have left the jail revealing wherever an operator does keep it.
  Also: `vm.DefaultKernel` is now the architecture's own name
  (`/var/lib/teploy-sandbox/vm/vmlinux-x86_64` on amd64, `.../Image` on
  arm64), so `SBX_VM_KERNEL` is no longer needed on x86-64.
- **B. `TestVMNetworkIsolation` needed guest IPv6.** The runbook's guest
  kernel has no IPv6 (`CONFIG_IPV6` unset in `ch_defconfig`, x86 and
  arm64 alike) and the test's control stopped when guest b had no IPv6
  link-local address, so its guest-to-guest, guest-to-host and ARP
  checks never ran on x86-64. *Fixed (test):* the IPv4, ARP and layer 2
  checks run regardless; the IPv6 ones run when the guest has IPv6 and
  are logged as not applicable when it does not (not a skip).
  `TestVMNetworkFailsClosed`'s one IPv6 line is guarded the same way.
  Checked by reading that nothing depends on guest IPv6 and that a guest
  that has it is still refused: the tap's netdev ingress chain accepts
  only the VM's ARP request for the gateway and IPv4 from its own
  address and drops everything else; both inet chains of the run's
  namespace and the host's forward chain drop `meta nfproto != ipv4`;
  the namespace and the host's end of the link have IPv6 disabled by
  sysctl; the guest setup turns IPv6 off on the device and tolerates a
  kernel without it. As first written this left the host's IPv6 drop
  untested on x86-64, on the wrong belief (in the test's comment) that a
  guest without an IPv6 stack cannot send IPv6: it can, by hand, through
  an AF_PACKET socket. The review of this branch caught it. Both tests
  now have guest a send raw IPv6 frames (to b's MAC, to all nodes, and
  through the gateway) whatever its kernel, and check with captures in
  guest b and on the host's end of a's link (each of which must see its
  own control frame leave) that none arrives, and, with rules in place,
  that the tap's ingress dropped them all. `SBX_VM_REQUIRE_IPV6=1` turns
  "not applicable" for the checks through the guest's own IPv6 stack into
  a failure. Those checks (link-local addresses, `ping -6`) still need a
  guest kernel with IPv6; they last ran on arm64.
- **C. A low disk limit made a VM that could not boot.** The run's
  `io.max` was set before boot. A fresh clone of the runbook's x86-64
  golden read about 465 MB before its agent answered (cgroup `io.stat`;
  about 490 MB within the first 20 s), so under the suite's 2 MiB/s
  (`TestVMDestroyIsNotHeldByQueuedIO`) the boot took longer than the
  driver's two minutes, and under 10 MiB/s a create took 46 s. The arm64
  image read about 100 MiB to boot (entry of 2026-11-16 on the seccomp filter and limits), which fits in
  two minutes at 2 MiB/s: that is why it passed there. Why the x86-64
  image reads five times more was not established; it is a never-booted
  clone each time (`snapd.seeded` 34 s, `ldconfig`,
  `systemd-networkd-wait-online` waits its full 2 min on a run with no
  network), but which of these reads what was not measured.
  *Decided as product behaviour, not a test patch:* an operator who sets
  a low `--vm-disk-mbps`/`--vm-disk-iops` must not get VMs that cannot
  boot, and cannot size a limit by an image's boot. A VM now boots with
  its read limits raised to at least the defaults (256 MiB/s and 16000
  IOPS; a higher limit, or none, is unchanged) and its write limits the
  run's own from the start: a boot of that image wrote about 2 MB (and
  discarded about 230 MB, which the kernel's throttle counts as 512
  bytes an operation; 42 writes and 68 discards before the agent
  answered), so its writes need nothing raised. The run's own read
  limits are written as soon as its agent first answers, or as soon as
  its cgroup has read `BootReadBudget` (1 GiB, about twice that image's
  boot; checked every 200 ms, so a boot can overshoot by about 50 MB),
  whichever is first, before a create returns or the warm pool counts
  the VM as ready. A VM that is being killed is never given them (its
  limits are only lifted then, see `DrainGrace`). Under 2 MiB/s a
  create now takes 3.4 to 3.7 s, under 10 MiB/s 3.7 to 3.8 s; the rate
  checks of `TestVMLimits` pass after boot as before. The pool-on
  failure ("the warm pool did not fill") went with it.
  *The trade-off, the noisy-neighbour one,* as first written was too
  wide, and an independent review of this branch said so: every boot
  got the default rate for reads and writes until its agent answered,
  for up to the boot timeout, and on a resume or fork (a tenant's own
  disk) when the agent answers is the tenant's choice, so a tenant
  could loop boots of a snapshot whose agent never starts and get that
  rate for two minutes at a time, back to back. Now:
  - only reads are raised, and at most 1 GiB of them per boot;
  - the boots of one snapshot that did not come up are held back by
    what they read at the raised rate: summed since the snapshot's last
    boot that came up, each 1 GiB of it makes the next boot of that
    snapshot wait (refused as at capacity, without starting anything),
    10 s, doubling up to 5 min; one boot that comes up, by anyone,
    clears it (`TestASnapshotWhoseBootsKeepFailingIsBackedOff`). A
    second review found that the first version counted failed boots,
    so cancelled ones (callers that went away, client timeouts under
    load) locked every user of a shared snapshot out for minutes; a
    boot cancelled after a few MB now costs about that. What remains of
    sharing: once a snapshot's failed boots have read 1 GiB, everyone
    who boots it waits with the one who caused it;
  - a boot whose reads cannot be counted (its io.stat cannot be read or
    does not list its disk, 50 times in a row at 200 ms) gets the run's
    limits, with one warning in the log
    (`TestABootThatCannotBeCountedGetsTheRunsLimits`). So a VM whose
    first disk read takes more than 10 s (an overloaded host) loses its
    raised boot reads and boots under the run's limits: the safe
    direction, noted by the final review, not changed;
  - **what is left, plainly:** a read limit below the defaults applies to
    a run after its boot. It does not cap what a caller who can create
    runs freely can read: every boot, including a create that succeeds
    and is destroyed again, reads at up to the default rate until its
    agent answers (about 465 MB for the README's image), so a
    create/destroy loop reads at the default rate for each VM booting at
    once, and a tenant with many snapshots can boot each at the raised
    rate up to 1 GiB. How many boot at once is bounded only by
    `--vm-max-runs` (by default unbounded).
  - **Follow-up, not done:** a host-wide budget for boosted boots (a cap
    on the raised-rate reads, or on the boots holding raised limits, at
    any one time, for the whole daemon), which would bound this without
    `--vm-max-runs`; per-tenant accounting would need a tenant identity
    the driver does not have.
  The alternative of keeping the run's limit for the boot was rejected
  because it makes a low limit unusable.
- **E. Runbook step 10 could not be met.** `-test.run TestVM` selects the
  three off-host tests, which skip without an S3 service, and the step
  said no `--- SKIP`. *Fixed (docs):* step 10 leaves them out with
  `-test.skip`, and a new step 10b runs them against versitygw 1.11 on
  loopback (the service the earlier live runs used; the commands were
  checked against the release on a workstation, not run on the x86-64
  host). Also corrected: the seccomp check reads `type=1326` only; the
  daemon and suite need no `SBX_VM_KERNEL`; small hosts' warm-pool
  failures and the "skipping the 2048/4096 MiB guest" lines are expected
  and say why; a Debian aside; the guest's interface name is `ens5` on
  x86-64 (`enp0s5` on arm64), which nothing depends on.

### Found on the re-run, and left open

- **A guest that floods its own disk stalls its own reads here.** With
  the fix for C, `TestVMDestroyIsNotHeldByQueuedIO` booted, but on this
  host (Linux 6.12, ZFS 2.3.9) the hypervisor's one disk-queue thread
  sleeps in `io_submit` (state D) once the 48 throttled writers queue,
  so the guest's reads, which have their own budget in `io.max`, wait
  behind the writes, and the guest's agent stops answering execs until
  the writes drain. AIO is in use (`fs.aio-nr` 128 per VM). On arm64
  (6.8, ZFS 2.2) the same guest kept answering. It only harms the guest
  that does it: the destroy is still held only for `DrainGrace` (3.4 s,
  four runs). The test now waits for the guest's first-boot reads to
  settle (about 16 s at 2 MiB/s), accepts an exec that times out once
  the writers run, checks that the writes reached the host, and keeps
  its destroy assertions; that a run under a low limit can freeze itself
  with writes is recorded here, not fixed. Which of the kernel, ZFS 2.3's
  zvol or blk-throttle makes the submission block was not established.
- **The golden image could boot lighter.** Masking snapd's seeding and
  `systemd-networkd-wait-online` in the base (README step 7) would cut
  every create's boot I/O and the 2-minute "starting" state; not done,
  because it changes what the runbook's image is and the figures
  against the arm64 runs.

- **Two unit tests that can flake, each seen once in CI on this branch.**
  `TestAPoolVMNotSeenGoneInTimeIsNotReplaced` failed once ("2 VMs
  booted, want only the pool's one") in both CI jobs of one push and
  passed on the re-run, on the pull request's run and 80 times locally
  (with and without `-race`). By reading: the pool's periodic refill
  look (every 2 s) can fall inside the create's 1.5 s claim grace,
  before the death at claim pauses the pool, and then boots a refill.
  Not caused by this branch (the boot path only gained one call after
  the agent answers). It failed again in the root-only unit run on the
  laptop in the review round, so the test now holds the pool's refill
  off while the claim waits (a create that boots its own VM still fails
  it). Likewise
  `TestReleaseKeepsTheUIDUntilTheCgroupIsEmpty` failed once in CI's
  `verify` job ("device or resource busy" on the retried release) and
  passed in `vm-root` and on the pull request's run: its fake cgroups
  give a removal 200 ms, which a loaded runner can spend before the
  first retry. Neither failed in 8 local runs of the whole package
  (`-cpu 1,2`). It failed once more in CI on main (PR #6's push run).
  Fixed in the code, not the test: a removal whose time ran out gave up
  right after the kill that had just emptied the group, without looking
  again; it now tries the removal once more before it reports the group
  busy (`TestARemovalLooksOnceMoreAfterItsLastKill`, with no time at
  all, fails without it). On a real host this only spares an error when
  the last kill's processes are reaped in that moment.

### Re-run on the branch (kernel at its default `/var` path, no `SBX_VM_KERNEL`)

- Root-only unit tests: all pass (245), no skip, the four named tests
  pass.
- Pool off and pool on (`SBX_VM_WARM=1x512=1`): `TestVMHostIsPrepared`,
  `TestVMLifecycle`, `TestVMConfinement`, `TestVMMemoryStaysInsideItsCgroup`,
  `TestVMCgroupLimitIsEnforced`, `TestVMLimits`, `TestVMNetworkIsolation`
  (IPv6 part logged not applicable), `TestVMNetworkTiers`,
  `TestVMNetworkFailsClosed` pass in both.
  `TestVMDestroyIsNotHeldByQueuedIO` passed with the pool on and failed
  with it off in the suite (the guest queued too little: see above);
  with the test change it passed three times alone with the pool off
  and once with it on. Not re-run: the whole suite after that last test
  change (it touches that one test only).
- No `type=1326` in the kernel log over all of it; the two OOM kills
  are `CONSTRAINT_MEMCG`, the ones `TestVMCgroupLimitIsEnforced` causes.
- Figures, not representative (3.7 GB laptop, eMMC file pool): cold
  create to agent ready 4.7 / 4.9 s (pool off / on), resume 4.2 / 4.4 s,
  fork 4.2 / 4.3 s, stop 0.46 / 0.56 s, destroy 0.23 / 0.27 s. 512 MiB
  guest: cgroup limit 584 MiB, peak 516 MiB (guest + 4.0 MiB),
  hypervisor VmHWM about 530 MB, pids.peak 11 of 136. Network setup:
  open runs host side 160 to 250 ms, guest side 0.2 to 1.2 s; allowlist
  host side 50 to 100 ms. Default-size VMs that fit, from the first run:
  1, and 1 by the cgroup limits.

### Review round (same day): what changed, and the live re-run

An independent security review of the branch asked for: reads only and
a read budget for the boot limits, and a back-off of failing snapshot
boots (entry C above); raw IPv6 frames from a guest without an IPv6
stack, and `SBX_VM_REQUIRE_IPV6` (entry B above); a kernel path that is
not absolute and clean refused at start; the jail helper's error naming
`/kernel` and not the host's path; usage text and figures made
consistent. Each with a unit test that fails without it, except the
live-test changes. Re-run on the laptop with the final code (logs kept
with the run's other files):

- Root-only unit tests: all pass (249), none skipped (the first attempt
  of this round hit the pool test's flake above, now fixed).
- `TestVMCgroupLimitIsEnforced`, `TestVMLimits`,
  `TestVMDestroyIsNotHeldByQueuedIO`: pass, pool off and on (create under
  2 MiB/s 4.1 s; destroy 3.4 and 3.7 s).
- `TestVMNetworkIsolation`, `TestVMNetworkFailsClosed`: pass, pool off
  and on; in each, 9 raw IPv6 frames per check (guest to guest, after
  the rules were restored, with every table flushed, with every table
  deleted) reached neither guest b nor the host's end of a's link, and
  with rules the tap's ingress counted them dropped. The first attempt
  failed on the test's own capture (a socket for 0x86DD alone does not
  see frames leaving, so its control failed); it captures every
  protocol now. With `SBX_VM_REQUIRE_IPV6=1` the test fails, as meant,
  on this guest kernel.
- No `type=1326` in the kernel log.
- Not run live: the read budget ending a boot whose agent never answers,
  and the back-off (unit tests only; the suite has no guest that will
  not start its agent).

### Second review round (same day)

A second review asked for: the back-off charged by raised-rate bytes
read, not by failures (entry C); the docs to say plainly that a read
limit below the defaults applies after boot and is no cap on a caller
who can create runs freely, with a host-wide budget for raised boots
recorded as a follow-up (entry C); the raw IPv6 check to fail when
sending outlasted its captures, and guest a's own capture to see its
frames leave (entry B); the boot watch to fail closed when it cannot
count (entry C). Unit tests for each fail without the change. Re-run
on the laptop, pool off: root-only unit tests all pass (254), none
skipped; `TestVMLimits`, `TestVMDestroyIsNotHeldByQueuedIO`,
`TestVMNetworkIsolation`, `TestVMNetworkFailsClosed` pass; no
`type=1326`. Not run live: the back-off and the fail-closed watch (no
guest in the suite fails its boot after reading, or hides its io.stat).

### Still needs a host of the runbook's size (16 GB, a disk for the pool)

- `TestVMWarmPool` and `TestVMWarmPoolRaces` in the suite (here the pool
  never reaches its target: the headroom gate needs more free memory than
  the host has; `TestVMWarmPoolRaces` passed alone in the first run), and
  so the `WARM`/`COLD` lines and pool-on start figures.
- The 2048 and 4096 MiB guests of `TestVMMemoryStaysInsideItsCgroup`.
- Density, and the go/no-go against the plan's phase-1 numbers (start
  from the pool, default-size VMs per host): nothing here speaks to it.
- The off-host tests (step 10b) on x86-64, and the whole suite green
  pool off and pool on in one run each. The x86-64 and bare-metal items
  stay open.

## 2026-11-21 — off-host storage: the two-phase delete (A4), the scrub that reads, upload backoff, and `drop`

Closes, under the assumptions stated below, the three items the third
review left open: A4's last window, "verification is sizes only", and
"a service that reports sizes differently ... no backoff"; and decides
`--remote-local drop`. **Nothing here has run live, and nothing here
has been reviewed**: no S3 service, hypervisor or pool was used. All of
it is unit tests on the in-memory bucket (`offhosttest.Memory`, with
`offhosttest.Faulty` for misbehaviour at one exact request) and on the
VM driver's fakes. With remote storage off nothing changes (below).

### The protocol as implemented

Collector (`Store.Collect` → `Store.condemn`), for the snapshots a round
finds due after its second look (`spare`), which now also spares a
snapshot that gained a pin, or a condemned copy, since the first look:

1. Read the manifest. Gone, or naming another upload attempt than the
   one decided on: leave it.
2. Write its bytes to `snap/<id>/condemned`, with `If-None-Match: *` on
   a service with conditional writes. Refused: another collection
   condemned it first (or left a copy); leave it.
3. Read the manifest again; not byte for byte what was read in 1:
   delete the copy and leave it.
4. Delete the manifest. From here every `Verify` of the snapshot fails.
5. List `snap/<id>/`. The manifest goes back if the listing does not
   show this round's own two writes (copy there, manifest gone: a
   listing that is behind), or shows any pin this round did not itself
   find aged.
6. If half the grace or more has passed since the second look began
   (the collector's own clock), every condemned manifest goes back.
7. Everything a snapshot that goes back builds on, if this round
   condemned it too, goes back with it.
8. Put back: write the manifest (with `If-None-Match: *` where there are
   conditional writes, so a fresh manifest an upload wrote meanwhile is
   left; without them a HEAD first), then delete the copy.
9. The rest: delete the chunks of the attempt the manifest named, then
   the copy.
10. Any error between 2 and 9 puts back, in the same process, whatever
    was condemned and not yet decided.

Uploader, and anything that checks before it builds or writes
(`Store.Verify`, so: the upload's checks, "already uploaded",
`usableParent`, the check after a stop's record, the scrub, eviction,
the give-back; and the rotation pass before it reads a manifest): write
`snap/<x>/pin/<16 random hex>` under each snapshot of the chain, **then**
read that snapshot's manifest. Every pin has a fresh name: a collector
deletes only a pin it has itself watched for the grace, and a name
written twice could be deleted as the old one with the new write in it.

Every round, besides: a pin keeps its snapshot and everything that
builds on it from being due, without counting as a reference (the time
a snapshot has been seen unreferenced keeps running: a pin covers a
moment); a condemned copy with no manifest beside it that the round has
not watched for the grace keeps its chain too (another collection may
put it back), and its chunks are nobody's garbage; one watched for the
grace is put back if whole, or finished (chunks, then copy) if its
chunks are already in pieces, or put back regardless when something
refers to it or pins it; a copy beside a manifest is a crash's
leftover, and the snapshot is not condemned again until the copy has
been watched for the grace and deleted; pins are deleted once watched
for the grace. All of these age only on readable service times, like
chunks.

### Why it closes the window, and on what

"Whichever of the two writes comes second sees the first": the
uploader's check found the manifest only if it read before step 4; its
pin was written before that read, so before step 5, and a listing begun
after a write finished shows it — the pin is seen and the manifest goes
back. If the listing showed no pin, the pin came after step 5, so after
step 4, and the uploader's read finds no manifest: it builds on nothing
that is going. The durable statement rests on the last check (after the
record for a stop, after the manifest for a caller's snapshot); its pin
is written after the second look began (the look would otherwise have
seen the manifest or record and spared the snapshot), so the pin is at
most half a grace old at step 5 (step 6), and a pin stands for at least
a grace (no collector deletes one it has watched for less). Conditional
writes make step 2 a single owner per condemnation, so two collections
cannot decide differently on the same snapshot.

The assumptions, each a place it can fail:

- **Listings show every write that finished before they began.** Step 5
  checks that the listing shows this round's own two writes, which
  catches a listing that lags in time; it cannot catch one that drops a
  pin it otherwise shows writes around. What providers document is
  below.
- **Conditional writes**, for more than one collector on a bucket. Every
  daemon collects. Without them `drop` is refused (below).
- **No process pauses for half a grace or more between two adjacent
  steps** where no clock is read: between step 6 and the first delete of
  step 9, or for four uploader requests inside one collector round trip
  (row 13 below).
- **Every daemon on the bucket runs this version.** An older collector
  neither condemns nor sees pins (it counts both as foreign objects and
  leaves them), so A4's window is open against it exactly as before.

### Every interleaving of the two-phase delete

C is the collection that condemns (steps 1–10 above), U an upload (or
anything that checks: pin, then read), C2 another daemon's collection.

| # | Interleaving | What happens | Test |
|---|---|---|---|
| 1 | U pins and checks (and writes its manifest and record and checks again) after C decided, before C's step 4 — A4's open window | U's pin is in C's listing: the manifest goes back, U's stop or caller snapshot restores | `TestTwoPhaseAnUploadThatCheckedBeforeTheCondemnationIsSeen` (stop; caller snapshot) |
| 2 | U pins after C's listing (step 5) | U's read finds no manifest: the base is sent again (or the parent judged unusable); C deletes the old attempt; U's stop restores from the fresh upload | `TestTwoPhaseAnUploadThatPinsAfterTheListingBuildsOnNothingCondemned` |
| 3 | U pins between C's steps 4 and 5 | The pin is seen; the put-back is refused by the fresh manifest U wrote on finding none; U restores | `TestTwoPhaseAPinBetweenTheDeleteAndTheListingIsSeen` |
| 4 | U's manifest, record or pin lands before C's second look, or before its first | The snapshot is spared, or never due | `TestABaseCollectedUnderAnUploadThatBuildsOnIt` (third order), `TestARecordWrittenWhileACollectionLooksKeepsItsSnapshot`, `TestTwoPhaseARotationPassIsSeenByACondemnation` (pin in the first listing) |
| 5 | C's listing in step 5 is behind (a replica as it was before step 2) and so also misses a pin U wrote just before | Nothing is concluded from it: the manifest goes back | `TestTwoPhaseAListingThatIsBehindDecidesNothing` (`Memory.Freeze`) |
| 6 | C's listing shows C's own writes and not a pin written before them | **Not covered**: the chunks go under a verified upload. Excluded by the listing assumption | none (an assumption) |
| 7 | C stalls between its second look and its decision for longer than half the grace; U's pin, watched for the grace by C2, is gone | Every condemned manifest goes back | `TestTwoPhaseACollectionThatStallsPutsBackWhatItCondemned` |
| 8 | C's deletions (or a stall) carry it past half the grace while later condemned snapshots are still to go; C2 finds one of their copies stale and puts the manifest back; U builds on it | *Fix round:* the bound is asked again before each snapshot's chunks are deleted, and the rest are put back once past it. *Corrected in the fourth fix round:* what is left is a pause between that check (with the owner's two HEADs) and the delete requests right after it that lasts past the moment another collection may act. A stale take-over needs the copy watched for a whole grace (so a pause of about half a grace); a referred-to take-over needs three quarters of a grace of watching (so a pause of about a quarter of a grace) — it was half a grace, i.e. almost no margin, until the fourth fix round | `TestReviewDeletionLoopOutlivesTheGrace` (the reviewer's reproduction, two condemned snapshots in one round) |
| 9 | C2 decides the same snapshot due while C has condemned it | With conditional writes C2's step 2 is refused and it leaves the snapshot. **Without them** both can own it, one can see a pin the other does not, and the other deletes chunks under the restored manifest | `TestTwoPhaseOnlyOneCollectionCondemnsASnapshot`; without conditional writes: open (`keep` repairs it; `drop` is refused everywhere: `TestDropIsRefused`, `TestOpenRefusesDrop`) |
| 10 | C2's round meets C's undecided condemnation of a child | C2 keeps the child's chain (the base), which it would otherwise find due; C puts both back on a pin | `TestTwoPhaseASecondCollectionKeepsWhatACondemnedSnapshotBuildsOn` |
| 11 | C2 meets a condemnation C left (C died) | Watched for the grace: put back if whole, finished if in pieces; before that, kept | `TestTwoPhaseACrashedCondemnationIsFinishedOrUndone` |
| 11a | *Fix round.* C is alive after all: it has put the copy back and condemned it again since C2's listing | C2 acts only on the very copy it watched (HEAD: same time and size), so it leaves it | `TestAStaleTakeoverDoesNotUndoALiveCollection` |
| 11b | *Fix round.* C2's own round is already half a grace old when it reaches the stale copies | It leaves them to the next round | `TestAnOldRoundLeavesStaleCopiesToTheNext` |
| 11c | *Fix round.* C2 meets C's undecided condemnation of a snapshot a record (or a staying manifest) refers to | *Fourth fix round:* put back once C2 has watched the copy for **three quarters** of a grace. Half a grace (the third round) was only moments after C's own bound: an owner whose last check passed just under it was still deleting (`TestR7cEarlyTakeoverRightAfterTheOwnersBound`). *Third fix round:* not at once — at once undid a live C: U's ensureBase (then unpinned) let C condemn and list the base, U wrote its manifest, C2 put the base back, U verified and was durable, C deleted the base | `TestACondemnedSnapshotThatIsReferredToIsPutBackAtOnce`, `TestR7bImmediatePutBackUnderALiveCollector` |
| 11d | *Third fix round.* C, between its decision and a snapshot's chunk delete, finds its copy gone (another collection took it), written again (*fourth round:* not the copy it wrote, by size and time to about a second) or a manifest back (an upload sent the snapshot again) | Deletes nothing of it; a manifest standing again is left standing (the put-back is refused). Left: a copy written again within about a second, with the same size, is taken for its own | `TestTheOwnerLeavesACondemnationItNoLongerHolds`, `TestTheOwnerLeavesACopyWrittenAgain`, `TestTwoPhaseAnUploadThatPinsAfterTheListingBuildsOnNothingCondemned` |
| 7a | *Fix round.* C's machine is suspended: its monotonic clock stands still while the wall clock moves on (or the wall clock steps back) | Either clock at half the grace, or a wall clock that went back, counts as stalled | `TestAStallIsMeasuredByEitherClock` |
| 12 | A rotation pass reads and rewrites a manifest while C condemns it | The pass pins first: rows 1–4 apply to it as to an upload | `TestTwoPhaseARotationPassIsSeenByACondemnation` |
| 12b | *Third fix round.* A rotation pass's rewrite lands in C's gap between steps 3 and 4 (C read the old bytes, the pass writes, C deletes the rewrite and puts the old bytes back on the pass's pin) | The pass, after its final re-read, also looks for a condemned copy: any copy counts as skipped, so `previousKeyNeeded` | `TestR7bRotationInTheCondemnGap` |
| 12a | *Fix round.* The pass pins between C's delete and listing; or meets a condemned copy under the old master; or finds the manifest condemned between its listing and its read; or has its write replaced by C's put-back of the old bytes | The pass walks condemned copies too, and counts each of these as skipped, so it answers `previousKeyNeeded: true` ("run again") instead of letting the old master be retired while a manifest under it can still come back (which would stop every collection and `ensureBase` fleet-wide) | `TestTwoPhaseARotationInEveryOrder` (four orders) |
| 13b | *Third fix round.* A repair's replace-in-one-write (`Manifest.replaces`: read the standing manifest, then an unconditional PUT) of a snapshot C has read (step 1) and not yet deleted (step 4) | **Not covered**, beside row 13: C deletes the fresh manifest and, on the repair's pin, puts back the damaged one; the repair's check after the write may have passed in between. As narrow as row 13 (the repair's PUT, pin and read inside one round trip of C). The portable follow-up for both rows: `Verify` GETs the condemned key after reading a manifest and treats a copy as "being condemned, not whole" | none (residual) |
| 13 | A re-upload of a snapshot that is not whole (U retracts the old manifest, writes a new one, pins, checks) entirely between C's steps 3 and 4 | **Not covered**: C deletes the fresh manifest and puts back the old one (not whole) on U's pin; what U built on it is lost. Four sequential requests of U inside one round trip of C, and only for a snapshot already not whole | none (residual) |
| 14 | A daemon of an older version collects | A4's window as before 2026-11-21 | none (deployment rule, README) |

Rows 2 and 3 are outcome tests (they pass with any of steps 5–7 alone);
the others each failed with the step they prove taken out, below.

### Every place a crash between two steps leaves state (two-phase delete, scrub, backoff)

The rows of the 2026-11-20 table stand; these are added.

| Between | Left behind | Recovered by |
|---|---|---|
| Copy written / manifest deleted (steps 2–4) | A copy beside the manifest; the snapshot is whole | Not condemned while the copy stands; the copy goes once watched for the grace, and the snapshot the ordinary way after |
| Manifest deleted / decision (4–6) | A copy, no manifest, chunks whole | Other collections keep it and its chain; once watched for the grace, the manifest is put back (it may be condemned again later) |
| Manifest put back / copy deleted (8) | As the first row | As the first row |
| Chunks being deleted / copy deleted (9) | A copy, chunks in pieces | Once watched for the grace: the rest of the chunks, then the copy |
| An error anywhere in 2–9 | — | Put back in the same process; what could not be is a stale copy for a later round |
| Pin written / the upload's end, or the uploader dies | A pin | Protects the snapshot until watched for the grace, then deleted |
| Scrub took "durable" back / repair uploaded | Run `failed`, with the damaged chunk, in the registry file (`remote.damage`, fix round) | The next upkeep repairs from the local copy. After a restart the damage is handed back to remote storage (`RememberDamage`) before anything runs: the run is not called durable by sizes, nor its copy evicted, until the snapshot is uploaded again or a read finds the chunk whole |
| Repair's chunks written / manifest replaced | The damaged manifest still stands; new chunks no manifest names | Retried by the upkeep; the new chunks are aged like any |
| Backoff in force / restart | Nothing (memory only) | The next upkeep tries at once, and backs off again after two identical failures |

### Listings and conditional writes, by provider (from their documentation, 2026-11-21)

Not verified by running anything against them.

| Provider | A listing shows a write that finished before it began | `If-None-Match: *` on PUT |
|---|---|---|
| AWS S3 | Documented, for PUT and DELETE ([consistency model](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html#ConsistencyModel)) | Documented ([conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)) |
| Cloudflare R2 | Documented ([consistency](https://developers.cloudflare.com/r2/reference/consistency/)) | Documented ([S3 API](https://developers.cloudflare.com/r2/api/s3/api/)) |
| Tigris | Documented within one region; eventual across regions for global buckets ([consistency](https://www.tigrisdata.com/docs/concepts/consistency/)) | Documented ([conditionals](https://www.tigrisdata.com/docs/objects/conditionals/)) |
| Google Cloud Storage (XML API) | Documented ([consistency](https://docs.cloud.google.com/storage/docs/consistency)) | No: create-only is `x-goog-if-generation-match: 0`, which this client does not send ([preconditions](https://docs.cloud.google.com/storage/docs/request-preconditions)) |
| MinIO | Vendor blog only, not reference docs | Vendor blog only |
| Wasabi | A general "immediate consistency" claim, listings not named | Not documented |
| Backblaze B2, Ceph RGW, DigitalOcean Spaces, versitygw | Not documented | Not documented (a third-party patch says B2 rejects the header) |
| Hetzner Object Storage | Not documented | Not supported on versioned buckets; otherwise not documented |

"Not documented" is silence, not a known failure. W2 (choosing a
provider) has to test both on the one chosen.

### The scrub that reads

`--remote-scrub-read-mb` (default 256: about 1 GiB a day per daemon at
the default 6h interval) bounds what each scrub fetches. It reads the
chunks of the stopped runs the daemon reports durable and of everything
their streams build on, sequentially, one chunk at a time, holding each
to the SHA-256 in its (authenticated) manifest; nothing is decrypted.
A cursor (snapshot, upload attempt, chunk) carries it from one scrub to
the next; each snapshot is read once per pass, so a shared base image is
read once, not once per run. A chunk whose bytes differ is read again;
damaged twice, it is remembered for that upload attempt (`Store.markBad`,
memory only), after which `Store.Verify` reports every snapshot built on
it not whole (`Incomplete.Content`), and the scrub takes "durable" back
from each run concerned through the same `confirmDurable` the sizes
scrub uses. A later read of the same chunk that matches forgets it.

Repair: the upkeep's upload meets the snapshot not whole. If the damaged
snapshot is its own and the host has it, it uploads a new attempt and
the manifest is **replaced** in one write (`writeManifest`, on a 412
whose standing manifest is known damaged; plain overwrite without
conditional writes) — never taken back first, since a read's verdict
can be wrong and the old chunks then stay until aged. If the damaged
snapshot is one its chain builds on and this host has that one (same
guid), that one is uploaded again (`Service.repair`; a base image through
`ensureBase`, which now treats a known-damaged base as not whole) and the
snapshot itself stands. With no copy here: `failed`, `STOPPED RUN AT
RISK`, nothing deleted.

A restore that meets a damaged chunk (`Download`) remembers it the same
way, so the give-back after a failed resume (`unclaimHeld`, which
already verified) now reports the run `failed` with the chunk named,
instead of `durable` again. The resume's own error says the same.

### Backoff

`publishPending` and the snapshot-note retry skip an upload whose last
two tries failed the check after the upload with the same words
(`ErrRemoteIncomplete`, or the new `ErrRemoteListing`: a listing that
does not show a chunk a request by name finds); the wait is 5 minutes,
doubling, at most 6 hours. Storage that cannot be reached is not backed
off (it costs nothing and must be retried at once when it is back); a
failure that changes, or a success, ends the wait. Only the upkeep's own
retries wait: a stop, a snapshot or a resume never does. Memory only.

### `--remote-local drop`: refused (decision of the fix round)

*[Superseded the same day. The first version of this branch accepted
`drop` with conditional writes, as below. The independent review found
that the two-phase delete as first built did not close the window by
the argument it rests on (finding 1: the half-grace check was made once
before an unbounded deletion loop), and the decision taken after it is:
`drop` is refused on every service, and the daemon does not start with
it (`remoteFlags.validate`, `dropRefused`). Why: with `drop` the bucket
is the only copy the moment a stop is durable, so each residual of the
table (rows 6, 8, 9 without conditional writes, 13, 14), each chunk the
scrub has not read yet, and each loss by the provider loses a run
outright where `keep` leaves it repairable; and none of the protocol has
run against a real service or been through a review of its fixes. It
stays refused until live items 12–16 have passed and a review of the
fix round agrees. Tests: `TestDropIsRefused`, `TestOpenRefusesDrop`. The
manager still implements the policy (the off-host fake tests set it
directly), but nothing a daemon is started with reaches it.]*

What the first version said:

The 2026-11-20 recommendation was "`keep` until A4 has run live under
collection load", because A4's result could only be repaired from the
local copy. The two-phase delete closes that window by the argument
above, **on a service with conditional writes** (row 9 needs a single
owner per condemnation) and a listing that shows every finished write.
So: `drop` is refused at start on a service without conditional writes
(`checkLocalPolicy`, in `open` after the probe), and accepted with
them, with a start-up warning that it is experimental. It is not made
the default and not recommended for real data: with `drop` the bucket is
the only copy, so rows 6, 8, 13 and 14, bit rot the scrub has not read
yet, and any loss by the provider have nothing to repair from, and none
of the protocol has run against a real service. `keep` is still what the
README tells everyone to use.

### Tests added, and the change each was proved against

Each was run with the named part of the change taken out locally; each
failed, and passes with it in.

| Taken out | Fails |
|---|---|
| Step 5's pin check | `TestTwoPhaseAnUploadThatCheckedBeforeTheCondemnationIsSeen`, `TestTwoPhaseASecondCollectionKeepsWhatACondemnedSnapshotBuildsOn` |
| Step 5's own-writes check | `TestTwoPhaseAListingThatIsBehindDecidesNothing` |
| Step 6 (half the grace) | `TestTwoPhaseACollectionThatStallsPutsBackWhatItCondemned` |
| Step 2's `If-None-Match` | `TestTwoPhaseOnlyOneCollectionCondemnsASnapshot` |
| Step 7 (what it builds on) | `TestTwoPhaseASecondCollectionKeepsWhatACondemnedSnapshotBuildsOn` |
| Keeping the chain of an undecided condemnation | `TestTwoPhaseASecondCollectionKeepsWhatACondemnedSnapshotBuildsOn` |
| Finishing or undoing stale condemnations | `TestTwoPhaseACrashedCondemnationIsFinishedOrUndone` |
| Step 10 (put back on error) | `TestTwoPhaseACrashedCondemnationIsFinishedOrUndone`, `TestTwoPhaseASecondCollectionKeepsWhatACondemnedSnapshotBuildsOn` |
| `Verify`'s pin | `TestTwoPhaseAnUploadThatCheckedBeforeTheCondemnationIsSeen`, `TestTwoPhaseACrashedCondemnationIsFinishedOrUndone`, `TestVerifyPinsTheWholeChainFirst` |
| The rotation pass's pin | `TestTwoPhaseARotationPassIsSeenByACondemnation` |
| `Verify` reporting known damage | `TestTheScrubThatReadsFindsBitRot`, `TestADamagedSnapshotIsRepairedFromALocalCopy`, `TestARestoreThatFailsOnContentIsRemembered` |
| Remembering a damaged read | the four above and `TestOneBadReadIsNotAVerdict`; at the daemon level `TestTheScrubThatReadsFindsBitRotAndTheCopyRepairsIt`, `TestTheScrubThatReadsWithoutACopySaysTheRunIsAtRisk`, `TestAResumeThatFailsOnContentLeavesTheRunFailed` |
| The second read | `TestOneBadReadIsNotAVerdict` |
| Forgetting on a good read | `TestOneBadReadIsNotAVerdict` |
| Replacing a damaged manifest; not taking it back first; repairing the chain; `ensureBase` seeing damage | `TestADamagedSnapshotIsRepairedFromALocalCopy` (one subtest each) |
| The scrub that reads in `ScrubRemote` | `TestTheScrubThatReadsFindsBitRotAndTheCopyRepairsIt`, `TestTheScrubThatReadsWithoutACopySaysTheRunIsAtRisk` |
| The backoff in `publishPending`; `ErrRemoteListing` among the backed-off | `TestUploadsThatFailVerificationTheSameWayBackOff`; `TestWhichUploadFailuresBackOff` covers what is and is not backed off |
| `drop` refused (fix round: on every service), and where `open` meets it | `TestDropIsRefused`, `TestOpenRefusesDrop` |
| The scrub answer's new fields | `TestRemoteScrubAnswersWhatItRead` |

Also `TestRemoteFlagBounds` (the new flag). Existing tests changed, and
why: seven filters of "the chunks of a snapshot" now leave out pins
(`/pin/`), which checks write beside them; the outage in
`TestOnlyAnUnusableParentFallsBackToAFullSend` fails chunk writes, not
pins (it is about the stream, and a failed pin now stops the check
before it); `TestACollectionTakesOnlyTheUploadItDecidedOn` (C3) now
accepts the race ending in a put-back as well as a delete, since the
listing it intercepts is now the one after the condemnation and the
upload's pin is in it; and the "nothing deleted" check of
`TestTheScrubFindsWhatIsNoLongerWhole` compares keys rather than a count
(pins are added, and aged out, by design).

`offhosttest`: `Faulty` gained `BeforeDelete`/`AfterDelete` and
`Headed`; `Memory.Freeze` answers listings from a past moment.

### Not fixed, and why

- **Rows 6, 8, 13, 14** of the table: assumptions and residuals, stated.
- **Without conditional writes** two collectors can still disagree
  (row 9). `keep` repairs that from the local copy at the next scrub, as
  before; `drop` is refused.
- **What a daemon has read is not shared.** Damage one daemon found is
  known to the others only through their own scrub or restore.
  *[Fix round: kept across a restart of the daemon that found it,
  through the run's `remote.damage`.]* A marker in the bucket was not
  added: it would be unauthenticated, and a false one would make every
  daemon re-upload from its copies.
- **Caller snapshots** are protected by the two-phase delete like
  stops (row 1 has a caller-snapshot case), but are still neither read
  by the scrub nor uploaded again when found not whole: only stopped
  runs are repaired (third review's item, unchanged).
- **Cost, not measured**: every check writes one pin per snapshot of the
  chain (a stop makes about three checks; a scrub one per durable run),
  pins stand for a grace, and every collection lists them; a condemnation
  is a read, a write, a read, a delete and a listing per snapshot; the
  scrub that reads re-reads the manifests of every durable run's chain
  each round.
- On a service whose modification times cannot be read, pins and
  condemned copies are never collected (as chunks without a manifest),
  and a crash's leftover copy keeps its snapshot from ever being
  condemned again.

### On the wire, and with remote storage off

With remote storage the change is additive: `POST /v1/remote/scrub`
also answers `contentReadBytes`, `contentSnapshots` and `damaged`; a
run's `remote.error` can name a damaged chunk. One flag is new
(`--remote-scrub-read-mb`), and `--remote-local drop` is refused at
start on a service without conditional writes where it used to be
accepted.

Without it, unchanged (the scrub route still answers 400). Every new path is behind `OffHost != nil` (`publishPending`,
the snapshot notes, `ScrubRemote`, the backoff), or in `internal/offhost`,
which nothing reaches without `--remote-endpoint`; `RemoteScrubReadBytes`
is set only when remote storage is. The Docker driver is untouched.

### What has to run live (additions to the list above)

12. **The two-phase delete against the chosen service**: a stop on a
    host whose base nothing refers to, with a second daemon collecting
    at a zero-length grace in a loop meanwhile; every stop restores. A
    listing right after a PUT shows it, and right after a DELETE does
    not, under load and across the service's regions or replicas.
13. **`If-None-Match: *` on the condemned copy** with two collectors
    racing it (and `drop` refused on a service without it).
14. **The scrub that reads**: what 256 MiB per round costs in egress and
    time; a chunk damaged by hand found, the run reported failed, the
    repair replacing the manifest, and a restore elsewhere byte-exact.
15. **A real resume that meets a damaged chunk**, reported `failed` with
    the chunk named on the daemon that tried. `TestVMOffHost` checks the
    state only after both damaged resumes; its list of "the snapshot's
    objects" now leaves out pins (changed here, not run).
16. **Backoff against a service that misreports sizes** (or a proxy that
    rewrites `Content-Length` in listings): uploads slow to one per
    backoff, and resume at once when it is fixed and the wait is over.
17. **The extra requests**: pins per stop and per scrub, and what a
    collection costs with them, on a bucket with thousands of stops.

### Fix round, after the first independent review (same day)

A reviewer who wrote none of this went through the branch for data loss
and recommended merging after fixes; their reproduction of finding 1 is
adopted as a regression test (`TestReviewDeletionLoopOutlivesTheGrace`).
Still **nothing here has run live**. Each fix has a test that failed
with the fix taken out locally.

| | Finding | Fix | Test (fails without the fix) |
|---|---|---|---|
| 1 | The half-grace check ran once, before a deletion loop of unbounded length. A round with several condemned snapshots deleted the first one's chunks long enough for another collection to find a later copy stale and put its manifest back, an upload to build on it and be reported durable, and then deleted that snapshot's chunks | The bound is asked before **each** snapshot's chunks are deleted; past it, the rest are put back. The stale side acts only on the very copy it watched (HEAD: same time and size) and only within half a grace of its own round's start | `TestReviewDeletionLoopOutlivesTheGrace`, `TestAStaleTakeoverDoesNotUndoALiveCollection`, `TestAnOldRoundLeavesStaleCopiesToTheNext` |
| 2 | The stall guard used the monotonic clock only, which stands still while a machine is suspended | `stalled`/`pastHalfGrace`: monotonic or wall at half the grace, or a wall clock that went backwards, is a stall | `TestAStallIsMeasuredByEitherClock` |
| 3 | Rotation listed only manifests: a condemned snapshot put back later came back under the old master while the pass answered `previousKeyNeeded: false`; retiring the old key then stops every collection (one record or manifest it cannot read stops a round) and `ensureBase` | The pass pins first, walks condemned copies too, and counts as skipped (so `previousKeyNeeded`, "run again"): a condemned copy under a previous master, a manifest missing after the pin unless a current-master copy stands for it, and a manifest that is not, when re-read after the write, the bytes the pass sealed | `TestTwoPhaseARotationInEveryOrder` (four orders) |
| 4 | What the scrub that reads found, and where it was, lived in memory: after a restart a damaged run was durable again by sizes, and eviction could then drop the only whole local copy; a daemon restarted more often than the interval never scrubbed | The damaged chunk is kept with the run (`remote.damage` in the registry and on the wire) and handed back to the store at load (`RememberDamage`); it goes when the run is durable again. A pass begins at a random snapshot; the first scrub is due at a random point in the first interval | `TestDamageFoundBeforeARestartIsNotForgotten`, `TestDamageFoundBeforeARestartIsRepairedFromTheCopy`, `TestAScrubPassBeginsWhereItIsTold`, `TestAFreshDaemonScrubsWithinItsFirstInterval` |
| 5 | A content verdict on a snapshot the chain builds on, with no copy of that one here, fell through to retracting the snapshot's own good manifest | For any content verdict the new upload replaces the manifest in one write (`Manifest.replaces`); a replacement found not whole puts the previous bytes back (`takeBack`) instead of retracting | `TestADamagedParentWithNoCopyHereReplacesNotRetracts` |
| 6 | Backoff was keyed by run and never cleared: a later stop of the same run could wait up to 6h | Keyed by run and snapshot (`stopUploadKey`); waits for uploads no longer owed (runs destroyed, resumed, stopped again; snapshot notes gone) are dropped at each upkeep | `TestUploadsThatFailVerificationTheSameWayBackOff` (now with a second stop), `TestABackoffIsDroppedWithItsUpload` |
| 7 | An undecided condemnation of a snapshot that something staying refers to waited a grace | Put back at once (same re-HEAD and round bound as the stale side) | `TestACondemnedSnapshotThatIsReferredToIsPutBackAtOnce` |
| 8 | The give-back after a failed resume said durable on any answer that was not "not whole", including no answer | Durable only when the check passed; storage not answering leaves the run `pending` (the upkeep publishes, which verifies) | `TestAGiveBackThatCannotCheckDoesNotSayDurable` |
| 9 | A caller's `DeleteSnapshot` ignores pins, against `Verify`'s comment | Documented, not changed: nothing builds on a caller's snapshot and a restore from it in flight fails as a whole (`Verify`'s comment, README) | none (documentation) |
| 10 | Aged pins were deleted one request after another | `deleteKeys`, eight at a time | `TestAgedPinsAreDeletedConcurrently` |
| — | `drop` | Refused on every service (see above) | `TestDropIsRefused`, `TestOpenRefusesDrop` |

Reverts made for the proof: for 1, the per-snapshot bound, the re-HEAD
and the round bound each off; 2, the wall-clock comparison; 3, the walk
of condemned copies, "missing after the pin", and the re-read after the
write, each off; 4, `rememberDamage` at load, the damage on `notDurable`,
the pass's random start, and the scrub jitter; 5, replacing for any
content verdict (only for the snapshot's own chunk, as before) and
`takeBack` (retract instead); 6, keying by run alone, and each of the two
prunes; 7, the immediate put-back; 8, durable on a check that did not
answer; 10, one delete at a time; `drop`, the old accept-both rule.

What the fix round changes in the rest of this entry: rows 7a, 8, 9,
11a–c and 12a of the interleaving table; the scrub row of the crash
table; and "What a daemon has read is not shared" below now holds only
across daemons, not across a restart of one. New rows a review of the
fix round should look at: the stale side's HEAD comparison trusts the
service's modification time and size (a service that rewrites an object
without changing either would defeat it); `pending` after a give-back
that could not check is published by the upkeep, which writes the
record once more as a new generation (state and snapshot unchanged)
and verifies.

## 2026-11-21 — recoverable execs, capacity disk, per-run usage, wire contract

Additive daemon asks: `recoverable` execs with `X-Exec-Id` and
`GET /v1/runs/{id}/execs[/{execId}[/output]]`; `disk` in
`GET /v1/capacity`; `cpuSeconds`/`rxBytes`/`txBytes`/`diskBytes`/
`sampledAt` in `usage` behind `--usage-interval` (default off);
`docs/wire-contract.md`. Not reviewed yet (a review is another session).

### Limits, by design in this slice

- Exec records are memory only. A daemon restart loses every record and
  every running command (running runs do not survive a restart); the
  lookup answers 404 with that reason at once. A control plane that sees
  that 404 for an exec it started knows only "outcome unknown".
- Output is the last 1 MiB per exec (plus 128 KiB of stream bits), 8
  records per run, 64 per daemon: about 72 MiB worst case. Running
  records are never evicted, so a 65th concurrent recoverable exec (or
  9th on one run) is a 503. One run holds at most an eighth of the
  slots; a caller with eight or more runs can still take them all (the
  daemon has one token and no notion of callers: that bound belongs to
  the control plane). Finished records live 15 minutes. All constants,
  not flags.
- A recoverable exec's `timeoutSec` is capped at
  `--exec-recoverable-max-timeout` (default 1h, at most 24h): a running
  one holds a slot until it ends, and an hour covers builds and suites.
  It can be cancelled (`DELETE …/execs/{execId}`). Under Docker that
  kills only the `docker exec` client: the record and the run's
  in-flight slot are released, but the in-container process runs on to
  its own timeout or the run's stop (not fixed: Docker cannot signal an
  exec's process from outside without tracking its pid in the
  container).
- A recoverable exec counts as in flight like any exec, so a caller's
  stop, snapshot, fork or lease takeover is 409 `busy` while it runs.
  Unlike a connected exec, a detached one has no client to end it, so
  (fixed after review) a stop the daemon makes itself (expiry with
  `onExpire: "stop"`, graceful shutdown) first cancels the run's
  recoverable execs and waits up to 10 s; before that fix such a stop
  was refused and a shutdown lost the run's state. Plain execs still
  block those stops as on `main`.
- Text-mode resume offsets are exact only when the output is valid UTF-8
  and the stream did not break inside a character; base64 mode is exact.
- `signal` is inferred from exit code 128+n; a command that exits 137
  itself reads as SIGKILL.
- Usage sampling runs at most four runs at a time; disk is read on the
  first round and every tenth (it is the expensive read), not at a stop,
  whose sample has a 3 s budget.
- Usage numbers are observations, not a ledger: usage after the last
  sample is lost on destroy, expiry-destroy and crash (a stop takes a
  final sample). Counters reset to zero for a fork and for a run resumed
  on another daemon (as `runningSec`). `diskBytes` is a level.
- Docker usage needs the daemon on the Docker host with cgroup v2. CPU
  and network are read only after checking the container's pid is in a
  cgroup named after its full ID, and the cgroup file is read again
  afterwards to catch a reused pid; a daemon that cannot see the host's
  `/proc` (containerised, remote Docker, Docker Desktop/colima from the
  host OS) reports `diskBytes` only. `docker container inspect --size`
  walks the writable layer on every sample. Under gVisor (`runsc`) the
  cgroup and namespace of `State.Pid` are assumed to be the sandbox's:
  not verified.
- VM `cpuSeconds` includes the hypervisor's own threads (it is the VM's
  cgroup). VM network counters come from the tap only; a `none` run has
  no device and reports no rx/tx (Docker reports 0 there). VM
  `diskBytes` is ZFS `used` of the clone.
- `disk` in capacity: the ZFS pool's own `used`/`available` (not the
  driver's dataset; a quota on the dataset is not reflected), or statfs
  of Docker's data root (`freeBytes` is f_bavail). Absent when the probe
  fails or exceeds 5 s.

### Tests and what ran live

Unit tests (each shown to fail with its change reverted locally):
dropped stream does not kill a recoverable exec and its exit/output are
fetched after; failed stream writes do not fail the command's copy;
resume by counted base64 offset with no duplicates, paging, bad
offsets; timeout and inferred signal; plain exec unchanged (same bytes,
no header, still killed by a dropped stream); records dropped with the
run; restart answers 404 with the reason quickly; output bound (3 MiB
written, last 1 MiB held, truncated read, tail); ring buffer against a
model, including its memory bound; per-run/total bounds and eviction;
expiry; capacity disk (Docker statfs via a fake CLI, ZFS pool name,
absent on failure); usage off by default (no samples, JSON unchanged),
monotonic across stop/resume/restart, high-water mark within one
container, fork at zero; Docker sampler cgroup check; tap counter
direction.

- Ran live: `TestRealRecoverableExecAndUsage` against real Docker
  (colima, so the daemon was not on the Docker host): the dropped stream,
  the command finishing, resume by offset and `diskBytes` passed; CPU,
  network and capacity `disk` were not exercised (Linux-host only).
- Not run live: `vm_usage_integration_test.go` (`TestVMRecoverableExecs`,
  `TestVMUsage`), Docker CPU/network/disk on a Linux Docker host, and
  anything under gVisor.

### Review fixes (2026-11-21, same day)

An independent review of PR #6 found one blocker and several smaller
items; each fix has a test that fails without it (shown locally):

- Lock-order deadlock (blocker): destroy dropped a run's exec records
  under the manager lock while the reaper's sweep held the registry lock
  and asked the manager about runs. The drop now happens after the
  manager lock is released, and the sweep releases the registry lock
  before asking. Regression: the reviewer's repro,
  `TestExecSweepAndDestroyDoNotDeadlock`. Every other registry call site
  takes the manager lock (if at all) only before or after, never around.
- Detached execs and daemon-made stops, cancel endpoint, timeout cap,
  per-run share (above). HTTP test of the 503 path and of the refused
  exec giving back its in-flight reservation.
- Found while testing the cancel endpoint: the recoverable path did not
  flush its headers, so a command that printed nothing held back
  `X-Exec-Id` until its first output. It is flushed at once now (the
  plain path is untouched).
- Docker's data root is asked for once and cached; capacity is a statfs.
- statfs uses f_frsize on Linux (no test: the two are equal on the
  filesystems at hand); cgroup paths with `..` are not followed; usage
  fields are hidden with sampling off.

### Second review fixes (2026-11-21)

- The Docker data-root lookup no longer holds its lock across `docker
  info`: one command at a time, on its own 30 s deadline, shared by every
  caller, each of which waits only as long as its own context. Test: a
  fake docker that blocks; a 200 ms caller behind a 3 s one returns in
  time and the command runs once.
- The reaper re-checks, on the live record, that a run is still due
  before cancelling its execs (it decides from a copy): a run stopped and
  resumed during a slow tick keeps its execs. Test.
- A cancel that lands after the command ended by itself (an exit code of
  its own, no error) no longer reports `cancelled`; the exit code stands.
  Test.
- Usage samples carry the run's container generation (bumped at every
  stop): a VM keeps its name across stop and resume, so a sample started
  under the old VM could land on the new one. Test.
- `--usage-interval` must be 0 or at least 1s. Test.
- `disk` for Docker is a statfs of the data root's path on the daemon's
  own filesystem: wrong or absent against a remote Docker or a Docker VM
  (Docker Desktop, colima). Documented, not changed.

### Third fix round, after the second independent review (same day)

A second reviewer recommended merging after fixes. The branch was first
brought up to date with `main` (PR #6, exec recovery and usage; the only
conflicts were the appended sections of this file and `Manager`'s
fields, both kept). Their three reproductions are adopted as regression
tests (`review2_test.go`, `TestR7b*`); each failed on the commit they
reviewed. **Nothing here has run live.**

| | Finding | Fix | Test (fails without the fix) |
|---|---|---|---|
| 1 (blocker) | The first fix round's "put back at once" (finding 7) undid a **live** collection's condemnation with no time between them (row 11c) | Another collection acts early on an undecided condemnation only after watching the copy itself for half a grace. The owner looks again before each snapshot's chunk delete that its copy still stands (HEAD) and that no manifest is back (HEAD); otherwise it deletes nothing of it. `ensureBase` pins the base before it reads it | `TestR7bImmediatePutBackUnderALiveCollector` (fails with all three out), `TestACondemnedSnapshotThatIsReferredToIsPutBackAtOnce` (half-grace rule), `TestTheOwnerLeavesACondemnationItNoLongerHolds` (copy re-check), `TestTwoPhaseAnUploadThatPinsAfterTheListingBuildsOnNothingCondemned` (manifest re-check), `TestEnsureBasePinsTheBaseFirst` |
| 2 | The stale side compared a listing's time (milliseconds) with a HEAD's Last-Modified (whole seconds): never equal on real services, so crashed condemnations were never put back or finished | `sameTime` compares to the second (with the size). The in-memory bucket now answers HEAD in whole seconds and listings in milliseconds, as real services do, so every stale-side test meets the difference | `TestR7bHeadTimeIsWholeSeconds`, and the stale-side tests of the earlier rounds (four fail with an exact comparison) |
| 3 | A rotation's rewrite inside C's gap between re-read and delete was reported done while the old bytes came back | After its final re-read the pass looks for a condemned copy; any copy is skipped (`previousKeyNeeded`). Row 13b documents the same gap for a repair's replace, with the portable follow-up | `TestR7bRotationInTheCondemnGap` |
| 4 | A failed run's remembered damage, with no local copy, was never read again (the scrub reads durable runs only), so a wrong read or a repair elsewhere left it failed for good | Each scrub that reads re-reads the one remembered chunk of every failed run (`RecheckDamage`); whole, or the snapshot uploaded again since: forgotten, and the upkeep publishes and verifies it | `TestARememberedDamageIsReadAgain` (across a restart) |
| a | `ensureBase`'s damaged-base replacement, and the 412 path that meets a standing damaged manifest, replaced without keeping the previous bytes: a replacement then found not whole left no manifest | Both keep `previous` (`ensureBase` tells the upload what it replaces, which is what matters on a service without conditional writes) | `TestADamagedReplacementThatIsNotWholePutsThePreviousBack` (two paths) |
| b | Setting a run `pending` (the give-back's first step; the sync meeting this daemon's own newer record) dropped its remembered damage | Carried | `TestPendingKeepsTheDamage` (both paths) |
| c | A leftover copy beside a manifest, on a service with unreadable times, was kept for good and blocked rotation | A copy beside a manifest goes on this daemon's own watch alone: deleting it is safe whatever its collection does (it keeps the bytes it would put back, takes the missing copy for a listing that is behind, and — by blocker 1 — deletes no chunks of a snapshot whose copy no longer stands). The rotation then finishes | `TestALeftoverCopyGoesWithoutTheServicesTime` |
| d | Condemning every due snapshot before listing any: with thousands due and a 1h grace, every round put them all back | At most `CondemnBatch` (256) per round; the rest wait | `TestACollectionCondemnsABatch` |
| e | The replace path (read, then unconditional PUT) between two repairing daemons | Documented as harmless: both write whole manifests of the same snapshot (same guid, same stream), either standing is correct; a repair whose check fails puts its previous bytes back only while what stands is still its own (`takeBack`). `If-Match` would make it exact on services that have it; not used, for the reason of A3 | none (documentation) |

Changed earlier tests, and why: the A4 test's first order no longer
expects its collection to delete the base (the base is pinned by
`ensureBase` now, so it is not due); row 2's test accepts the owner
leaving the base when the upload has sent it again; finding 7's test
now expects nothing at first sight and the put-back half a grace later.

New things a review of this round should look at: the owner's re-check
is two HEADs per condemned snapshot, which narrows rather than closes
the moment between the check and the chunk delete (row 8's residual); a
copy rewritten within the same second with the same size is taken for
the one watched (a later round then acts on it); and `RecheckDamage`
reads one chunk per failed run per scrub, outside the read budget.

### Fourth fix round, after the third independent review (same day)

A third reviewer recommended merging after one fix; their reproduction
is adopted (`review3_test.go`, `TestR7cEarlyTakeoverRightAfterTheOwnersBound`),
and failed on the commit they reviewed. **Nothing here has run live.**

| | Finding | Fix | Test (fails without the fix) |
|---|---|---|---|
| 1 | The early take-over of a referred-to condemnation fired at first sight plus half a grace: only moments after the owner's own bound (its last look plus half a grace), so an owner whose last check passed just under its bound was still deleting | Three quarters of a grace of watching; README states the wait; row 8's wording corrected (the residual is a pause of about a quarter of a grace for this path, half for the stale path) | `TestR7cEarlyTakeoverRightAfterTheOwnersBound`, `TestACondemnedSnapshotThatIsReferredToIsPutBackAtOnce` (nothing at half a grace, the put-back at three quarters) |
| a | The re-read of failed runs' damage ran only with the scrub that reads on | Called from `ScrubRemote` itself, whatever `--remote-scrub-read-mb` says | `TestARememberedDamageIsReadAgain` (the restarted daemon now reads nothing else) |
| b | `sameTime` required the same truncated second; services that round Last-Modified differ by one | Within a second either way. Live check 18 below | `TestSameTimeAllowsASecondEitherWay` |
| c | A leftover copy beside a manifest was deleted without looking that it was still the copy watched | HEAD first, same size and (when the listing had a time) `sameTime`; a copy written afresh is left | `TestALeftoverCopyWrittenAgainIsLeft` |
| d | The batch cap could take a parent and leave its due child for the next round, which then logged the child as not whole | Due snapshots are batched deepest first: a batch that holds a snapshot holds every due snapshot built on it | `TestABatchKeepsAChainTogether` |
| e | The owner's re-check only asked that some copy stood | The owner HEADs its copy right after writing it and, before each chunk delete, requires that very copy (size, and time within a second). One more request per condemned snapshot. Left: a copy rewritten within about a second with the same size | `TestTheOwnerLeavesACopyWrittenAgain` |

18. **Last-Modified precision of the chosen service**, live: a listing's
    time and a HEAD's for the same object, many times; they must agree to
    within one second (`sameTime`), or every stale condemnation and
    leftover copy is left for good.

## 2026-11-21 (evening) — VM driver: first live run of main (`38ca4c0`) on x86-64, first off-host run against a real S3 service, and the fixes it called for

**Host.** The same small bare-metal x86-64 laptop as the first x86-64 run
(Pentium Silver N5000, 4 cores, 3.7 GB, eMMC, file-backed pool; Debian 13,
kernel 6.12.117, ZFS 2.3.9, Cloud Hypervisor v54.1, guest kernel
`ch-release-v7.2.8-20261009`). Far below the runbook's 16 GB: its density
and throughput figures are not representative. Golden image reused (the
guest agent is byte-identical between the commit it was built from and
`38ca4c0` once built with `-trimpath -buildvcs=false`).

### Results on main `38ca4c0` (unchanged)

- Root-only unit tests: PASS (265, no SKIP).
- Live suite, pool off: 15 PASS, 2 FAIL. Pool on (`1x512=1`): 14 PASS,
  3 FAIL. No SKIP (TestVMMemoryStaysInsideItsCgroup logged that it skipped
  its 2048 and 4096 MiB guests, as the README says for a host this size).
  - TestVMWarmPool fails both times for memory (the documented small-host
    failure: available memory fell to about 270 MiB). TestVMWarmPoolRaces
    passed both times and alone.
  - **TestVMUsage failed deterministically: a test defect.** Its busy
    sample was usage round 1, which never reads disk (`usageDiskEvery =
    10`), so DiskBytes could not grow. Its failure message printed
    pointers instead of values.
  - **TestVMNetworkIsolation (pool on) failed on a race in the test**: the
    daemon's 2 s watcher restored the flushed rules before the test listed
    them ("rules emptied by hand are unchanged; nothing was tested"). It
    passed 3/3 alone.
- Off-host against versitygw 1.11.0 (POSIX backend, loopback), pool off and
  pool on: TestVMOffHost PASS, TestVMCallerSnapshots PASS,
  **TestVMKeyRotation failed deterministically: a test defect** (the
  rotation's pin, added by the two-phase delete, writes a `pin/` object
  under the snapshot's prefix, which the test counted as "moved"). The
  `internal/s3` live tests passed (36, run twice, including "1 won, 15
  refused" for `If-None-Match: *` with 16 racing writers).
  - TestVMOffHost logged "base image included: false" even when the
    restore had fetched it, because it asked after the restore: it
    under-reported one pool-on restore as 317 MiB at 4 MiB/s; the
    daemon's own log line said 1184 MiB at 15 MiB/s.
  - TestVMCallerSnapshots and TestVMKeyRotation left the received base
    image (842 MiB each, a new name every run) on the standing pool, and
    the off-host tests left the second daemon's empty cgroups.
- **No seccomp kills**: `journalctl -k | grep type=1326` empty across the
  whole session.
- Off-host, live for the first time: encryption at rest (0 of 21 fetched
  chunks hold the plaintext marker, none of the service's own files do,
  a chunk does not compress, unsigned GET 403); an incremental stop after
  4 MiB changed stored 7.4 to 7.6 MiB; fencing (two daemons resuming one
  run: one running copy, one hypervisor, the loser gets `ErrRemoteConflict`;
  each daemon won once, so both orders ran); loss of a host and byte-exact
  resume and fork on the other; a flipped bit and a deleted chunk refused
  with the pool left as it was and the run reported not whole; destroy
  plus collect to an empty bucket (101 objects, about 1.19 GB, in 230 ms).

### versitygw 1.11.0 behaviour, against what the code assumes

All within the code's assumptions:

- list-after-write is immediate (same process, same filesystem);
- `If-None-Match: *` on an existing key gives 412 and leaves the object;
  on a new key 200; other `If-None-Match` values give 501 (the code only
  sends `*`; `Probe` would read a 501 as "no conditional writes");
  `If-Match` on a missing key gives 404 where AWS gives 412 (not used);
- Last-Modified: HEAD (RFC 1123) and listing (`...Z`, **no fraction**,
  where AWS gives milliseconds) agree in 40 of 40 objects, and both are
  the backend file's mtime **truncated** to the second, never rounded.
  So `sameTime`'s window (truncate, then a second either way) is 2 to 3
  seconds wide here; two writes of one size inside it are not told
  apart, the documented cost;
- ETag is the MD5 of a single PUT's body, the same in HEAD, PUT and
  listing (the code does not use ETags);
- missing key: GET 404 NoSuchKey, HEAD 404, DELETE **204**; missing bucket
  404; `PUT` of an existing bucket 409 BucketAlreadyOwnedByYou (accepted);
  bad signature 403 (the error body echoes the StringToSign and
  CanonicalRequest, as AWS does); range past the end 416;
- extra listing fields (`ChecksumAlgorithm`, `ChecksumType`) are ignored;
- whole run: 1965×200, 700×204, 56×412, 53×404, 13×409, 3×403, 1×416,
  1×501, no 5xx;
- the POSIX backend leaves an empty lock file per object ever written in
  `.vgwlocks/` and never removes them (harmless).

### Figures (this host)

Warm create to first exec, medians: 14 ms (none), 311 to 314 ms
(allowlist), 406 to 417 ms (open). Cold create 4.7 to 4.9 s, resume 4.2 to
4.4 s, fork 4.2 s, snapshot of a running run about 0.2 s. Off-host (bucket
and pool on one eMMC): upload 40 to 51 MiB/s; restore 15 to 33 MiB/s, disk
bound; rotation pass about 40 ms.

### Fixed on this branch

| | Defect | Fix | Test (fails without the fix) |
|---|---|---|---|
| 1 | TestVMUsage's busy sample never read disk | `run.Manager.SampleUsageWithDisk`: one round that reads disk and does not move the ticker's cadence; the test samples with it every time it compares disk, and prints the values | `TestUsageSamplingCadenceAndParallelism` (forced round on a non-disk round, cadence unchanged, no-op with sampling off); TestVMUsage live (failed on `38ca4c0`, see above) |
| 2 | TestVMKeyRotation counted rotation's pin as moved | Compares the snapshot's own objects only: `pin/` and `condemned` left out (`snapshotObjects`, also used by TestVMOffHost) | TestVMKeyRotation live (failed on `38ca4c0`) |
| 3 | TestVMOffHost asked whether the base image was here after the restore | Asks before; and now fails if the restore left none | TestVMOffHost live |
| 4 | TestVMNetworkIsolation raced the 2 s watcher | Each ruleset is looked at right after its own damage, and counts as damaged when it lists differently then **or** when the daemon has logged since the damage began that it found that very ruleset changed (host table, or the run's namespace by name) and put it back. The daemon logs before it writes, so a listing already back always comes after the log line. A damage that did nothing gives neither and still fails; the wait for every ruleset to be back identical, and the checks after, are unchanged | Race, not reproducible on demand. Live: passed 3/3 pool on; the daemon never beat the look in these runs, so the "already put back" branch has not run live |
| 5 | Received base images and empty cgroups left behind | The daemon that received the base reclaims it at teardown after destroying its runs; `standingPoolAsFound` fails the test at its end if the standing pool differs from its start, and destroys this test's base if left; the first daemon's cgroup tree is removed | TestVMKeyRotation and TestVMCallerSnapshots live: pool after each off-host run is `sbx`, `sbx/base@v1` and `sbx/golden-guestd@v1` only |
| 6 | **KSM (security, existing gap).** `PR_SET_MEMORY_MERGE` (Linux 6.4) makes every mapping of a process mergeable and is inherited across fork and execve; a daemon started with it (systemd `MemoryKSM=yes`) would have made every guest's RAM mergeable host-wide, a cross-tenant timing side channel | The jail helper calls `prctl(PR_SET_MEMORY_MERGE, 0)` before the execve (`EINVAL` on a kernel without it is taken as cleared; any other error refuses the start). The hypervisor is started with `mergeable=off`. The daemon's seccomp filter refuses `prctl(PR_SET_MEMORY_MERGE)` (either value) and `madvise(MADV_MERGEABLE)` with `EPERM`, judged on the low 32 bits (both are an `int`); every other prctl and madvise is allowed | `TestJailClearsTheMemoryMergeFlag` (root-only: the test process sets the flag; a plain child inherits it, `1`, which is what makes the test mean something; the jailed one has `0` and both requests are refused). With the helper's clear removed it fails (`vm-unit-noclear`). `TestSeccompFilterOnBothArchitectures` (the argument checks, both architectures). `TestVMConfinement` live: the test runs as a daemon with the flag set (24 of its own mappings show `mg`), and no mapping of any hypervisor may show `mg` in `/proc/PID/smaps`; with the clear removed it fails with 92 mergeable mappings |

Kernel semantics, checked against v6.12's sources (`kernel/sys.c`,
`include/linux/sched/coredump.h`, `mm/ksm.c`): option 67, no capability
check, arguments 3 to 5 must be 0; `MMF_VM_MERGE_ANY` is in
`MMF_INIT_MASK`, so a new mm takes it from the parent's; clearing it
unmerges and clears `VM_MERGEABLE` on the process's mappings. Inheritance
across execve was not settled from the sources read and was **measured**:
on 6.12 a child exec'd by a process with the flag set has it. v6.12's
`/proc/PID/ksm_stat` has no field for the flag, hence `smaps` VmFlags in
the live test. Cloud Hypervisor v54.1 calls `madvise(MADV_MERGEABLE)` only
with `mergeable=on` and never calls `PR_SET_MEMORY_MERGE` (from its
`memory_manager.rs`; its tail was not read). Landlock is not involved (no
path); the prctl runs before the helper installs the filter.

### Live, on the fixed branch (same host)

- Root-only unit tests: PASS (266 PASS lines, no SKIP, no FAIL), including
  `TestJailClearsTheMemoryMergeFlag`.
- Pool off: TestVMUsage PASS (before: cpu 5.30 s, disk 827392; busy: cpu
  7.36 s, tx 778, disk 69991424), TestVMConfinement PASS. Pool on: both
  PASS.
- TestVMNetworkIsolation, pool on: PASS 3/3; rules back after 0.8 to
  1.4 s (deleted) and 2.0 to 2.1 s (emptied).
- Off-host against versitygw 1.11.0, pool off and pool on: TestVMOffHost,
  TestVMKeyRotation and TestVMCallerSnapshots PASS. Daemon-b won the
  concurrent resume both times, so the cold resume on it fetched no base
  image and is now reported so (317 MiB, base image included: false); the
  "true" path did not occur.
- `type=1326`: 0 lines. After the runs the pool holds only `sbx`,
  `sbx/base@v1` and `sbx/golden-guestd@v1`; no off-host pool, cgroup,
  hypervisor process, netns or nft table left.

**Still open.** A whole green suite on a host with memory enough for the
warm-pool tests; the 16 GB bare-metal figures (memory overhead of the 2048
and 4096 MiB guests, VM density, warm and cold timings); off-host against
a remote S3 service over a real network, and one that rounds Last-Modified
or carries milliseconds (AWS S3, MinIO); `--remote-local drop`, still
refused. `install-host.sh` does not warn about a unit with `MemoryKSM=yes`. The
jail helper clears the flag for every hypervisor and the daemon clears
its own at start (found by review: the daemon holds tenants' data in
the clear while encrypting and decrypting it), so teploy's own
processes are safe either way; the warning would still catch the case
for every other process the operator runs under the same unit.
## 2026-11-21 — access, daemon side (phase 4, task 4a: A1–A4)

What landed: the `accessgrant` package (grant format, strict verification,
scope table), the run's access state (epoch, ports, revoke with write-through
to the remote record, the move rule on resume, fork, access bytes), guest
protocol version 2 `connect`, and the access listener with `connect` on the
VM driver. Off unless `--access-addr` is set; with it off the API, run JSON,
registry file and remote record are unchanged (`TestAccessOffChangesNothing`,
`TestAccessRoutesAbsentWhenOff`). **Nothing here has run live**: the
vmintegration tests in `vm_access_integration_test.go` (none-tier reachability
with host network state unchanged, the daemon's tables deleted, streams ending
at expiry/revoke/stop, guest-initiated vsock refused) have not been run on a
KVM host. The Linux-only unix-socket test (`unix_linux_test.go`) runs in CI,
not on the builder's machine.

Not built (remaining 4a): **A5** `connect` on the Docker driver (held netns
descriptor from `SandboxKey`, inode check against the daemon's own netns,
locked-thread dial; the Docker-host overlay rules are documented in the README
but untested): Docker answers 501 `unsupported-driver`. **A6** `session`
(guestd PTY/exec/subsystem, root on VM; `docker exec -u` on Docker): the route
does not exist; the stream caps already reserve 4 session slots per run. No
HTTP/1.1 `Upgrade: teploy-stream` fallback (HTTP/1.1 with full duplex is
accepted instead).

Limits and choices a reviewer should check:

1. **Move rule is stricter than the design's letter.** A resume of a run read
   from its remote record sets `epoch = max(epoch+1, accessEpoch+1, now)`, not
   `max(record, passed, now)`: with the latter a grant minted at the record's
   epoch survives a move made within the same second (or with the clock behind).
   A local resume takes `max(epoch, accessEpoch)`. `TestResumeEpochRules`.
2. **Write-through needs the run's exclusivity** for the remote write (≤ 30 s
   timeout): execs, writes, stops and lease acquires on that run get 409 `busy`
   for its duration, and a revoke while a stop/resume/fork/delete holds the run
   fails with 502 (epoch raised, streams closed) and must be repeated. A revoke
   during a stop whose payload was read before the bump can leave the old epoch
   in the stopped record; the next move still revokes (rule 1), clock skew aside.
3. **Write-through rewrites another daemon's stopped record** (a stopped run
   adopted from elsewhere and revoked here): the new generation is this
   daemon's, with the same snapshot and key. Other daemons adopt it like any
   newer stop of the same snapshot.
4. **A run with no remote record** (never stopped with remote storage) has
   nothing to write through; its first stop carries the epoch.
5. **Same-host state rollback** restores the old epoch and the old grants until
   they expire (design residual, README).
6. **Grant verification tries every key** (≤ 8) before parsing anything, then
   requires the payload's `kid` to name the key that verified. Cost per invalid
   grant ≤ 8 Ed25519 verifications; the listener is mTLS-only.
7. **Owner proofs** (`own`) are refused by the daemon for `connect` (the scope
   table says "accepted nowhere"); the design's table did not name the daemon
   row for them.
8. **One run per connection is enforced** by the daemon (421 `wrong-connection`),
   beyond the design's per-edge connection cap, so the HTTP/2 connection window
   is only ever shared by one run's streams. Lookups do not bind a connection.
9. **HTTP/2 windows**: 256 KiB per stream; the connection window is 4 MiB − 1
   (Go's maximum), not stream window × 64 as the design wrote. With 16 stalled
   streams a connection is full, which stalls only that run (rule 8).
   `TestStalledRunDoesNotStallAnother` shows a healthy run unaffected by eight
   stalled streams of another; it would not catch a regression in the edge's
   per-run connections, which is the edge's (4b).
10. **Memory sizing**: refuse to start when `streamsMax × 320 KiB` exceeds
    `--access-memory-mb` (default host memory / 10, 1024 MiB where unreadable).
    The budget fraction is a choice, not measured. Streams counted by Go's
    HTTP/2 server before the handler admits them (up to 64 per connection ×
    connections) are bounded by the per-edge connection cap, not by this check.
11. **Guest protocol frames**: v2 reads (`connect`'s answer) are ≤ 64 KiB,
    allocated as bytes arrive, under a 5 s deadline. **Pre-existing, unchanged**:
    the v1 `readFrame` allocates the declared size (≤ 1 MiB) on a five-byte
    header, so a malicious guest holds ≤ 1 MiB per in-flight v1 call
    (exec/read/write), as before.
12. **Half-close**: the end of the edge's request body is passed to the guest as
    a vsock `CloseWrite` on the hypervisor's unix socket; whether Cloud
    Hypervisor turns that into a vsock shutdown is **not verified live**.
    A guest closing its side ends the stream (no reverse half-close).
13. **guestd linger**: once one direction of a connect ends, the other must move
    a byte every 2 minutes or the stream closes (so a guest server that keeps a
    half-closed socket gives its slot back). guestd caps open connects at 128.
14. **Rates** are token buckets per run (granted, anonymous) and per daemon,
    burst 0.1 s; `TestAnonymousRate` checks ±15%/−30% at 8 Mbit/s. Daemon CPU per
    Gbit is not measured (design: 4b).
15. **Metering**: access bytes are flushed to the run every 10 s and when a
    stream ends; a destroy loses the last partial interval of streams still
    open. They are counters, not a ledger.
16. **Unix socket peer check** is Linux only; on other systems `unix:` is refused
    at start. The default `--access-unix-uid` is the daemon's own uid.
17. **Docker-host overlay rules** (S11): documented example only, not installed
    and not tested (A5).
18. **Revert proofs**: every behaviour test of this change was run with its
    change reverted and failed; the edge-name check is two layers (handshake
    callback and post-handshake) and fails only with both reverted.
19. **Fuzzing**: `FuzzVerify` ran 10 minutes (10.2 M executions, no failure);
    80 corpus entries are committed under `accessgrant/testdata/fuzz`.

## 2026-11-22 — access, part 1: two independent reviews, and what they changed

Two reviewers who did not write the slice went through it (the grant
crypto and protocol for one, the daemon surface and lifecycle for the
other) before merge. The grant math, the strict decode, the epoch
lifecycle, the off-state purity and the VM connect path held under
every attack; the fixes below are what they found.

- **A cnf-bound grant was a bearer token at the daemon's connect.**
  `UseDaemonConnect` accepted a grant whose `cnf` binds it to an SSH
  key nobody checks on that path — on the unix listener there is no key
  authentication at all, so a stolen cnf-bound port-forward grant was
  enough. The scope table now refuses `cnf` at the daemon's connect
  (the package comment and the code agree again); an edge relaying a
  user's `-L` forward is to obtain its own grant without `cnf` — the
  shape A6 will build on, not a bearer-for-someone-else.
- **A cross-daemon revoke was lost on the run's birth host.** The
  reconcile branch for "our stop, written again by another daemon"
  kept the local payload and never read the record's access fields, so
  a revoke written into the stopped record by the host that adopted the
  run did not travel: the birth host resumed with the old epoch and its
  next stop wrote the old one back. The branch now takes the record's
  epoch and ports when the record is ahead. Narrow crash window; the
  off-host fakes get a test for it with the next pass.
- **The denylist now bites per stream, not per handshake**: a connection
  admitted before its edge was denylisted has every further stream
  refused until it reconnects.
- **`--access-addr` refuses the foot-gun binds**: an unspecified
  address (every interface — a copy-paste away from the internet) is
  refused at start, and the three rate flags refuse their negatives.
- **A stream for a run that is not here no longer binds its
  connection** (the 404 came after the bind, leaving a wrong-connection
  421 for every real run that followed).
- **The unix socket is 0660 from its first byte** (a umask guard around
  the listen), a second daemon at the same path is refused instead of
  blindly stealing the socket, a failed start unlinks it, and close
  removes it.
- **A run's rate buckets persist across stream churn** (open, blast,
  close, reopen no longer re-earns the burst each cycle) and age out
  after a quiet minute.
- **A dead access listener is visible**: its streams are closed at
  once, and the config view says `listenerDown` with `enabled: false`
  so a probe notices instead of a page at grant expiry.
- **The fuzz corpus carries real seeds** for every refusal class, not
  minimized noise.

Deployment rule, same as rotation's and the two-phase delete's: **every
daemon sharing a bucket must run a version that knows the access
fields.** An older daemon resuming and stopping such a run drops them
from its next record, and an epoch pushed past `now` by repeated
same-second revokes can come back short until the next move or revoke.

## 2026-11-23 — access and usage: the first live run of the access suite

The merged access daemon (PR #9) and the usage fixes (PR #10) ran live
for the first time (nested arm64, the rebuilt golden with the protocol
v2 agent; 38 tests passed, three failed, one of them the source-needing
CI test run outside a checkout). Two real findings, both fixed:

- **A completed response's stream ended in a reset.** The stream's
  close callback set the response's WRITE deadline as well as its read
  one, and the handler called it before returning — killing the final
  frames of a response whose body had already arrived whole (the client
  saw INTERNAL_ERROR after every byte, on a clean transfer). The
  handler now stands the write deadline down once its own copy loop is
  done; an external close (revoke, stop, expiry) still sets both.
- **Per-run disk usage lagged a transaction group.** The guest's
  `sync` flushes to the volume, the data IS on the ZFS dataset (a
  mid-run snapshot carries it; a direct read back through the guest
  round-trips), but `used` does not include the current txg's dirty
  data, so a sample taken in the same ~5 s window reads the old
  figure. The slow x86-64 host the suite last passed on hid this — a
  txg always synced between the write and the sample there. The test
  now samples until the accounting settles (bounded); the semantics
  are ZFS's, not a defect: per-run disk is current only as of the last
  transaction group.

The source-needing `TestCIStepsThatPipeFailWithTheirTests` failed only
because the binary ran outside a checkout; the live pattern now used
excludes it.

## 2026-11-23 — the merged access and usage fixes: whole suite green, pool off and on

With PR #11's three fixes (the clean stream end, the transaction-group
wait, the counter-normalized host-state check), the whole live suite
ran green on the merged `main` (`d5558cb`) twice over: pool off
(23/23) and pool on with the small warm pool this 8 GiB nested host
carries (23/23). This closes the loop the previous entry opened: the
access daemon, the usage sampling and the none-tier reachability have
now all run against a real hypervisor, and the register's open item
from the access review — "nothing has run live" — is no longer true.
The pool-on gap that remained from 2026-11-17/18 (the three S3 tests
on a starved host) is closed with them.

Still open, unchanged: x86-64 and bare metal beyond the one
below-spec laptop pass (the rented box's job); a second physical
host; `SBX_TEST_RUNTIME=runsc`; and the A5/A6 follow-ons.

## 2026-11-24 — G2 code review follow-ups (access, PR #9)

The independent G2 code review of PR #9 (the daemon side of access) was
only partly addressed before that PR merged. Its reproduction tests,
which logged results instead of asserting, were re-run against `main`
(`a8bb0e7`); everything below that was still present is now fixed, each
with an asserting regression test that was run with its fix reverted and
failed. **Nothing here has run live** (fakes, the in-memory S3 and real
TLS sockets on the builder's machine only).

Fixed in PR #9's own fix round (the 2026-11-22 entry above, not repeated
here): the cnf-bound grant as a bearer token at the daemon's connect;
the cross-daemon revoke lost on a run's birth host (the "our stop,
written again" reconcile branch); the denylist checked per stream (the
first half of S-2); the foot-gun binds; a 404 stream binding its
connection; the unix socket's mode, double start and cleanup; rate
buckets re-earned by churn; a dead listener made visible; real fuzz
seeds.

Fixed here:

- **B-1, adopting a record lowered the local epoch.** A daemon holding a
  stale view of a stopped run revoked it (each write-through failed:
  another daemon had moved the run on), then synced; the adopt replaced
  its run with the record's, epoch and all, so the epoch went back down
  and the next resume landed below the revokes — a grant minted at the
  last revoked epoch passed. Every path that updates a stopped run from a
  newer record (adopt and takeover through `replaceHeld`, and the "stop
  written again" branch) now keeps `max(local, record)`, under the lock
  (so a revoke racing the adopt, which reads the record outside it, is
  kept too), and writes a local epoch found ahead into the record. The
  ports are the record's on every such path (the newer configuration by
  generation; a local port change that did not reach the record was
  answered with an error, below). Tests: `TestAdoptingANewerRecordNeverLowersTheEpoch`,
  `TestAStopWrittenAgainKeepsTheHigherEpochAndTheRecordsPorts`
  (`internal/vm`).
- **S-1, a held resume never wrote its raised epoch.** `claimHeld`
  returns early for a run this daemon already holds (a takeover), so the
  running record kept the pre-move epoch; a second takeover from that
  record landed on the first one's epoch, and the first host's grants
  passed on the third. A resume whose move changed the epoch of a held
  run now writes it through before boot (and gives the run back if it
  cannot). Test: `TestTakeoverResumeWritesTheRaisedEpoch`.
- **S-2 remainder, expired certificates and removed keys.** A connection
  now closes at the earliest `notAfter` of its verified chain, and a
  stream asked for on an expired connection is 403 `edge-expired` (the
  guard behind the timer). Removing an issuer key, or replacing it under
  its kid, closes the streams it admitted; a key `notAfter` brought
  forward ends them by then; a stream admitted with a key removed between
  verification and the count is refused after the count. Tests:
  `TestAConnectionEndsWhenItsCertificateExpires`,
  `TestAStreamOnAnExpiredConnectionIsRefused`,
  `TestIssuerKeyChangesEndTheirStreams` (`internal/access`).
- **S-3, anonymous stalls starved the owner.** Sixteen anonymous streams
  whose guest does not read filled the connection's 4 MiB window, and
  the owner's granted stream on the same connection stalled. A
  connection now binds to (run, anonymous or granted); the other kind on
  it is 421 `wrong-connection` (wire contract updated: edges open one
  connection per run and kind). An anonymous stream with bytes waiting,
  either way, that moves none for `Limits.AnonStall` (30 s) is closed; an
  idle one is not. Test: `TestAnonymousStallsDoNotStarveTheOwner` (the
  421, the owner's upload on its own connection, the stalled streams
  closed, the next visitor served, an idle stream left alone).
- **S-4, a revoke answered 200 with the registry unwritten.** `persist`
  logged and moved on. A revoke or port change now writes the registry
  with `persistNow`, and a failure answers 500 `access-not-persisted`
  with the epoch (the change still holds in memory and the reaper retries
  the write). Tests: `TestAccessChangeFailsLoudlyWhenTheRegistryIsNotWritten`
  (`internal/run`), `TestRevokeNotPersistedAnswers500WithTheEpoch`
  (`internal/server`).
- **S-5, guest text echoed.** A 34 KB error from the guest agent was the
  502 `guest-agent` problem's detail. The detail is fixed text now; the
  guest's text is logged, cut to 256 bytes. Test:
  `TestGuestErrorTextIsNotEchoed`.
- **S-7, port changes were not written through.** Publishing,
  unpublishing and removing a port changed only the local run; another
  daemon resuming the run from its record served the old ports. They now
  write through like a revoke (502 `access-write-through` when they
  cannot; the change holds here). Tests: `TestPortChangesAreWrittenThrough`
  (`internal/vm`), `TestPortChangeWriteThroughFailureAnswers502`
  (`internal/server`).
- **Grant nits.** `"cnf":""`, `"own":false`, `"ref":""` and `"org":""`
  are malformed (absent is the one spelling of "not set"); the SSH
  forward row refuses any grant with an `http:` scope (`[http:*, tcp:*]`
  + cnf was permitted); `NewKeyring` refuses one public key under two
  kids (the first verified every grant naming the second, so the
  second's notAfter or removal meant nothing — `PUT /v1/access/config`
  now refuses such a configuration); a resume's `accessEpoch` must be at
  most 2^53-1 - 2^20, since an epoch at the maximum can never be raised
  again. Tests: `TestVerifyRefuses`, `TestNewKeyringRefuses`,
  `TestPermitsTable` (`accessgrant`), `TestResumeRefusesAnEpochNearTheMaximum`
  (`internal/run`). `FuzzVerify` ran 60 s after the change (2.1 M
  executions, no failure) with a seed for the empty claims.

Limits and choices a reviewer should check:

1. **The anonymous stall timeout (30 s) is a choice, not measured.** It
   counts only time with a write to the guest blocked (after the review
   round below), so long-polls, quiet websockets and paused visitors are
   untouched. A guest that trickle-reads (one write per < 30 s) is not
   caught; it holds at most 256 KiB per stream, 4 MiB for the run's
   anonymous connection — that run's visitors only. Granted streams are
   not watched: each grant has its own connection.
2. **Writing a local epoch found ahead during a reconcile is best
   effort** (logged when it fails). Until it lands, a resume on another
   daemon goes by the record and by the caller's `accessEpoch` — which
   is what the revoke's 502 told the caller to keep.
3. **A port change that fails its write-through holds locally**, like a
   revoke, and is marked as changed here (`accessDirty`, persisted); a
   later reconcile with a newer record merges it failing closed (review
   round below) instead of taking the record's.
4. **The registry file carries access state only for stopped runs**
   (unchanged): a running run's epoch is not in it, and a run lost by a
   restart comes back through its remote record and the move rule, or
   not at all.
5. **Edges must open one connection per run and kind** (anonymous, or
   one per grant `jti`, after the review round below) — the 4b edge has
   to be built that way; an edge mixing them gets 421s, not stalls.
6. **The key-removal race** (a key removed between verification and the
   stream's count) is closed by a recheck after the count; there is no
   deterministic test for the interleaving itself, only for the closes.
7. **The unix socket's peers have no expiry**: credentials there are
   checked at accept, as before.

Deferred: nothing of the list above. Review items not in this
follow-up's list (S-6 and the review's notes) were not re-run here.

### Review round on PR #13 (2026-11-25)

Two independent reviews of this PR (both: not yet) found the following;
each reproduction is now an asserting regression test, run with its fix
reverted and failing. Invariants held: a run's epoch never goes down on
any host, and once any host answers a revoke with E no host admits a
grant below E; once a user gets a success answer making a port private,
no host serves it public. Nothing relies on clocks. Not run live.

- **A1 (blocker, a regression this PR introduced):** the "stop written
  again" branch took the record's ports unconditionally, so an unpublish
  answered 502 ("holds on this daemon") was undone by the next sync.
  Ports changed here since the last record this daemon wrote or took
  (`accessDirty`, persisted, never in the record) are now merged with a
  newer record failing closed — this daemon's entries, each public only
  if the record has it public too — and written through; same rule on
  adopt/takeover (`replaceHeld`). A run not changed here takes the
  record's ports (a stale copy does not unpublish ports published
  elsewhere). `TestAnUnpublishThatFailedItsWriteIsNotUndoneBySync`.
- **A2:** a resume of a held run wrote its epoch only when it raised it;
  after a takeover resume whose write and give-back both failed, the
  retry raised nothing (the move was spent) and booted on the old
  record. Every held resume now writes its access state before boot (a
  no-op when in step). `TestAHeldResumeRetryWritesTheEpoch`.
- **A3:** share-link holders are granted streams; they shared the
  owner's connection and were never stall-checked. A connection now
  binds to (run, anonymous | one grant's `jti`): a share link's holders
  get one connection, the owner's grant another (421 otherwise). (The
  first version of this raised `--access-edge-conns` to four per run,
  which the third round below found exploitable and replaced.)
  `TestShareLinkHoldersDoNotStarveTheOwner`.
- **V1/V2:** on a run's first publish (no record yet) a revoke or port
  change skipped its write-through and answered 200, then the publish
  wrote generation 1 from its earlier payload — a private port served
  public, revokes lost, on the next host. Such a change now answers 502
  (the run is busy), and the publish compares the live access state with
  its payload after the record lands and writes the difference
  (`publishAccessSince`; a failure fails the publish, whose retry writes
  from the live run). This covers publishPending retries, republish
  from generation 0 and registries from before remote storage.
  `TestAPortChangeDuringTheFirstPublishReachesTheRecord`,
  `TestARevokeDuringTheFirstPublishReachesTheRecord`.
- **V3:** a running copy superseded by a takeover kept admitting grants
  below the new holder's revoked epoch and serving ports it made
  private. On learning of the takeover the daemon closes the copy's
  streams (`superseded`), and `AccessAdmit`/`DialPort` refuse it.
  **Window:** until this daemon sees the takeover (its next sync, or a
  request that reads the run's record) the copy serves the access state
  it had — documented in the README and the wire contract.
  `TestASupersededRunningCopyTakesNoStreams`.
- **Epoch floors:** a run dropped here (resumed elsewhere) while its
  epoch was ahead of its record (a revoke whose write failed) keeps that
  epoch as a persisted floor; adopting the run here again applies it and
  writes it through. Floors are kept only in that case and are consumed
  on re-adopt; one for a run that never comes back stays in the registry
  file (a few bytes). `TestARunDroppedAheadOfItsRecordComesBackNoLower`.
- **Nits:** the handler ends a stream with `closeBy` (never later than
  an end a configuration change set meanwhile; `closeBy` is unit-tested,
  the race in the handler itself has no deterministic test);
  certificate expiry is also checked against the wall clock per read
  and by the sweep (`TestAStreamEndsOnItsFirstReadAfterTheCertificateExpired`,
  `TestTheSweepClosesStreamsPastTheirCertificate`); only a blocked write
  to the guest is a stall (`TestAVisitorThatDoesNotReadIsNotStalled`);
  Serve unregisters its configuration watch
  (`TestServeUnregistersItsConfigurationWatch`); denylisting an edge
  closes its open streams (`TestDenylistingAnEdgeEndsItsStreams`); the
  wire contract says a write-through holds the run up to 30 s.

### Third review round on PR #13 (2026-11-25)

A broad reviewer and an invariant reviewer re-read the PR at `8806bb3`.
Each reproduction below is an asserting regression test, and each one
fails when its fix is reverted. Every earlier fix and test is kept.
Nothing here has run live.

- **Blocker: per-grant connections could use up the edge's connection
  cap.** Binding a connection per grant (`jti`) meant one tenant could
  mint a few grants for its own run and open one stream per grant. The
  per-edge cap (then 4 × streamsMax/64) counted all of them, so once it
  filled, other runs could not be reached through that edge.
  - **Fix: the reviewer's option (b).** A connection counts against the
    edge's cap only until its first stream binds it to a run. From then
    on it counts against that run's connections from that edge, capped
    at 8 (`DefaultConnsPerRun`). Past the cap, the stream answers 429
    `run-connections` with `Connection: close`, so Go's HTTP/2 server
    sends GOAWAY and the unused connection gives its edge slot back.
  - The edge cap now only bounds connections that do not serve a run
    yet. The edge opens those itself, and a tenant cannot hold one open,
    because a refused one closes. Its default goes back to twice the
    runs the stream cap allows for.
  - **Why (b) over (a)**, which was: bind per (run, anonymous or
    granted) and stall-check non-owner granted streams.
    - The daemon cannot tell an owner's grant from a share link: both
      are ordinary grants, and the `own` proof never reaches the
      daemon.
    - So (a) would mean stall-checking every granted stream. That cuts
      an owner's own long transfer to a guest that pauses, and lets
      share-link holders share the owner's connection window until the
      check fires, so `TestShareLinkHoldersDoNotStarveTheOwner` could
      not pass.
    - (b) keeps that isolation and needs no clock. No run's
      connections, and no set of grants, can take another run's
      capacity, because the capacity is per run.
  - **Limits of the fix.**
    - At most 8 grants per run may hold connections from one edge at
      once (the anonymous connection is one of the 8). A ninth needs an
      idle connection closed first.
    - The total number of connections an edge may hold is now
      8 × (runs it serves) + its unbound cap. Memory is still bounded
      by the stream caps (each stream's 256 KiB window); a connection
      holds no buffer of its own beyond its streams'.
  - Tests: `TestPerGrantConnectionsDoNotExhaustTheEdgeCap` (the
    reviewer's repro), `TestARunsConnectionsFromAnEdgeAreCapped`, and
    `TestShareLinkHoldersDoNotStarveTheOwner` (still passes).
- **V4: a lost answer on the first record write lost later changes.**
  1. Generation 1 of the record landed, but its answer was lost. The
     run was left failed, with `remoteGen` 0 and nobody holding it.
  2. A port change or revoke then answered 200 with no write to the
     record.
  3. The upkeep's retry adopted the stale generation 1 as its own.
  4. `publishAccessSince` compared the live state with the retry's own
     payload instead of with the record that landed. They matched, so
     nothing was written.
  - Fix: every publish with access on now ends with `writeAccessHeld`,
    which reads the newest record and writes only what differs.
  - Across a crash: the change is in the registry file before it is
    answered. If the daemon restarts, it publishes the change at its
    next upkeep, or merges it if another daemon has written the record
    since. The wire contract now says this instead of the earlier,
    narrower promise.
  - Tests: `TestAPortChangeAfterALostFirstRecordAnswerReachesTheRecord`,
    `TestARevokeAfterALostFirstRecordAnswerReachesTheRecord`.
- **V5: losing the record revived a taken-over running copy.** When a
  sync found the takeover's records missing (or at an older
  generation), it cleared the superseded mark. The copy then admitted
  streams again at its old epoch and served ports the new holder had
  made private.
  - Fix: missing or older records no longer clear the mark. Only the
    `recovers` case (the copy's own newest record) clears it.
  - Test: `TestASupersededCopyStaysSupersededWhenTheRecordsAreLost`.
- **Denylist race.** An edge denylisted between the stream's first
  check and its count could keep its stream. Denied is now rechecked
  after the count, the same way the issuer-key recheck works.
  `TestAnEdgeDenylistedBeforeTheCountIsRefused` injects the change
  through the grant clock, which is read after the first check.
- **Epoch floors are now pruned.**
  - A floor is pruned only when the run's record says destroyed: when a
    sync or lookup sees that record, and on every sync for each floor
    still held. A run ID is never reused, so a destroyed run cannot
    come back.
  - A record that is merely missing does not prune a floor, because the
    run may still come back.
  - Test: `TestAnEpochFloorIsPrunedOnlyWhenTheRunIsDestroyed`.
- **A stale `accessDirty` flag could undo another host's publish.**
  When a record this daemon writes carries the run's current ports (a
  resume's claim, or giving the run back after a failed boot), the
  "changed only here" flag is now cleared. Without that, the next sync
  failed closed against a port another daemon had published, and wrote
  the loss through.
  `TestAPortPublishedElsewhereSurvivesAStaleLocalChange` fails without
  the fix in both places.
- **Edge window.** The wire contract now requires the edge's HTTP/2
  window for one daemon connection to cover 16 streams × the edge's
  per-stream window. Anonymous stalls are detected only toward the
  guest, so a visitor that does not read holds the edge's window, not
  the daemon's.
- **Behaviour change, kept on purpose: a revoke or port change on a
  busy run that has never been published now answers 502 instead of
  200.** "Busy" here means a stop is writing the run's first record.
  The change still holds on this daemon, and the publish writes it to
  the record. The 502 tells the caller it is not known to be in remote
  storage yet, and to repeat it; repeating is harmless. Answering 200
  would claim a durability that does not exist yet.
