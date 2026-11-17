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
now) passes with the pool on (`SBX_VM_WARM=1x512=2,1x1024=1`).

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
  window is the claim itself.
- **One caller can keep the pool empty.** Every create that takes a
  pool VM costs the host a boot, whether the run is kept, destroyed at
  once or abandoned mid-claim (a claim whose caller gives up destroys
  the VM). There is no fairness between callers: the others then wait
  for a cold boot, as with no pool.
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
