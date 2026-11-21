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
| `POST /v1/runs/{id}/resume` | `{ttlSec?, takeover?}` → the same run, same `id`, `state: "running"`, new deadline (`takeover`: see Off-host storage) |
| `POST /v1/runs/{id}/fork` | `{ttlSec?, labels?, onExpire?}` → 201, a new run started from this one's filesystem and settings, with `forkedFrom` |
| `GET /v1/capacity` | `{server, driver, runtime, cpus, memoryMb, runs: {running, stopped}, allocated: {cpus, memoryMb}, warmPool?}` — the host's size and the sum of running runs' limits (and of the VM driver's warm pool, when it has one) |
| `GET /v1/remote/snapshots` | Only with remote storage: the caller snapshots in the bucket → `{snapshots: [{id, run?, createdAt, storedBytes}]}` — membership is the durability probe for a snapshot whose upload failed and is retried |
| `POST /v1/remote/sync`, `POST /v1/remote/collect`, `POST /v1/remote/rotate`, `POST /v1/remote/scrub` | Only with remote storage (400 without): look for runs stopped on other daemons now → `{remote, changed}`; garbage-collect the bucket now → 204; re-wrap the bucket's keys under the current master → `{manifestsRewrapped, recordsRewrapped, …, previousKeyNeeded, previousKeyNeededFor: [...]}`; check now that every stopped run this daemon reports durable is whole in the bucket → `{checked, notWhole, unreachable}` |
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
after a daemon restart, fork of a running run, destroy, and the three
network tiers with `egressAllow` (see Guest networking below). With
remote storage configured a stopped run also resumes on another host
(see Off-host storage below).

What is refused with a 400 rather than faked:

- `warm` (no warm repo cache);
- `limits.pids` (a VM is bounded by its memory and CPUs; the task limit
  on its hypervisor is the driver's, not the caller's);
- an `image` that is neither `golden` nor a snapshot this driver took.

Also not built yet: nested virtualisation inside a run, and memory
reclaim policy. A warm pool of pre-booted VMs is there, off by default
(see Warm pool below).

Host setup: `sudo scripts/install-host.sh [POOL]` prepares a host and can
be run again at any time; a second run changes nothing. It installs the
udev rule described below, makes sure `/dev/kvm` is openable by a group
rather than by root alone, checks the VM UID range (against accounts and
against `/etc/subuid` and `/etc/subgid`) and the cgroup controllers, sets
`volmode=dev` on the pool, checks what guest networking needs (the `ip`,
`tc`, `nft` and `conntrack` commands, `/dev/net/tun`, and a trial network
namespace with a veth link, a routing rule that matches a port, an
nftables ruleset with a connection limit and a rate-limited device in
it), turns on IPv4 forwarding and makes that permanent, says whether the
hypervisor binary is statically linked, checks that the kernel has
seccomp filters and that a tmpfs can be mounted for a VM's sockets, and
reports whether the kernel has Landlock. The pool, the kernel image and the golden snapshot
are yours to provide: build the golden with `scripts/build-golden.sh`
from a volume holding a bootable systemd root filesystem.

Host requirements, checked at start; the daemon refuses to start and
names everything that is missing, with the command that fixes it where
there is one:

- root, on x86-64 or arm64, on Linux 5.13 or newer with cgroup v2,
  seccomp filters and Landlock (`landlock` in
  `/sys/kernel/security/lsm`). There is no mode that runs without
  Landlock or without the daemon's seccomp filter: a host that lacks
  either is refused, not warned. The daemon must be able to mount (it
  gives every VM a small tmpfs for its sockets);
- `/dev/kvm`, with a group (or everyone) allowed to open it;
- the `cloud-hypervisor` binary (`--vm-hypervisor`) and an uncompressed
  guest kernel (`--vm-kernel`), both readable by any user. Use the
  statically linked build (the upstream release has one): a dynamically
  linked binary works, but its jail then also holds the host's library
  directories, read-only, and the daemon says so at start;
- a ZFS pool (`--vm-pool`) with `volmode=dev` set on it, and a golden
  snapshot in it (`--vm-golden`);
- udev not probing ZFS volumes for filesystems (below);
- 4096 UIDs no account has and no range in `/etc/subuid` or
  `/etc/subgid` hands out, from `--vm-uid-base` (default 1879048192);
- a cgroup the daemon may create groups in, with the `cpu`, `io`,
  `memory` and `pids` controllers (`--vm-cgroup`, default
  `/sys/fs/cgroup/teploy-sandbox-vm`);
- a directory for device nodes on a filesystem that allows them
  (`--vm-dev-dir`, default `/dev/teploy-sandbox`; `/run` is `nodev`);
- for guest networking: the `ip` and `tc` (iproute2), `nft` (nftables)
  and `conntrack` (conntrack-tools) commands, `/dev/net/tun`, network
  namespaces with veth links, routing rules that match a port (Linux
  4.17 or newer), nftables inside a namespace with `ct count` (the
  `nft_connlimit` module) and a `tbf` queue on a device (`sch_tbf`,
  which some distributions ship in a `linux-modules-extra` package); the
  daemon makes and removes a trial namespace at start and refuses a host
  where any of it fails, `net.ipv4.ip_forward=1`, an IPv4 subnet nothing else on the host uses
  (`--vm-subnet`, default `10.209.0.0/16`), and an IPv4 DNS resolver
  that is not on the host itself (`--vm-dns`, default: the host's own
  resolvers). These are required whatever tiers you use.

`GET /v1/capacity` reports `driver` and `nestedVirt`, and `warmPool`
when one is configured (below).

`--vm-max-runs N` (`SBX_VM_MAX_RUNS`, default 0: no limit) caps the VMs
runs may have at once; a create beyond it gets a 503 (`at-capacity`).
It is also the number the host's sizing is checked against (Host sizing
below).

### Warm pool

`--vm-warm 2x2048=3,4x8192=1` (`SBX_VM_WARM`; default empty, no pool)
keeps that many VMs of each size booted: `CPUSxMEMORY=COUNT`, whole
virtual CPUs and the guest's MiB. A create on `image: "golden"` whose CPU
limit rounds up to CPUS and whose memory limit is MEMORY exactly takes
the oldest waiting VM of that size instead of booting one; any other
create, a create that finds the size empty, and every resume and fork
(they boot their own disk) boots as before.

- **What a pool VM is.** A VM booted exactly as a run's VM is: a volume
  cloned from the golden snapshot, the same jail, its own UID, both
  seccomp filters, Landlock, the cgroup limits of its size, its own
  socket filesystem. It has no network device, no environment and no
  run data, and nothing has been run in its guest: the daemon has only
  asked its agent whether it is up. Nobody else can reach it.
- **What a claim does.** Everything that is the run's happens when a
  create takes the VM, and is what happens to a VM booted for a run:
  the run's network namespace and tier (made before, with the proxy's
  listener, as always), the tap handed to the running VM, and in the
  guest the PCI rescan, the address, routes and resolvers, and the
  clock. A claim that fails destroys the VM.
- **Once.** A VM leaves the pool once, under the pool's lock, to one
  run or to be destroyed, and never comes back: a VM a run has had,
  however briefly, is never another run's. The run's container ID is
  the VM's own name (its volume, cgroup, device node and runtime dir
  already carry it, and none of them is renamed under a running
  hypervisor); the run's network place keeps the run's name.
- **What a run can tell.** The same PCI devices in the same slots, the
  same interface name and the same kernel command line as a VM booted
  for it (checked live). What differs is how long the guest has been
  up, and whatever its guest logged while it waited.
- **Refill.** In the background once a claim is done (not during it:
  a boot takes the CPU the claim needs), and every two seconds, one
  boot per short size in turn. At most `--vm-warm-boots`
  (default 2) boots are under way when the pool starts one, counting
  creates that are booting their own VM, so a burst of creates is not
  followed by a burst of pool boots. A boot starts only while the host's
  `MemAvailable`, less what the boots under way may still take, covers
  the new VM's cgroup limit plus `--vm-warm-headroom-mb` (default 1024);
  the pool logs once when it holds back. A failed boot is retried after
  a pause that doubles up to a minute. A pool VM that exits while it
  waits is removed and replaced, after the same kind of pause (it
  doubles with every VM that dies waiting, until a create takes one):
  a pool whose VMs boot and then die is not a boot loop.
- **Restart and shutdown.** Pool VMs are VMs of the daemon's identity
  like any other, so the startup sweep finds and removes them with
  everything else a previous life left; the pool starts filling only
  after the sweep. A daemon that shuts down removes its pool. The reaper
  never sees a pool VM: it is in no registry.
- **Capacity.** `GET /v1/capacity` gains `warmPool: {sizes: [{cpus,
  memoryMb, target, ready, booting}]}`, and the VMs the pool holds,
  ready or booting, are counted in `allocated`.

Measured on the nested arm64 test host (Cloud Hypervisor v54.1, a 1 vCPU
512 MiB guest; create through the manager until the run's first exec
has answered, ten of each): from the pool, a median of 34 ms on `none`,
369 ms on `allowlist` and 379 ms on `open` (worst 108, 433 and 460 ms);
a cold boot took 6 to 15 s across the runs. What a networked claim
spends is mostly the guest's own setup (the PCI rescan, waiting for the
device and its name, the `ip` commands); the host's part (namespace,
tap, rules, routes, the hand-over) is tens of milliseconds. AUDIT_OPEN.md
has the figures.

### Host sizing

Three limits on the host are shared by every VM and are the operator's
to set. The daemon compares each with its configuration at start and
warns, without refusing, when one is too small; `install-host.sh`
reports the same from `SBX_VM_MAX_RUNS`, `SBX_VM_NET_CONNECTIONS` and
`SBX_VM_WARM`:

| Limit | Needs at least | Because |
|---|---|---|
| `net.netfilter.nf_conntrack_max` | runs × connections | an open run's connections through its link are tracked by the host's table, up to `--vm-net-connections` each |
| the daemon's `RLIMIT_NOFILE` (`LimitNOFILE=`) | runs × connections × 2 + (runs + pool) × 8 + 1024 | an allowlist run's connections through its proxy are two of the daemon's open files each; a few more per VM and for the daemon itself |
| `fs.aio-max-nr` | (runs + pool) × 128 | every VM's disk takes 128 of the host's asynchronous I/O (measured; io_uring is refused, so the hypervisor uses Linux AIO) |

runs is `--vm-max-runs`; pool is the warm pool's VMs. With no
`--vm-max-runs` only the pool's AIO can be checked, and the log says so.
At the defaults (4096 connections), 64 runs need a connection table of
262144 and an open file limit of about 525000.

Confinement of the hypervisor. The hypervisor process is what a guest
talks to, so each one is run as if a guest had already taken it over.
The layers are independent; each is checked by the live suite.

- **Its own file tree and process table (the jail).** A hypervisor
  does not run in the host's file tree. The daemon starts its own
  binary again as a small helper, in new mount, PID, network, IPC, UTS
  and cgroup namespaces and already inside the VM's cgroup. The helper
  mounts an empty tmpfs, binds into it exactly seven things (the
  hypervisor binary, the kernel image, the VM's disk node, `/dev/kvm`,
  `/dev/urandom`, and the directory the VM's two sockets are made in),
  makes that the root with `pivot_root`, detaches the old root so that
  no path, descriptor or working directory leads back to the host's
  tree, drops to the VM's UID and executes the hypervisor in its place.
  The hypervisor starts with its input and its two outputs open and
  nothing else (a run's tap reaches it later, over its API socket):
  every other descriptor is closed at the exec,
  including any the daemon itself was started with and knows nothing
  of.
  The root is read-only; everything is `nosuid`, everything but the
  binary `noexec`, everything but the three devices `nodev`, and only
  the socket directory is writable. There is no `/proc`, no `/sys`, no
  `/etc`, no `/run/dbus` and no other run's disk or sockets: the host's
  unix sockets that anyone may connect to (the system D-Bus, journald,
  the resolver, snapd) have no name the hypervisor could connect to.
  In its PID namespace the hypervisor is process 1 and alone, so no
  process of the host has a number it could signal or inspect. The
  helper is root for the few milliseconds this takes, runs nothing but
  the daemon's own code, and adds about 10 ms to a create. No separate
  jailer binary is installed.
- **Its own user.** Every VM's hypervisor runs under a UID and GID of
  its own from the reserved range, for as long as it runs, with one
  supplementary group (the one that opens `/dev/kvm`), no capabilities,
  an empty capability bounding set and `no_new_privs`, in network and
  IPC namespaces of its own that hold nothing (not even a working
  loopback). Its core dump limit is 1 byte, soft and hard: a
  hypervisor's memory is its guest's, and that limit, unlike 0, also
  keeps the kernel from handing a dump to a crash reporter that
  `core_pattern` pipes to. Per-VM UIDs
  rather than one shared account, because with a shared account one
  hypervisor could open another run's disk, connect to another run's
  control socket and signal another run's process; with its own UID,
  plain file permissions already refuse all three. No account has to be
  created. The daemon stays root and reaches each VM's sockets as root.
- **Its own disk node.** The hypervisor is not given the volume's node
  under `/dev/zvol` (udev resets that node's ownership on every change
  event, and it is shared with the host's tools). It gets a private
  block device node for the same volume in `--vm-dev-dir`, mode 0600
  and owned by the VM's UID, removed with the VM. No other run's node
  is touched.
- **The hypervisor's own sandbox.** `--seccomp true` (a system call
  outside the hypervisor's list kills it) and `--landlock`, which limits
  the process to the paths on its command line: the kernel image, its
  disk node, its two sockets, `/dev/kvm` and `/dev/urandom`. A file its
  UID owns elsewhere in its jail is refused. Landlock does not judge a
  connect to a unix socket by its path; the jail is what keeps the
  host's sockets from the hypervisor, by not containing them.
- **The daemon's own seccomp filter, under the hypervisor's.** The
  hypervisor's filters hold the threads a guest drives tightly, but its
  main thread may `clone` with any flags, open sockets of any family
  and set up io_uring, and threads share memory. So the jail helper
  installs a filter of the daemon's just before it executes the
  hypervisor (the kernel runs both and takes the stricter answer). It
  is a list of what is refused, with `EPERM`, and everything else is
  left to the hypervisor's own allowlist: `unshare`, `setns` and `clone`
  with any namespace flag (`clone3` answers `ENOSYS`, so a C library
  falls back to `clone`, whose flags a filter can read); every socket
  family but unix; `io_uring_*` (the hypervisor falls back to the
  kernel's older asynchronous I/O for the disk); the mount calls old
  and new, `pivot_root`, `chroot`; `ptrace`, `process_vm_readv/writev`,
  `pidfd_getfd`, `kcmp`; `keyctl`, `add_key`, `request_key`; `bpf`,
  `perf_event_open`, `userfaultfd`, `memfd_secret`; modules, `kexec`,
  file handles, and the calls only an administrator uses (swap, reboot,
  clocks, quotas, host name). A call made through another
  architecture's table (32-bit on x86-64, x32) kills the process. A
  denylist rather than an allowlist because what a hypervisor needs
  differs by version, architecture and device, and a call missing from
  an allowlist kills a VM at an hour nobody tested; the hypervisor's
  allowlist is still there for the rest. `execve` cannot be on it (the
  filter is installed before the one `execve` that starts the
  hypervisor); the hypervisor's own filters refuse it afterwards.
- **A socket directory with a size.** The one writable place in the
  jail is the directory the VM's sockets are made in. The daemon mounts
  a tmpfs of 64 KiB and 16 inodes there for each VM, owned by the VM's
  UID, and the jail binds that: whatever a hypervisor that was taken
  over writes there fills its own filesystem and nothing of the host's
  `/run`. It is unmounted with the VM, and by the startup sweep.
- **Its sockets are not trusted by path.** The runtime dir is the VM's
  own, so the daemon checks, on every connection, that the VM's UID is
  what listens there before it sends anything.
- **Its own cgroup**, entered at the moment the process is created:
  `memory.max` is the guest's size plus 64 MiB plus 8 MiB per GiB of
  guest (`memory.swap.max` 0), `pids.max` is 128 plus 4 per vCPU,
  `cpu.max` is the VM's vCPUs, and `io.max` on the VM's volume is
  `--vm-disk-mbps` (default 256 MiB/s) and `--vm-disk-iops` (default
  16000), each for reads and for writes separately; 0 turns one off.
  The disk limit is the host kernel's and not the hypervisor's own rate
  limiter, which a hypervisor that was taken over would be free to
  ignore; ZFS volumes honour it for direct I/O, which is how the guest's
  disk is opened (measured: under 20 MiB/s a guest wrote at 19.6 and
  read at 20.2 MiB/s against 349 and 580 without; under 500 operations
  per second it made 494 and 505 against 3946 and 5383). The limits are the daemon's, for every run; a create cannot
  change them. They are for a VM that is alive: I/O the kernel holds
  back for the limit cannot be taken back, a killed process does not
  end while it has any, and the guest chooses how much it queues, so a
  VM that was killed keeps its limits for 3 seconds and then has them
  lifted (what is left of its queue reaches the volume at the volume's
  speed, once). A guest that uses all of its memory
  stays inside that (measured: at most 7 MiB over the guest's size); a
  hypervisor that grows past it is killed by the host's kernel and the
  run reports its VM gone. The group is removed with the VM, and a
  starting daemon kills and removes whatever groups its previous life
  left.

The guest's clock is set by the daemon each time a VM boots (a guest has
no clock of its own to read, and with the wrong date no TLS certificate
verifies).

### Guest networking

A guest controls its own kernel, so nothing here depends on what a guest
does with its network device: it can send any frame, claim any address
and speak any protocol, and the host decides what leaves the tap.

Nor does it depend on a firewall being in place. A firewall fails open:
flush it, and everything passes. So the first layer is what exists at
all, and the rules only say it a second time.

| `network` | What a VM run gets |
|---|---|
| `none` (default) | No network device at all. |
| `allowlist` | A device whose only reachable destination is the run's own proxy port on the gateway address. Always a proxy of its own with a random credential in its URL (the Docker driver shares one proxy between runs that pass no `egressAllow`); the same proxy env, the same allowlist and the same `egressAllow` grammar. No default route and no resolver: the proxy resolves. |
| `open` | A device that is routed and masqueraded to the public internet, with the host's resolvers. See below for what that excludes. |

How it is built:

- **A network namespace per run.** Every run with a network has a
  namespace of its own, made by the daemon, and its tap exists in that
  namespace and nowhere else. The host's services are not in it (a
  socket bound to every address of the host is bound in the host's
  namespace), and neither is any other run's tap. There is no bridge
  and no shared segment, so there is no path of any kind from one guest
  to another.
- **An allowlist run's namespace leads nowhere.** It holds the tap, the
  gateway address and one listening socket: the run's proxy, which the
  daemon listens for from inside that namespace (the proxy's own
  connections leave from the host, as before). It has no link to the
  host and no route but the guest's own address. Its proxy port cannot
  be reached from another run, with or without the credential, because
  it does not exist in another run's namespace.
- **An open run's namespace has one link to the host,** which routes
  and masquerades what arrives on it. Inside the namespace the ranges
  that are not the public internet, the guests' subnet and each of the
  host's own addresses (with the broadcast address of each subnet the
  host is on, which the host's kernel also takes for itself) are
  unreachable routes, port 25 is an
  unreachable routing rule, and DNS to the configured resolvers is
  looked up in a table of its own. These are routes, not firewall
  rules: they hold with no nftables table anywhere. The daemon follows
  the host's addresses and updates the routes when they change.
- **The tap is handed over as a descriptor, to the running VM.** Every
  VM boots without a network device. The daemon creates the run's tap
  in the run's namespace and gives the hypervisor the open file with
  its `vm.add-net` request, as an `SCM_RIGHTS` message on the VM's API
  socket (after the same check of who listens there as for every other
  call); the guest finds the new device on its PCI bus. The hypervisor
  stays unprivileged, in its jail and in its own empty network
  namespace: it has a file descriptor, not an interface. The tap is not
  persistent, so it exists exactly as long as its hypervisor does. A VM
  booted for its run and one taken from the warm pool get their device
  the same way, so a guest sees the same PCI slots and the same
  interface name either way.
- **In the namespace, no IPv6 at all** (disabled, not filtered), strict
  reverse-path filtering (a packet is only accepted from the interface
  its source address is routed to, which for the tap is the VM's one
  address), no answer to a ping, no redirects, and no forwarding unless
  the run is open.
- **The rules, in two places.** Each run's namespace has its own
  nftables ruleset whose chains drop by default. At the tap's ingress
  hook (before the namespace's ARP and IP code runs): only frames from
  the VM's MAC, only IPv4 from the VM's address, and only ARP requests
  for the gateway from that MAC and address; spoofed MACs and
  addresses, IPv6, DHCP, multicast, broadcast and other ethertypes are
  dropped there. Then: to the namespace itself, only an allowlist run's
  own proxy port; through it, only an open run's traffic, never to the
  guests' subnet or the host's addresses, DNS to the resolvers, then
  everything except the ranges that are not the public internet and TCP
  port 25; back to the guest, only answers. A `flush ruleset` on the
  host does not touch these: nftables is per namespace. The host has
  one table per daemon identity for the open runs' links, which says
  the same again (and masquerades); a link the table does not name is
  dropped at every hook.
- **Addresses.** Each VM has one address, a /32 routed to its tap. The
  gateway address is the same in every run's namespace and means that
  namespace. Neighbour entries are permanent on both sides of every
  link, so no ARP a guest sends can change who has an address. The
  guest is told its address, route and resolvers through its agent (it
  needs `ip` from iproute2; with systemd-resolved it is configured
  through `resolvectl`, otherwise `/etc/resolv.conf` is written).
  Nothing is offered by DHCP. An address is not handed to another VM
  until every other address has been used, and the host's connection
  tracker's entries for it are deleted when it is given up and again
  before it is used. An allowlist run's proxy port is fixed by its
  address slot (20000 plus the slot), so it is likewise not used again
  while the namespace that had it exists.
- **The daemon watches the contents of its rules, not only that they
  exist.** Every two seconds it lists each ruleset it wrote (the host's
  table and every run's namespace), compares it with what the kernel
  listed when it was written, and writes back whatever differs: a table
  that was deleted, a table that was flushed and left empty, a single
  changed rule. Each restore is logged as an error. The watch stops
  only when it reads another daemon instance's mark in the host's
  table; a look that fails (an `nft` that could not be started) is
  logged and followed by the next one.
- **A run's share of the network is bounded.** `--vm-net-mbit` (default
  200) is what a run may send and what it may receive, per second: a
  token bucket (`tbf`) on the run's tap, which is what the guest
  receives on either tier, and on an open run's link, which is what it
  sends. A queue on a device is the kernel's and not a rule, so a
  flushed firewall does not remove it. `--vm-net-connections` (default
  4096) is how many connections a run may have tracked at once, counted
  by `ct count` in the run's own namespace: for an open run what it
  starts through the link, so that one run cannot fill the host's
  connection table, and for an allowlist run its connections to its
  proxy, which are the daemon's open files. Connections that both ends
  closed stop counting at once; UDP and ICMP flows count until the
  kernel forgets them. 0 turns either off. What an allowlist run sends
  to its proxy has no rate: it has no device to leave through.

What happens with no rules at all, which the live suite does to four
running guests (every table of the daemon flushed, then deleted, on the
host and inside every namespace, with the daemon's upkeep stopped so
that nothing comes back): no guest reaches a host service on any of the
host's addresses, another guest, or another run's proxy; an allowlist
guest still reaches only its own proxy; an open guest still reaches
nothing link-local, no port 25 and nothing of its resolver beyond DNS.
What an open run loses then is its way out (nothing masquerades), not
its limits. What remains open in that state is in AUDIT_OPEN.md: a
neighbour on the host's own network segment that routes the guests'
subnet through the host could send unsolicited packets to an open
guest.

Where the `open` tier differs from the Docker driver's, on purpose. The
Docker `open` tier is "everything the host can route", including the
host's LAN, an overlay network, a cloud metadata service and the host's
own services on the bridge gateway. A VM run on `open`:

- reaches the **public internet only** by default. Private
  (`10/8`, `172.16/12`, `192.168/16`), shared (`100.64/10`), link-local
  (`169.254/16`, where metadata services are), loopback, documentation,
  benchmarking, multicast and reserved ranges are dropped.
  `--vm-open-private` (`SBX_VM_OPEN_PRIVATE=true`) restores the Docker
  meaning for the private, shared, documentation and benchmarking
  ranges; link-local, loopback, multicast and reserved space stay closed;
- never reaches the **host itself** or another guest, with or without
  that flag;
- cannot connect to **TCP port 25** anywhere (the Docker tier does not
  close it);
- has **no IPv6**.

The resolvers are an exception to the private ranges for port 53 only:
a host that resolves through its router still gives its guests DNS.

What to know before relying on it:

- `net.ipv4.ip_forward=1` makes the host route between all of its
  interfaces, not only for guests. If that is new on your host, filter
  forwarding for the rest in your own firewall.
- Another firewall on the host that drops forwarded traffic by default
  (a `policy drop` forward chain: ufw, firewalld, Docker's `FORWARD`
  chain) still applies to open runs: an accept in this daemon's table
  does not overrule a drop in another. Allow traffic arriving on the
  daemon's links there (the daemon logs the chains it finds at start,
  and the link prefix, `tvh…`). An allowlist run does not pass the
  host's firewall at all.
- While the daemon is dead (a crash), the namespaces and their rules
  stay as they were, so a leftover guest has at most its tier: an
  allowlist guest has nothing (its proxy was the daemon), an open guest
  has the internet. Nothing watches the rules then, and nothing needs
  to for the host's services and other guests to stay out of reach.
  The next start rewrites the host's table before anything else, which
  cuts every leftover open guest off, and the sweep then kills the VMs
  and removes their namespaces and links.
- The watch costs one `nft list` per running networked VM every two
  seconds.

The guest's disk is opened with direct I/O, so it is not cached a second
time in the host's page cache at the VM's expense.

The cgroup: by default the daemon makes `/sys/fs/cgroup/teploy-sandbox-vm`
itself at start, beside the groups systemd manages, the way a container
runtime's cgroupfs driver does. That needs the root group to pass `cpu`,
`memory` and `pids` down, which systemd does by default. To keep the VMs
inside the daemon's own unit instead, give the unit `Delegate=yes` and
`DelegateSubgroup=daemon` (systemd 254 or newer; the daemon's own process
then sits in a subgroup, which leaves the unit's group free to have
children with controllers) and pass
`--vm-cgroup /sys/fs/cgroup/system.slice/UNIT.service/vms`. Both
arrangements were run against the live suite.

Guest disks and the host. `zfs set volmode=dev POOL` is what keeps the
host kernel from scanning a guest's disk for partitions: every volume
under the pool inherits it, so no guest partition becomes a block device
on the host. Setting it on each volume as it is cloned is not enough (on
ZFS 2.2 the device node can be created before the property applies), so
the daemon requires it on the pool and checks each run's device before
booting from it.

The whole disk is still a block device on the host for as long as the
volume exists, and udev would probe it like any other disk: a guest that
writes a filesystem signature over the start of its disk would get a
`/dev/disk/by-label` or `by-uuid` link on the host with a label of its
choosing. The rule files that storage tools install (bcache, LVM,
kpartx, udisks) look at block devices too, and one that finds its own
signature on a disk hands the disk to the host's kernel driver for it.
The host must turn both off, with
`/etc/udev/rules.d/59-teploy-zvol-noprobe.rules` containing
`KERNEL=="zd*", ENV{UDEV_DISABLE_PERSISTENT_STORAGE_RULES_FLAG}="1", ENV{DM_UDEV_DISABLE_OTHER_RULES_FLAG}="1"`
(`scripts/install-host.sh` installs it; it applies to every ZFS volume
on the host, and the `/dev/zvol` links stay). The daemon does not take
the rule file's word for it: at start it creates a 1 MiB scratch volume,
writes a labelled filesystem signature to it as a guest could, lets udev
handle the device and refuses to start if udev recorded a filesystem,
made a link, or handled the device without both flags. The scratch
volume is destroyed either way. A rule file that honours neither flag is
not covered: check what `udevadm test /sys/class/block/zdN` runs on your
host if it has storage tools beyond a stock install.

A VM's console and its hypervisor's output are kept in the daemon's
memory, the last 64 KiB of each; nothing a guest can make grow is written
to `--vm-run-dir`.

Test against a real hypervisor (needs root, KVM, ZFS, a host set up by
`scripts/install-host.sh`, and outbound internet for the network tiers;
CI has none of it and only vets the suite; what CI does run as root, on
x86-64, is the jail, the seccomp filter and the socket filesystem from
the unit tests in `internal/vm`):
`CGO_ENABLED=0 go test -c -tags vmintegration -o vm.test . && sudo ./vm.test -test.run TestVM -test.v`
(with `SBX_VM_WARM=1x512=2,1x1024=1` the whole suite runs with a warm
pool, and the network and lifecycle tests then get pool VMs; the
`TestVMWarmPool` and `TestVMWarmPoolRaces` tests bring their own pool
either way)

### Off-host storage

With `--remote-endpoint` a stopped run's disk is also kept in an
S3-compatible bucket, so the host that ran it is disposable: any daemon
given the same bucket, prefix and master key can resume or fork the run.
It is the VM driver's (a stop snapshot is a ZFS send stream) and off
unless configured. A daemon without it behaves as it did before remote
storage existed: `snapshot:<tag>` is an ordinary image name to it, and
none of the routes and fields below exist.

```
serve --driver vm --state-dir /var/lib/teploy-sandbox/state \
  --remote-endpoint https://s3.example.com --remote-bucket sandbox-runs \
  --remote-access-key ID --remote-secret-key-file /etc/teploy/s3-secret \
  --remote-key-file /etc/teploy/remote.key
```

| Flag (env) | Default | |
|---|---|---|
| `--remote-endpoint` (`SBX_REMOTE_ENDPOINT`) | none | The service's URL. Empty: no remote storage. `http://` is accepted for this host only (see `--remote-insecure-http`) |
| `--remote-bucket`, `--remote-prefix` | | Daemons that share both share their stopped runs |
| `--remote-region`, `--remote-path-style` | `us-east-1`, off | Signing region; `endpoint/bucket/key` instead of `bucket.endpoint/key` |
| `--remote-access-key` (`SBX_REMOTE_ACCESS_KEY`, `AWS_ACCESS_KEY_ID`) | | |
| `--remote-secret-key-file` (or `SBX_REMOTE_SECRET_KEY`, `AWS_SECRET_ACCESS_KEY`) | | The secret is never a flag value |
| `--remote-key-file` (or `SBX_REMOTE_KEY`) | required | The master key, the same on every daemon. See "The master key" |
| `--remote-previous-key-file` | none | Comma-separated files of master keys this daemon still opens but no longer wraps with (the state while a rotation runs) |
| `--remote-insecure-http` | off | Allow a plain `http://` endpoint on another host. Only on a network that is itself trusted |
| `--remote-snapshot-retry` | 12h | How long a caller snapshot whose upload failed is retried before it stays on that host only (0: not retried). Shorter than `--remote-gc-grace` |
| `--remote-chunk-mb`, `--remote-parallel` | 16, 4 | Object size and objects in flight; one transfer holds about (parallel + 1) chunks in memory, whatever the disk's size |
| `--remote-transfers` | 4 | Uploads and restores at once, across all runs. The rest wait |
| `--remote-max-chain` | 8 | Incremental uploads in a row before one is sent against the base image again (1 to 64: no daemon restores through a longer chain) |
| `--remote-local` | `keep` | `keep` a durable snapshot's local copy for a fast resume here, or `drop` it at once |
| `--remote-pool-reserve` | 15 | Percent of the pool to keep free; below it, local copies of durable snapshots go, oldest stop first |
| `--remote-sync-interval`, `--remote-gc-interval`, `--remote-gc-grace` | 1m, 1h, 24h | The grace is at least 1h |
| `--remote-scrub-interval` | 6h | How often every stopped run this daemon reports durable is checked again in the bucket (0: never) |
| `--remote-unfenced` | off | See "Without conditional writes" |

It needs `--state-dir` and a reachable bucket: a daemon that cannot
reach its storage at start does not start. The state directory holds the
daemon's identity among those sharing the bucket (`daemon-id`, a random
name) and the name of the bucket prefix its registry belongs to
(`remote-fleet-id`, read from `v1/fleet-id` in the bucket, which the
first daemon to use a prefix writes). A daemon started against a bucket
or prefix with another name, or with none, **does not start**: a
registry full of runs pointed at the wrong bucket finds none of their
records there. To move a daemon to other storage on purpose, remove
`remote-fleet-id`; what it has copies of is then published there again.

**The master key.** 32 random bytes, in a file only the daemon's user
can read (a file readable by group or others is refused), as 64 hex
digits, as base64, or raw:

```
(umask 077; head -c 32 /dev/urandom | xxd -p -c 64 > /etc/teploy/remote.key)
```

A key that is plainly not random is refused (32 characters of text,
zeros, a repeated byte). A secret given in the environment
(`SBX_REMOTE_KEY`, `SBX_REMOTE_SECRET_KEY`, the `AWS_*` variables) is
removed from the daemon's environment once read, and no host command the
VM driver runs is started with those variables: files are still the
better place, since a process's first environment stays readable in
`/proc` to its own user. Losing the master key loses every stopped run
that is only in the bucket. It is one key for the whole fleet: whoever
holds it can read and write everything in the bucket.

**What is stored.** Under the prefix:

```
v1/snap/<id>/<attempt>/<index>   one encrypted chunk of a snapshot's stream
v1/snap/<id>/manifest            the snapshot: its chunks (size and SHA-256
                                 of each), the stream's SHA-256, and the
                                 snapshot the stream is incremental against
v1/run/<run id>/<generation>     one generation of a run's record
v1/fleet-id                      the random name of this prefix
```

A stop sends `zfs send -c` of the stop snapshot, cut into chunks as it is
produced; nothing is held whole in memory or written to the host's disk.
The stream is incremental against the run's previous upload while this
host still has it and the bucket has it whole, and otherwise against the
golden image the run's disk descends from, which is uploaded once (as
`base-<its ZFS guid>`) by the first daemon that needs it there. A daemon
whose own golden image is that very snapshot uses it; any other receives
it from the bucket, so daemons do not have to be provisioned with the
same golden. After `--remote-max-chain` incremental uploads the next is
sent against the base again: a restore never fetches more than the base,
one stream against it and that many increments. A fork's first stop is
sent against the snapshot it was forked from.

**Encryption.** Every chunk is AES-256-GCM, encrypted on the host, under
a key derived (HKDF-SHA256) per snapshot from the run's data key; the
chunk's place (snapshot, upload attempt, index) is authenticated with it.
Manifests and run records (which hold the run's env) are sealed the same
way, bound to the name they are stored under and to the run (or base
image) whose key they are under. The run's data key is random, and
stored only wrapped by the master key. The storage provider sees object
sizes, counts and times, and the IDs in key names; never guest data or
run settings.

**Durable means** the manifest and then the run's record are in the
bucket, **and the bucket was looked at**: every chunk the manifest names
is there with its recorded size, and so is every snapshot the stream
builds on, back to the base image. That check is made after the manifest
is written and again after the record names the snapshot; an upload that
fails it takes its manifest back, makes sure of the base image again and
starts over. `POST /stop` uploads before it answers, and the run then
carries

```
"remote": {"state": "durable", "generation": 3, "snapshot": "<id>", "local": true,
           "storedBytes": 7130112, "uploadMs": 66, "incremental": true, "durableAt": "..."}
```

`state` is `durable`; `pending` or `failed` (stopped here, **not** known
to be whole off the host: `error` says why, and the upload is retried on
every upkeep round from this host's copy); or `superseded` (below). The
stop itself answers 200 either way: the run is stopped. A local copy is
only ever dropped once `state` is `durable`, and only after the bucket
was asked again. A stop made by the reaper (`onExpire: "stop"`) or at
shutdown is published by the upkeep, not in line.

"Durable" is a statement about a moment. The **scrub** makes it again:
every `--remote-scrub-interval` (and on `POST /v1/remote/scrub`) each
daemon checks every stopped run it reports durable the same way, and
that the run's record is there. A run that fails stops being reported
durable, in the log and in `remote.error`. If this host still has its
snapshot the next upkeep uploads it again; if it does not (`local:
false`), the run stays listed as `failed` and nothing can restore it —
the log line begins `STOPPED RUN AT RISK`. Nothing is deleted on a
scrub's findings. Collection reports, fleet-wide, every snapshot that
cannot be restored — its manifest names chunks that are not there, or it
builds on a snapshot that is gone or missing chunks — caller snapshots
and base images included, which no scrub looks at.

**Resuming anywhere.** Each daemon lists the bucket every
`--remote-sync-interval` (and on `POST /v1/remote/sync`), and a resume,
fork or delete of an ID it does not know looks the run up first. A run
stopped elsewhere appears in `GET /v1/runs` as `stopped` with
`remote.local: false`; `capacity.runs.stoppedRemote` counts those. Resume
fetches the manifests, verifies every chunk (size and SHA-256 against the
manifest, then the authentication tag) before any of it reaches the
pool, holds each stream to its first record (the plain stream of one
volume's snapshot, with the identities the manifest names: a filesystem,
a package of datasets or another snapshot is refused before `zfs
receive` sees it, and nothing received is mounted), receives the streams
into volumes marked as a restore, and only when the last one is in makes
the snapshot usable. A restore that would not fit in the pool is not
started. A chunk that is missing, altered, cut short or out of place
fails the resume with the run still stopped, and what the restore
received is removed again — except a base image the restore had finished
receiving, which is kept like any other received base, for the next
restore or until the pool is short; and if the removal itself fails
(the error says so) the leftovers are marked as an unfinished restore,
which the next start removes.

At most `--remote-transfers` uploads and restores run at once; restores
run one at a time, and so do uploads of base images. A request that
waits for one gives up when its caller does.

**One running copy.** A run's record is a series of numbered
generations, each an object written once with `If-None-Match: *` (the
header is signed, so nothing on the path can strip it). To resume, a
daemon creates the next generation ("running", by me); of two daemons
that try, the service lets exactly one, and the other answers 409. No
clock, heartbeat or controller decides who runs a run. The cost: a
daemon cannot tell a dead holder from a slow one, so a run whose holder
died stays held until someone says so. `POST /resume {"takeover": true}`
on another daemon is that statement: it resumes the run **from its last
durable stop**. If the old holder was alive after all, its copy keeps
running but can no longer become the run: its next stop is kept on its
host as `remote.state: "superseded"`, which can be forked or deleted,
not resumed. Only a record **another** daemon wrote supersedes a copy; a
daemon that finds its own record newer than it remembered (a crash
between a write and its note) carries on from it. A daemon that restarts
finds the runs it was running (lost with their VMs, as always) back as
stopped at their last durable stop. Resume, and delete of a stopped run,
need the bucket: when it cannot be reached they answer 503 rather than
act on a run that may have moved.

**A record that is not there** is not a statement. A daemon drops its
copy of a run only when the bucket holds a record saying another daemon
runs it now, or that it was destroyed. A run whose record is missing —
a provider that lost objects, records deleted by hand — is kept, shown
as `failed` with the reason, and published again from this host's copy.
One consequence to know: the record that says "destroyed" is kept for
thirty times `--remote-gc-grace` (30 days by default) and then
collected, so a daemon that was away for longer than that and still
holds a copy of a run destroyed meanwhile brings the run back.

**Without conditional writes.** The daemon tests the service at start. If
`If-None-Match` is not honoured, uploads, restores and forks work as
above, but a daemon only resumes or deletes runs whose record it wrote
last itself (409 otherwise): nothing in the bucket could stop two
daemons. `--remote-unfenced` lifts that for deployments where a
controller already sends each run to one daemon at a time.

**Retention and garbage.** `--stopped-retention` applies to the bucket:
whichever daemon's reaper gets there first destroys the run in it. The
daemon that stopped a run counts from the stop; every other daemon
counts the same length from when it first saw the run, on its own
clock, so one daemon whose clock runs ahead does not reap the fleet's
runs early. Destroying a run writes a last generation ("destroyed").
Every `--remote-gc-interval` each daemon deletes snapshots that no run's
newest record names, no caller owns and no snapshot that is staying
builds on; chunks no manifest names (failed or interrupted uploads); the
records of destroyed runs, thirty graces after; and old generations.

Nothing is deleted before **the collecting daemon itself** has seen it
as garbage for `--remote-gc-grace` on its own clock — a snapshot
unreferenced, an upload's chunks without a manifest and not growing — so
a daemon that just started deletes nothing for that long, and a
collector whose clock is wrong cannot age an upload in flight. The
service's modification times are a second condition; where they cannot
be read, chunks without a manifest are not collected at all. What a
manifest builds on is kept for as long as the manifest is, referenced or
not: an upload's manifest exists a moment before its record. A round
that cannot read a record or a manifest deletes nothing at all, and a
round in which a manifest it listed is not there when read deletes no
snapshot (old generations and other uploads' leftover chunks still go).
Before a round deletes snapshots it lists the bucket once more and reads
what is new — records that appeared or moved on, manifests that were not
there — and keeps whatever those name or build on; the rest of what was
due goes, so a fleet that is never still does not keep a destroyed run's
disk for good. Only objects
shaped exactly like the daemon's own are ever considered; anything else
under the prefix is counted in the log and left. `POST
/v1/remote/collect` runs a round now.

Clocks, then: none decides who runs a run. A daemon's own clock times
its grace and its retention; the service's modification times are
compared with it as a second condition for deleting; and request
signing needs the two within the service's tolerance (the error names
the difference).

**Key rotation.** Rotation retires a master key that is merely old. It
is **not** a recovery from one that leaked: no data key changes, so
whoever holds the old master and a copy of any old manifest or record
still has the keys the chunks are under. (Recovering from a leak means
uploading every snapshot again under new data keys, which is not built.)

Every daemon is given the new master key and, while the rotation runs,
the old one under `--remote-previous-key-file`. A daemon's own writes
re-wrap as they go: a run's key it opens under the old master is stored
and answered under the new one. `POST /v1/remote/rotate`, **on every
daemon**, covers what is standing still: every manifest (checked to be
whole before and after it is rewritten), every stopped run's record as a
new generation with the state and the owner unchanged, and the data keys
in that daemon's own registry (its running runs', and the snapshot
uploads it still owes). The answer says whether the previous master is
still needed and for what, in `previousKeyNeeded` and
`previousKeyNeededFor`:

- records that were just rewritten: the generation each replaced is
  under the old master until the next collection has pruned it;
- runs that are running: the record of each is rewritten by its own next
  stop, and until then a takeover of it needs the old master;
- destroyed runs' records, until collection removes them (thirty graces);
- records that changed during the pass (run it again), and, on a service
  without conditional writes, stopped runs' records another daemon wrote
  or that `--remote-unfenced` lets another daemon change: those wait for
  their own next write, or for the pass on the daemon that wrote them.

The old master can be retired when a pass on **every** daemon answers
`previousKeyNeeded: false`. A daemon that was not passed over keeps old
keys in its own registry and cannot stop its runs without the old
master.

**Caller snapshots.** `POST /snapshot` uploads too and adds
`"remote": {"state", "id", "error?", ...}` to its answer — the ID names
the snapshot in remote storage whichever way the upload went, so a
snapshot that failed is still nameable. The run is held only while the
snapshot is taken, not while it is uploaded: it can be exec'd in,
stopped, destroyed or expire meanwhile, and the request answers when the
upload has. `failed` means failed so far: the upload is retried by the
upkeep (`--remote-snapshot-retry`, 12h by default) and `GET
/v1/remote/snapshots` says when it landed; membership is the probe.
`image: "snapshot:<id>"` on create boots it on any daemon, and a delete
may name that ID too. An ID names a **caller's** snapshot only: a run's
stop snapshot is that run's disk, goes with the run, and is used by
naming the run (resume, or fork) — a create or delete naming one by ID
is refused (400, 409), and an ID that is nowhere is 404. What a delete
by ID removes is the bucket copy and anything local to the host asked; a
local copy on another host goes by the ref that host minted, which is
the caller's to keep. Until its upload has landed, a snapshot is
deletable only on the host that took it — nowhere else can name what is
not in the bucket yet.

Requirements of the service: SigV4 over every header that carries a
condition, PUT/GET/HEAD/DELETE, ListObjectsV2 that honours `prefix`
(a listing with a key outside it is refused, not acted on), and
read-after-write consistency of objects and listings (a listing that
does not show a chunk which is there is detected and retried, never
taken for a missing chunk). Run live against versitygw 1.11 (POSIX
backend) before the changes of 2026-11-20; see `AUDIT_OPEN.md` for what
has not run live since.

Live suite: `TestVMOffHost` in the `vmintegration` suite, with
`SBX_S3_TEST_ENDPOINT`, `SBX_S3_TEST_BUCKET`, `SBX_S3_TEST_ACCESS_KEY` and
`SBX_S3_TEST_SECRET_KEY` (skipped without them); the client alone:
`go test -tags s3integration ./internal/s3`.

### Validating on a fresh x86-64 host

Everything above was developed and run live on arm64 only (nested KVM);
x86-64 has been compiled and unit-tested by CI, never run with a
hypervisor. The steps below take a fresh host to a run of the whole live
suite and to the figures that close the x86-64 and bare-metal items in
`AUDIT_OPEN.md`. Follow them in order; each command is meant to be run
as written, from the checkout unless it says otherwise. Not every
mistake is caught for you: the daemon and `scripts/install-host.sh`
check the host, but nothing checks that the guest kernel or the base
image is the one described here.

1. **The host.** A bare-metal x86-64 machine with VT-x on in its
   firmware, 4 or more CPUs, 16 GB of memory, a spare disk for the ZFS
   pool and outbound internet. A cloud VM with nested KVM can run every
   step and closes the x86-64 items, but not the audit's bare-metal
   item: its figures are nested ones, like the arm64 runs. Install
   **Ubuntu 24.04 LTS** with its 6.8 kernel (the server install's
   default): Linux 6.8 and ZFS 2.2 are the versions of the arm64 runs,
   so the CPU architecture is the only variable. Keep the
   host free of other firewalls (no Docker; leave `ufw` inactive): a
   `policy drop` forward chain blocks open runs (see Guest networking
   above).
   `ls -l /dev/kvm` must show the device.
2. **Packages.**
   `sudo apt-get update && sudo apt-get install -y zfsutils-linux nftables conntrack iproute2 qemu-utils cloud-guest-utils e2fsprogs git curl python3`
   (`curl` and `python3` are also used on the host by the network tests,
   for their peer). Go comes from go.dev, not from Ubuntu, whose
   `golang-go` is older than `go.mod` allows; CI builds with 1.26:
   `curl -fsSL https://go.dev/dl/go1.26.11.linux-amd64.tar.gz | sudo tar -C /usr/local -xz`
   and `export PATH=/usr/local/go/bin:$PATH` (any later 1.26.x works).
   Then `git clone https://github.com/useteploy/teploy-sandbox.git && cd teploy-sandbox`.
3. **The ZFS pool**, named `sbx` throughout:
   `sudo zpool create -O compression=lz4 -O volmode=dev sbx /dev/disk/by-id/YOUR-DISK`.
   A file works for a trial (`sudo truncate -s 60G /var/lib/sbx.img`,
   then the same command with `/var/lib/sbx.img` for the disk), but its
   disk figures are not a bare-metal host's.
4. **Cloud Hypervisor v54.1**, the version every live run so far used,
   as its statically linked release asset, before the host script so
   that it checks the binary:
   `sudo curl -fsSL -o /usr/local/bin/cloud-hypervisor https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/v54.1/cloud-hypervisor-static`,
   `sudo chmod 0755 /usr/local/bin/cloud-hypervisor`, and
   `cloud-hypervisor --version` to see it run.
5. **The guest kernel.** The guest runs the host's choice of kernel,
   not the image's: Cloud Hypervisor on x86-64 boots an uncompressed ELF
   `vmlinux` directly (PVH), with no initramfs, so everything the guest
   needs must be built in: virtio block, PCI and net, the virtio vsock
   transport (the agent's only way in), the balloon, the RNG, ACPI PCI
   hot-plug (how a run's network device arrives), ext4 and vfat (the
   image mounts its EFI partition). A distro's `/boot/vmlinuz` is a
   compressed bzImage that loads those as modules, and does not boot
   here. Use the kernel Cloud Hypervisor publishes for this: the
   `vmlinux-x86_64` asset of a `ch-release-*` release of
   [cloud-hypervisor/linux](https://github.com/cloud-hypervisor/linux/releases),
   built from that tag's `arch/x86/configs/ch_defconfig`, which has all
   of the above built in and no module support (`make ch_defconfig && make vmlinux`
   in that tree builds the same). For example, the newest release when
   this was written:
   `sudo install -d -m 0755 /var/lib/teploy-sandbox/vm` and
   `sudo curl -fsSL -o /var/lib/teploy-sandbox/vm/vmlinux-x86_64 https://github.com/cloud-hypervisor/linux/releases/download/ch-release-v7.2.8-20261009/vmlinux-x86_64`,
   then `sudo chmod 0644 /var/lib/teploy-sandbox/vm/vmlinux-x86_64`
   (an unprivileged VM process must read it). The daemon and the suite
   look for `/var/lib/teploy-sandbox/vm/Image` (the arm64 name) unless
   told otherwise, and refuse to start without a kernel: set
   `SBX_VM_KERNEL=/var/lib/teploy-sandbox/vm/vmlinux-x86_64` (the
   daemon's `--vm-kernel`). Leave `SBX_VM_CMDLINE` unset: the default
   command line already names the x86-64 console (`ttyS0`) and the root
   partition (`/dev/vda1`).
6. **Host setup**: `sudo env SBX_VM_WARM=1x512=2,1x1024=1 scripts/install-host.sh sbx`.
   It writes the udev rule, opens `/dev/kvm` to the `kvm` group, checks
   the cgroup controllers, the network tools and kernel features, the
   hypervisor's linkage, seccomp and Landlock, and sizes the host for
   the pool the suite will use. It must end with "host is ready". If it
   reports no `tbf` queue,
   `sudo apt-get install -y linux-modules-extra-$(uname -r)` and run it
   again.
7. **The base image**: Ubuntu 24.04's cloud image, which has what the
   suite runs in a guest (systemd, `iproute2`, `curl`, `python3`,
   `netcat-openbsd`) and puts its root filesystem in partition 1, where
   the kernel command line looks for it. Write it to a volume, grow its
   root filesystem, and turn cloud-init off (with it on, a guest looks
   for a datasource on every boot and configures network devices
   itself). The pool hides every volume's partitions (`volmode=dev`), so
   this one volume shows them while it is prepared, as
   `scripts/build-golden.sh` does:

   ```sh
   curl -fsSLO https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
   sudo zfs create -V 20G sbx/base
   sudo qemu-img convert -f qcow2 -O raw noble-server-cloudimg-amd64.img /dev/zvol/sbx/base
   sudo zfs set volmode=full sbx/base
   sudo udevadm settle
   disk=$(readlink -f /dev/zvol/sbx/base)
   ls -l "${disk}p1"                 # the root partition; if it is not there yet, wait a moment and repeat from the readlink
   sudo growpart "$disk" 1
   sudo e2fsck -f -y "${disk}p1"
   sudo resize2fs "${disk}p1"
   mnt=$(mktemp -d)
   sudo mount "${disk}p1" "$mnt"
   sudo touch "$mnt/etc/cloud/cloud-init.disabled"
   sudo umount "$mnt"
   sudo zfs set volmode=dev sbx/base
   sudo zfs snapshot sbx/base@v1
   ```

8. **The golden image**: the guest agent for x86-64, installed into a
   clone of the base:
   `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o teploy-guestd ./cmd/teploy-guestd`,
   then
   `sudo scripts/build-golden.sh --from sbx/base@v1 --to sbx/golden-guestd@v1 --guestd ./teploy-guestd`.
   `sbx/golden-guestd@v1` is the name the suite and the daemon use by
   default.
9. **The root-only unit tests**, exactly as CI's `vm-root` job runs
   them. They are in `./internal/vm`, and they re-execute their own test
   binary inside a jail as an unprivileged UID, which is why the binary
   is installed where any UID can start it:

   ```sh
   set -o pipefail
   CGO_ENABLED=0 go test -c -o vm-unit.test ./internal/vm/
   sudo install -D -m 0755 vm-unit.test /opt/teploy-test/vm-unit.test
   sudo /opt/teploy-test/vm-unit.test -test.v 2>&1 | tee vm-unit.log
   grep -E -- '--- SKIP' vm-unit.log && echo "a test was skipped: that is a failure"
   for name in TestJailHoldsNothingOfTheHost TestJailRefusesTheCallsTheFilterNames TestSocketDirIsBounded TestSeccompNumbersAreThisArchitectures; do
     grep -q -- "--- PASS: $name" vm-unit.log || echo "$name did not run"
   done
   ```

   The run must pass, with no `--- SKIP` (as root on this host none of
   them has a reason to skip) and with all four named tests passing.
   `TestJailRefusesTheCallsTheFilterNames` makes the refused calls on
   purpose and can leave seccomp kill lines in the kernel log; the check
   in step 11 only reads what came after.
10. **The live suite**, twice: without a warm pool and with one. Each
    run takes about 30 minutes, and the network tests need outbound
    internet (the open tier is tested against public hosts). Build once,
    then note the time, so that step 11 reads only these runs' kernel
    log:

    ```sh
    CGO_ENABLED=0 go test -c -tags vmintegration -o vm.test .
    start="$(date '+%F %T')"
    sudo env SBX_VM_KERNEL=/var/lib/teploy-sandbox/vm/vmlinux-x86_64 SBX_VM_HYPERVISOR=/usr/local/bin/cloud-hypervisor \
      SBX_VM_POOL=sbx SBX_VM_GOLDEN=sbx/golden-guestd@v1 \
      ./vm.test -test.run TestVM -test.v -test.timeout 2h 2>&1 | tee vm-pool-off.log
    sudo env SBX_VM_KERNEL=/var/lib/teploy-sandbox/vm/vmlinux-x86_64 SBX_VM_HYPERVISOR=/usr/local/bin/cloud-hypervisor \
      SBX_VM_POOL=sbx SBX_VM_GOLDEN=sbx/golden-guestd@v1 SBX_VM_WARM=1x512=2,1x1024=1 \
      ./vm.test -test.run TestVM -test.v -test.timeout 2h 2>&1 | tee vm-pool-on.log
    ```

    Both must end in `PASS`, again with no `--- SKIP`.
    `TestVMWarmPoolRaces` is sensitive to timing: if it alone fails,
    re-run it alone (`-test.run TestVMWarmPoolRaces`) before believing
    the failure, and record both runs.
11. **What to record**, in a new dated entry in `AUDIT_OPEN.md`, to
    close its open x86-64 and bare-metal items:
    - the host: CPU model, bare metal or not, memory, disk, Ubuntu and
      kernel version (`uname -r`), ZFS (`zfs version`), the hypervisor
      (`cloud-hypervisor --version`) and the guest kernel's release tag;
    - that both runs passed (or what failed, and the re-runs);
    - **no seccomp kills** with the real x86-64 hypervisor under the
      daemon's own filter: `sudo journalctl -k --since "$start" | grep -E 'type=1326|seccomp'`
      prints nothing after both runs (a kill of the daemon's filter is
      logged as `type=1326` with `sig=31`);
    - **warm and cold create timings**: the `WARM` and `COLD` lines
      `TestVMWarmPool` logs (create to first exec, per tier);
    - **memory overhead**: the lines `TestVMMemoryStaysInsideItsCgroup`
      logs per guest size (cgroup limit, idle, peak, the hypervisor's
      `VmHWM`); with 16 GB all three sizes run, and a "skipping the
      ... guest" line means the host was too small;
    - **the network device's hot-plug**: the network tests passing says
      it works; whether x86-64 needs the PCI rescan the guest setup does
      for arm64 (on x86-64 the hypervisor announces the device through
      ACPI, and the rescan is believed to find nothing new) needs one
      look inside a guest, below;
    - **how many VMs of the default size (1 CPU, 1024 MiB) fit**, below,
      both as measured and as the cgroup limits allow
      (`(MemTotal − 2 GiB) / 1096 MiB`, 1096 MiB being the cgroup limit of
      a 1024 MiB guest).

    For the last two, run the daemon by hand. In one terminal:

    ```sh
    go build -o teploy-sandbox .
    sudo ./teploy-sandbox serve --driver vm --token-file /var/lib/teploy-sandbox/check/token \
      --vm-kernel /var/lib/teploy-sandbox/vm/vmlinux-x86_64 --vm-pool sbx --vm-golden sbx/golden-guestd@v1
    ```

    and in another (the daemon mints the token file on its first start):

    ```sh
    T=$(sudo cat /var/lib/teploy-sandbox/check/token)
    api() { curl -s -H "Authorization: Bearer $T" "$@"; }
    id=$(api -d '{"image":"golden","network":"open"}' http://127.0.0.1:7439/v1/runs | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
    api -N -d '{"cmd":"dmesg | grep -iE \"acpiphp|hotplug|virtio_net|pci 0000:00\""}' http://127.0.0.1:7439/v1/runs/$id/exec
    api -X DELETE http://127.0.0.1:7439/v1/runs/$id
    : > ids
    while [ "$(awk '/MemAvailable/ { print int($2 / 1024) }' /proc/meminfo)" -gt 2048 ]; do
      api -f -d '{"image":"golden"}' http://127.0.0.1:7439/v1/runs | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' >> ids || break
    done
    wc -l < ids
    for id in $(cat ids); do api -X DELETE http://127.0.0.1:7439/v1/runs/$id; done
    ```

    Record the guest's kernel lines for the device, and the daemon's
    `vm network device ready` log line for that run (`guestSetup` is the
    guest's part; on arm64 the rescan was 157 to 168 ms of it). The loop
    boots default-size VMs, idle, until the host has 2 GiB available:
    record the count, which is the measured figure. Stop the daemon with
    Ctrl-C when done.

The off-host storage tests are not part of these steps: they need an
S3-compatible service as well, and are described at the end of
"Off-host storage" above (`TestVMOffHost`).

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

(The mechanism below is the Docker driver's. Under the VM driver the
same limits hold by other means; see Guest networking.)

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

(Under the Docker driver. The VM driver's `open` tier is narrower; see
Guest networking in the VM driver section.)

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
Build for both architectures whichever one you are on
(`GOOS=linux GOARCH=amd64 go build ./...` and the same with `arm64`, and
`go vet -tags vmintegration ./...` for each): the VM driver makes system
calls by number, and CI compiles both for that reason.
Native Linux firewall fixtures need root: build a static integration test
binary with `CGO_ENABLED=0 go test -c -tags integration -o /tmp/sandbox-tests .`
and run `sudo /tmp/sandbox-tests -test.v`. Native Linux
integration covers the host firewall and the Docker peer/host/proxy boundary;
use `SBX_TEST_RUNTIME=runsc` to also verify gVisor snapshot persistence.
