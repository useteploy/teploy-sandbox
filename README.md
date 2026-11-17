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
after a daemon restart, fork of a running run, destroy, and the three
network tiers with `egressAllow` (see Guest networking below).

What is refused with a 400 rather than faked:

- `warm` (no warm repo cache);
- `limits.pids` (a VM is bounded by its memory and CPUs; the task limit
  on its hypervisor is the driver's, not the caller's);
- an `image` that is neither `golden` nor a snapshot this driver took.

Also not built yet: a pool of pre-booted VMs (every create is a cold
boot), nested virtualisation inside a run, and memory reclaim policy.

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

`GET /v1/capacity` reports `driver` and `nestedVirt`.

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
  The hypervisor starts with its input, its two outputs and its tap
  open and nothing else: every other descriptor is closed at the exec,
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
- **The tap is handed over as a descriptor.** The daemon creates it in
  the run's namespace and gives the hypervisor the open file
  (`--net fd=3`). The hypervisor stays unprivileged, in its jail and in
  its own empty network namespace: it has a file descriptor, not an
  interface. The tap is not persistent, so it exists exactly as long as
  its hypervisor does.
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
