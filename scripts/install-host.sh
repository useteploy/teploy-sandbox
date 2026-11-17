#!/usr/bin/env bash
# Prepare a host for `serve --driver vm`. Run as root, as often as you
# like: every step checks before it changes anything, and a second run
# changes nothing.
#
#   sudo scripts/install-host.sh [POOL]
#
# POOL is the ZFS pool (or dataset) run volumes live under, the daemon's
# --vm-pool; default "sbx". The pool itself is yours to create.
#
# What it sets up, and why the daemon refuses to start without each:
#
#   1. A udev rule that stops udev probing ZFS volumes for filesystems.
#      A run's disk is a block device on the host; without the rule a
#      guest that writes a filesystem signature to its disk gets links
#      under /dev/disk/by-label and by-uuid with names it chose. The
#      same rule keeps the rule files of storage tools (bcache, LVM)
#      from reading a guest's disk and acting on what they find.
#   2. /dev/kvm openable by a group (kvm) rather than by root alone.
#      Every VM's hypervisor runs under a UID of its own from a reserved
#      range (default 1879048192 and the 4095 after it, --vm-uid-base)
#      with that one supplementary group. No account is created; the
#      script checks that no account already has a UID in the range and
#      that no subordinate ID range (/etc/subuid, /etc/subgid) holds one.
#   3. cgroup v2 with the cpu, io, memory and pids controllers passed
#      down to the group the daemon keeps its VMs in (--vm-cgroup). Each
#      VM gets its own group there with a memory, task and CPU limit and
#      a limit on what it reads from and writes to its disk.
#   4. volmode=dev on the pool, so the host kernel does not scan guest
#      disks for partitions.
#
#   5. Guest networking: the ip, tc, nft and conntrack commands,
#      /dev/net/tun, network namespaces with veth links, routing rules
#      that match a port and nftables inside them (with a limit on
#      tracked connections, "ct count"), a rate on a device (a tbf
#      queue), and IPv4 forwarding (persisted in /etc/sysctl.d). Each VM with a network gets a network namespace of
#      its own, with its tap in it; a run with network "open" also gets a
#      link from that namespace to the host, and forwarding is what
#      carries its traffic on. Note that forwarding makes the host route
#      between all of its interfaces, not only for guests.
#
# Nothing has to be installed for the jail every hypervisor is started
# in (mount and PID namespaces, pivot_root, a tmpfs for its sockets, a
# seccomp filter): the daemon does that itself. The script checks that
# the kernel has seccomp filters and that this is an architecture the
# daemon has a filter for (x86-64 or arm64).
# A statically linked hypervisor binary keeps the jail free of the host's
# libraries; the script says which kind it finds.
#
# It also reports whether the kernel has Landlock, which the daemon
# requires and this script cannot install, and whether unprivileged
# processes can create user namespaces, which it leaves as it finds.
#
# Environment: SBX_VM_UID_BASE, SBX_VM_CGROUP and SBX_VM_HYPERVISOR, as
# for the daemon.
set -euo pipefail

POOL="${1:-${SBX_VM_POOL:-sbx}}"
UID_BASE="${SBX_VM_UID_BASE:-1879048192}"
UID_COUNT=4096
CGROUP="${SBX_VM_CGROUP:-/sys/fs/cgroup/teploy-sandbox-vm}"
RULE_FILE=/etc/udev/rules.d/59-teploy-zvol-noprobe.rules
KVM_RULE_FILE=/etc/udev/rules.d/59-teploy-kvm.rules
SYSCTL_FILE=/etc/sysctl.d/60-teploy-sandbox-vm.conf

changed=0
problems=0
did()  { echo "  changed: $*"; changed=$((changed + 1)); }
ok()   { echo "  ok:      $*"; }
fail() { echo "  PROBLEM: $*" >&2; problems=$((problems + 1)); }

[ "$(uname -s)" = Linux ] || { echo "install-host.sh: a Linux host is needed" >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo "install-host.sh: run as root" >&2; exit 1; }

# write_file PATH CONTENT: install a root-owned 0644 file unless it is
# already exactly that. Returns 0 when it wrote.
write_file() {
    local path="$1" content="$2"
    if [ -f "$path" ] && [ "$(cat "$path")" = "$content" ]; then
        return 1
    fi
    local tmp
    tmp="$(mktemp "$path.XXXXXX")"
    printf '%s\n' "$content" > "$tmp"
    chmod 0644 "$tmp"
    mv -f "$tmp" "$path"
    return 0
}

echo "udev: no filesystem probing of ZFS volumes"
if ! command -v udevadm >/dev/null 2>&1; then
    ok "no udev on this host; nothing probes block devices"
else
    # Sorts before 60-persistent-storage.rules, which honours the flag.
    # /dev/zvol links come from 60-zvol.rules and are not affected.
    if write_file "$RULE_FILE" "# Installed by teploy-sandbox scripts/install-host.sh. Do not probe ZFS
# volumes for filesystems, and keep the storage tools' rule files (bcache,
# LVM, kpartx, udisks) away from them: they are guests' disks.
KERNEL==\"zd*\", ENV{UDEV_DISABLE_PERSISTENT_STORAGE_RULES_FLAG}=\"1\", ENV{DM_UDEV_DISABLE_OTHER_RULES_FLAG}=\"1\""; then
        did "wrote $RULE_FILE"
        udevadm control --reload
        # Volumes that exist already keep the links they have until udev
        # looks at them again.
        udevadm trigger --subsystem-match=block --sysname-match='zd*' --action=change
        udevadm settle --timeout=60 || true
        did "reloaded udev and re-read existing ZFS volumes"
    else
        ok "$RULE_FILE"
    fi
fi

echo "kvm: /dev/kvm for an unprivileged hypervisor"
if [ ! -c /dev/kvm ]; then
    fail "/dev/kvm does not exist: this host has no KVM (in a VM, turn on nested virtualisation)"
else
    kvm_mode="$(stat -c %a /dev/kvm)"
    kvm_group="$(stat -c %G /dev/kvm)"
    if [ $((0$kvm_mode & 06)) -eq 6 ]; then
        ok "/dev/kvm is open to everyone (mode $kvm_mode)"
    elif [ $((0$kvm_mode & 060)) -eq 48 ] && [ "$kvm_group" != root ]; then
        ok "/dev/kvm is root:$kvm_group, mode $kvm_mode"
    else
        getent group kvm >/dev/null || { groupadd --system kvm; did "created group kvm"; }
        if write_file "$KVM_RULE_FILE" "# Installed by teploy-sandbox scripts/install-host.sh.
KERNEL==\"kvm\", GROUP=\"kvm\", MODE=\"0660\""; then
            did "wrote $KVM_RULE_FILE"
            udevadm control --reload
        fi
        chgrp kvm /dev/kvm
        chmod 0660 /dev/kvm
        did "/dev/kvm is now root:kvm, mode 660 (was root:$kvm_group, mode $kvm_mode)"
    fi
fi

echo "users: UIDs $UID_BASE to $((UID_BASE + UID_COUNT - 1)) for VMs"
taken="$(awk -F: -v lo="$UID_BASE" -v n="$UID_COUNT" '$3 >= lo && $3 < lo + n { print $1 "(" $3 ")" }' /etc/passwd | tr '\n' ' ')"
if [ -n "$taken" ]; then
    fail "accounts have UIDs in the VM range: $taken- choose another range with SBX_VM_UID_BASE / --vm-uid-base"
elif [ "$UID_BASE" -lt 65536 ] || [ $((UID_BASE + UID_COUNT)) -gt 2147483648 ]; then
    fail "SBX_VM_UID_BASE must be between 65536 and $((2147483648 - UID_COUNT))"
else
    ok "no account has a UID in the range"
fi
# A subordinate range lets an account's user namespaces use these IDs.
for file in /etc/subuid /etc/subgid; do
    [ -f "$file" ] || continue
    overlap="$(awk -F: -v lo="$UID_BASE" -v n="$UID_COUNT" '!/^#/ && NF == 3 && $3 > 0 && $2 < lo + n && $2 + $3 > lo { print $1 "(" $2 "+" $3 ")" }' "$file" | tr '\n' ' ')"
    if [ -n "$overlap" ]; then
        fail "$file hands out IDs in the VM range: $overlap- remove the entry or choose another range with SBX_VM_UID_BASE / --vm-uid-base"
    else
        ok "no range in $file overlaps"
    fi
done

echo "cgroups: $CGROUP with cpu, io, memory and pids"
if [ ! -f /sys/fs/cgroup/cgroup.controllers ]; then
    fail "cgroup v2 is not mounted at /sys/fs/cgroup (a legacy or hybrid hierarchy; boot with systemd.unified_cgroup_hierarchy=1)"
else
    parent="$(dirname "$CGROUP")"
    if [ ! -d "$CGROUP" ]; then
        mkdir "$CGROUP"
        did "created $CGROUP"
    fi
    has_all() { local have=" $(cat "$1") "; for c in cpu io memory pids; do case "$have" in *" $c "*) ;; *) return 1 ;; esac; done; }
    if ! has_all "$CGROUP/cgroup.controllers"; then
        # A group has the controllers its parent passes down.
        if echo "+cpu +io +memory +pids" > "$parent/cgroup.subtree_control" 2>/dev/null && has_all "$CGROUP/cgroup.controllers"; then
            did "enabled cpu, io, memory and pids in $parent/cgroup.subtree_control"
        else
            fail "$CGROUP lacks controllers (has: $(cat "$CGROUP/cgroup.controllers")); enable cpu, io, memory and pids in $parent/cgroup.subtree_control (the io controller needs CONFIG_BLK_CGROUP and CONFIG_BLK_DEV_THROTTLING)"
        fi
    fi
    if has_all "$CGROUP/cgroup.controllers"; then
        if has_all "$CGROUP/cgroup.subtree_control"; then
            ok "$CGROUP passes cpu, io, memory and pids to its children"
        elif echo "+cpu +io +memory +pids" > "$CGROUP/cgroup.subtree_control" 2>/dev/null; then
            did "$CGROUP now passes cpu, io, memory and pids to its children"
        else
            fail "cannot enable controllers in $CGROUP/cgroup.subtree_control (the group must hold no processes of its own)"
        fi
    fi
    # The cgroup filesystem does not survive a reboot. The daemon makes
    # this group again at start; what has to persist is the parent
    # passing the controllers down, which systemd does by default.
fi

echo "zfs: volmode=dev on $POOL"
if ! command -v zfs >/dev/null 2>&1; then
    fail "the zfs command is not installed"
elif ! zfs list -H -o name "$POOL" >/dev/null 2>&1; then
    fail "no ZFS pool or dataset named $POOL (create it, then run this again)"
elif [ "$(zfs get -H -o value volmode "$POOL")" = dev ]; then
    ok "volmode=dev"
else
    zfs set volmode=dev "$POOL"
    did "zfs set volmode=dev $POOL"
fi

echo "network: namespaces, taps, nftables and IPv4 forwarding for guests"
for tool in ip:iproute2 tc:iproute2 nft:nftables conntrack:conntrack; do
    if command -v "${tool%%:*}" >/dev/null 2>&1; then
        ok "the ${tool%%:*} command"
    else
        fail "the ${tool%%:*} command is not installed (package ${tool##*:})"
    fi
done
[ -c /dev/net/tun ] || modprobe tun 2>/dev/null || true
if [ -c /dev/net/tun ]; then
    ok "/dev/net/tun"
else
    fail "/dev/net/tun does not exist: the kernel has no tun/tap driver (modprobe tun)"
fi
if command -v ip >/dev/null 2>&1 && command -v nft >/dev/null 2>&1; then
    # What every run with a network is given, made once and removed: a
    # named network namespace, a veth link into it, a routing rule that
    # matches a port (how port 25 is closed without a firewall rule;
    # Linux 4.17 or newer), and a ruleset inside it.
    probe_ns="tvnprobe$$"
    probe_link="tvpprobe$$"
    probe_step=""
    try() { probe_step="$1"; shift; "$@" >/dev/null 2>&1; }
    if try "create a network namespace (ip netns add)" ip netns add "$probe_ns" &&
       try "make a veth link into it (modprobe veth)" ip link add "${probe_link:0:15}" type veth peer name uplink netns "$probe_ns" &&
       try "add a routing rule that matches a port (Linux 4.17 or newer)" ip -n "$probe_ns" rule add pref 100 ipproto tcp dport 25 unreachable &&
       try "add an unreachable route" ip -n "$probe_ns" route replace unreachable 192.0.2.0/24 &&
       try "hook a device's ingress with nftables inside it (nf_tables with the netdev family)" ip netns exec "$probe_ns" nft "add table netdev guest; add chain netdev guest ingress { type filter hook ingress device uplink priority -300; policy drop; }" &&
       try "track connections with nftables inside it (nf_conntrack)" ip netns exec "$probe_ns" nft "add table inet guest; add chain inet guest forward { type filter hook forward priority filter; policy drop; }; add rule inet guest forward ct state established,related accept" &&
       try "limit the tracked connections of a run (nftables' ct count: the nft_connlimit module)" ip netns exec "$probe_ns" nft "add rule inet guest forward ct state new ct count over 1 drop" &&
       try "put a rate on a device (tc with a tbf queue: the sch_tbf module, on some distributions in a linux-modules-extra package)" ip netns exec "$probe_ns" tc qdisc replace dev uplink root tbf rate 1mbit burst 65536b latency 50ms; then
        ok "network namespaces with veth links, port-matching routing rules, nftables with connection limits, and rate-limited devices"
    else
        fail "this kernel cannot $probe_step"
    fi
    ip link del "${probe_link:0:15}" 2>/dev/null || true
    ip netns del "$probe_ns" 2>/dev/null || true
    # Not something this script can fix: another firewall that drops
    # forwarded traffic by default has to be told to let open runs' through.
    # (An allowlist run does not pass the host's firewall at all: its
    # proxy listens inside the run's own namespace.)
    foreign="$(nft list chains 2>/dev/null | awk '$1 == "table" { t = $2 " " $3 } $1 == "chain" { c = $2 } /policy drop/ && /hook forward/ && t !~ /teploy_sbx_vm_/ { print "table " t " chain " c }' | tr '\n' ';')"
    if [ -n "$foreign" ]; then
        echo "  note:    another firewall drops forwarded traffic by default (${foreign%;}). Allow what arrives on the daemon's links (tvh*) there, or runs with network \"open\" will not reach the internet."
    fi
fi
if write_file "$SYSCTL_FILE" "# Installed by teploy-sandbox scripts/install-host.sh. The vm driver routes
# the traffic of runs with network \"open\" from their links.
net.ipv4.ip_forward = 1"; then
    did "wrote $SYSCTL_FILE"
fi
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ]; then
    ok "net.ipv4.ip_forward = 1"
else
    echo 1 > /proc/sys/net/ipv4/ip_forward
    did "net.ipv4.ip_forward is now 1"
fi

echo "hypervisor: what its jail has to hold"
HYPERVISOR="${SBX_VM_HYPERVISOR:-cloud-hypervisor}"
hypervisor_path="$(command -v "$HYPERVISOR" 2>/dev/null || true)"
if [ -z "$hypervisor_path" ]; then
    echo "  note:    $HYPERVISOR is not installed, or not on PATH (set SBX_VM_HYPERVISOR to check a path)"
elif [ "$(dd if="$hypervisor_path" bs=1 skip=1 count=3 2>/dev/null)" != ELF ]; then
    fail "$hypervisor_path is not an ELF binary: the daemon executes it directly inside a jail, where no interpreter exists"
else
    # A program header of type 3 (PT_INTERP) names a loader: the binary is
    # dynamically linked. Read straight from the file (64-bit,
    # little-endian, which is every host this driver runs on), so that
    # no binutils are needed.
    field() { od -An -v -t u"$3" -j "$2" -N "$3" "$1" | tr -d ' \n'; }
    linkage=unknown
    if [ "$(field "$hypervisor_path" 4 1)" = 2 ] && [ "$(field "$hypervisor_path" 5 1)" = 1 ]; then
        phoff="$(field "$hypervisor_path" 32 8)"
        phentsize="$(field "$hypervisor_path" 54 2)"
        phnum="$(field "$hypervisor_path" 56 2)"
        linkage=static
        i=0
        while [ "$i" -lt "$phnum" ]; do
            [ "$(field "$hypervisor_path" $((phoff + i * phentsize)) 4)" = 3 ] && linkage=dynamic
            i=$((i + 1))
        done
    fi
    case "$linkage" in
        static)  ok "$hypervisor_path is statically linked: its jail holds nothing of the host but the binary itself" ;;
        dynamic) echo "  note:    $hypervisor_path is dynamically linked: its jail will also hold the host's library directories, read-only. The upstream static build needs nothing of the host." ;;
        *)       echo "  note:    cannot tell how $hypervisor_path is linked; the daemon says so in its log at start if the jail has to hold the host's libraries" ;;
    esac
fi

echo "kernel: seccomp filters, and a tmpfs for each VM's sockets"
case "$(uname -m)" in
    x86_64|aarch64) ok "the daemon has a seccomp filter for $(uname -m)" ;;
    *) fail "the daemon has no seccomp filter for $(uname -m): the vm driver runs on x86-64 and arm64" ;;
esac
# Seccomp: 2 in a process's status only shows for a filtered process; the
# list of actions is there on every kernel that has filters (4.14).
if grep -qw kill_process /proc/sys/kernel/seccomp/actions_avail 2>/dev/null; then
    ok "the kernel has seccomp filters that can kill a process"
else
    fail "the kernel has no seccomp filters (CONFIG_SECCOMP_FILTER, Linux 4.14 or newer; see /proc/sys/kernel/seccomp/actions_avail)"
fi
probe_dir="$(mktemp -d /run/teploy-sockdir-probe.XXXXXX)"
if mount -t tmpfs -o mode=0700,size=64k,nr_inodes=16,nosuid,nodev,noexec tmpfs "$probe_dir" 2>/dev/null; then
    umount "$probe_dir"
    ok "a tmpfs can be mounted for a VM's sockets"
else
    fail "cannot mount a tmpfs under /run: the daemon gives every VM one for its sockets (it needs CAP_SYS_ADMIN and a mount namespace it may change; not an unprivileged container)"
fi
rmdir "$probe_dir" 2>/dev/null || true

echo "kernel: Landlock"
if [ -r /sys/kernel/security/lsm ] && tr ',' '\n' < /sys/kernel/security/lsm | grep -qx landlock; then
    ok "Landlock is active"
else
    fail "Landlock is not active: it needs Linux 5.13 or newer and \"landlock\" in the lsm= kernel parameter (see /sys/kernel/security/lsm)"
fi

# Reported, not changed: other software on the host may need them. The
# daemon's own seccomp filter keeps a hypervisor from creating any
# namespace, whatever this setting is; a host that also turns user
# namespaces off does not depend on that filter for it.
echo "kernel: user namespaces for unprivileged processes"
sysctl_value() { cat "/proc/sys/$1" 2>/dev/null || true; }
if [ "$(sysctl_value user/max_user_namespaces)" = 0 ]; then
    ok "user namespaces are off (user.max_user_namespaces = 0)"
elif [ "$(sysctl_value kernel/unprivileged_userns_clone)" = 0 ]; then
    ok "unprivileged processes cannot create user namespaces (kernel.unprivileged_userns_clone = 0)"
elif [ "$(sysctl_value kernel/apparmor_restrict_unprivileged_userns)" = 1 ]; then
    ok "AppArmor confines the user namespaces of unprivileged processes (kernel.apparmor_restrict_unprivileged_userns = 1)"
else
    echo "  note:    unprivileged processes can create user namespaces. If nothing on this host needs them (rootless containers and browser sandboxes do), turn them off: sysctl -w user.max_user_namespaces=0, and persist it in /etc/sysctl.d."
fi

echo
if [ "$problems" -gt 0 ]; then
    echo "install-host.sh: $problems problem(s) left for you to fix; $changed change(s) made" >&2
    exit 1
fi
echo "install-host.sh: host is ready for the vm driver ($changed change(s) made)"
