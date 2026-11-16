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
#      under /dev/disk/by-label and by-uuid with names it chose.
#   2. /dev/kvm openable by a group (kvm) rather than by root alone.
#      Every VM's hypervisor runs under a UID of its own from a reserved
#      range (default 1879048192 and the 4095 after it, --vm-uid-base)
#      with that one supplementary group. No account is created; the
#      script checks that no account already has a UID in the range.
#   3. cgroup v2 with the cpu, memory and pids controllers passed down to
#      the group the daemon keeps its VMs in (--vm-cgroup). Each VM gets
#      its own group there with a memory, task and CPU limit.
#   4. volmode=dev on the pool, so the host kernel does not scan guest
#      disks for partitions.
#
#   5. Guest networking: the ip, nft and conntrack commands, /dev/net/tun,
#      the dummy interface type, and IPv4 forwarding (persisted in
#      /etc/sysctl.d). Each VM with a network gets a tap of its own that
#      the daemon creates and filters; forwarding is what carries the
#      traffic of runs with network "open". Note that it makes the host
#      route between all of its interfaces, not only for guests.
#
# It also reports whether the kernel has Landlock, which the daemon
# requires and this script cannot install.
#
# Environment: SBX_VM_UID_BASE and SBX_VM_CGROUP, as for the daemon.
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
# volumes for filesystems: they are guests' disks.
KERNEL==\"zd*\", ENV{UDEV_DISABLE_PERSISTENT_STORAGE_RULES_FLAG}=\"1\""; then
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

echo "cgroups: $CGROUP with cpu, memory and pids"
if [ ! -f /sys/fs/cgroup/cgroup.controllers ]; then
    fail "cgroup v2 is not mounted at /sys/fs/cgroup (a legacy or hybrid hierarchy; boot with systemd.unified_cgroup_hierarchy=1)"
else
    parent="$(dirname "$CGROUP")"
    if [ ! -d "$CGROUP" ]; then
        mkdir "$CGROUP"
        did "created $CGROUP"
    fi
    has_all() { local have=" $(cat "$1") "; for c in cpu memory pids; do case "$have" in *" $c "*) ;; *) return 1 ;; esac; done; }
    if ! has_all "$CGROUP/cgroup.controllers"; then
        # A group has the controllers its parent passes down.
        if echo "+cpu +memory +pids" > "$parent/cgroup.subtree_control" 2>/dev/null && has_all "$CGROUP/cgroup.controllers"; then
            did "enabled cpu, memory and pids in $parent/cgroup.subtree_control"
        else
            fail "$CGROUP lacks controllers (has: $(cat "$CGROUP/cgroup.controllers")); enable cpu, memory and pids in $parent/cgroup.subtree_control"
        fi
    fi
    if has_all "$CGROUP/cgroup.controllers"; then
        if has_all "$CGROUP/cgroup.subtree_control"; then
            ok "$CGROUP passes cpu, memory and pids to its children"
        elif echo "+cpu +memory +pids" > "$CGROUP/cgroup.subtree_control" 2>/dev/null; then
            did "$CGROUP now passes cpu, memory and pids to its children"
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

echo "network: taps, nftables and IPv4 forwarding for guests"
for tool in ip:iproute2 nft:nftables conntrack:conntrack; do
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
if command -v ip >/dev/null 2>&1; then
    # The gateway address guests reach the host at lives on a dummy
    # interface; make and remove one to see that the kernel can.
    probe="tvprobe$$"
    if ip link add "$probe" type dummy 2>/dev/null; then
        ip link del "$probe"
        ok "dummy interfaces"
    else
        fail "the kernel cannot create a dummy interface (modprobe dummy)"
    fi
fi
if command -v nft >/dev/null 2>&1; then
    probe="teploy_sbx_probe_$$"
    if nft "add table netdev $probe; add chain netdev $probe c { type filter hook ingress device lo priority 0; }" 2>/dev/null; then
        nft delete table netdev "$probe"
        ok "nftables with ingress hooks"
    else
        nft delete table netdev "$probe" 2>/dev/null || true
        fail "nftables cannot hook a device's ingress (the kernel needs nf_tables with the netdev family)"
    fi
    # Not something this script can fix: another firewall that drops by
    # default has to be told to let guests' traffic through.
    foreign="$(nft list chains 2>/dev/null | awk '$1 == "table" { t = $2 " " $3 } $1 == "chain" { c = $2 } /policy drop/ && (/hook input/ || /hook forward/) && t !~ /teploy_sbx_vm_/ { print "table " t " chain " c }' | tr '\n' ';')"
    if [ -n "$foreign" ]; then
        echo "  note:    another firewall drops by default (${foreign%;}). Allow traffic arriving on the daemon's taps (tv*) there: to the gateway address for the allowlist tier, forwarded for the open tier."
    fi
fi
if write_file "$SYSCTL_FILE" "# Installed by teploy-sandbox scripts/install-host.sh. The vm driver routes
# the traffic of runs with network \"open\" from their taps.
net.ipv4.ip_forward = 1"; then
    did "wrote $SYSCTL_FILE"
fi
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ]; then
    ok "net.ipv4.ip_forward = 1"
else
    echo 1 > /proc/sys/net/ipv4/ip_forward
    did "net.ipv4.ip_forward is now 1"
fi

echo "kernel: Landlock"
if [ -r /sys/kernel/security/lsm ] && tr ',' '\n' < /sys/kernel/security/lsm | grep -qx landlock; then
    ok "Landlock is active"
else
    fail "Landlock is not active: it needs Linux 5.13 or newer and \"landlock\" in the lsm= kernel parameter (see /sys/kernel/security/lsm)"
fi

echo
if [ "$problems" -gt 0 ]; then
    echo "install-host.sh: $problems problem(s) left for you to fix; $changed change(s) made" >&2
    exit 1
fi
echo "install-host.sh: host is ready for the vm driver ($changed change(s) made)"
