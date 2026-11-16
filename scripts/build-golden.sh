#!/usr/bin/env bash
# Build a golden image for the VM driver: clone a base volume, install
# teploy-guestd into it as a systemd service, and snapshot the result.
# The daemon boots every run from that snapshot (serve --vm-golden).
#
#   sudo scripts/build-golden.sh --from POOL/base@snap --to POOL/golden-guestd@v1 \
#        --guestd ./teploy-guestd
#
# The base is a zvol holding a bootable Linux root filesystem with systemd
# (for example a cloud image written to the volume, cloud-init disabled).
# The base snapshot is only cloned, never modified. The new volume stays a
# clone of it, so the base cannot be destroyed while the golden exists.
#
# Build the agent for the guest's architecture first:
#   CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o teploy-guestd ./cmd/teploy-guestd
set -euo pipefail

from="" to="" guestd="" part="1"
while [ $# -gt 0 ]; do
  case "$1" in
    --from) from="$2"; shift 2 ;;
    --to) to="$2"; shift 2 ;;
    --guestd) guestd="$2"; shift 2 ;;
    --root-partition) part="$2"; shift 2 ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "build-golden: unknown argument: $1" >&2; exit 2 ;;
  esac
done

die() { echo "build-golden: $*" >&2; exit 1; }

[ -n "$from" ] && [ -n "$to" ] && [ -n "$guestd" ] || die "--from, --to and --guestd are required (see --help)"
[ "$(id -u)" = 0 ] || die "must run as root (zfs and mount)"
command -v zfs >/dev/null || die "zfs not found"
[ -f "$guestd" ] || die "no agent binary at $guestd"
case "$from" in *@*) ;; *) die "--from must be a snapshot (POOL/volume@name)" ;; esac
case "$to" in *@*) ;; *) die "--to must be a snapshot (POOL/volume@name)" ;; esac
volume="${to%@*}"
zfs list -H -t snapshot "$from" >/dev/null 2>&1 || die "base snapshot $from does not exist"
if zfs list -H "$volume" >/dev/null 2>&1; then
  die "$volume already exists; pick a new --to (a golden image is never rebuilt in place: runs are clones of it)"
fi

mnt=""
created=0
cleanup() {
  status=$?
  if [ -n "$mnt" ]; then
    mountpoint -q "$mnt" && umount "$mnt"
    rmdir "$mnt" 2>/dev/null || true
  fi
  if [ "$status" -ne 0 ] && [ "$created" = 1 ]; then
    echo "build-golden: failed; removing the half-built $volume" >&2
    zfs destroy -r "$volume" || true
  fi
  exit "$status"
}
trap cleanup EXIT

zfs clone "$from" "$volume"
created=1
# Resolve the kernel's own partition node. The /dev/zvol/...-partN links
# are made by a udev helper that has been seen to mislabel partitions
# numbered above 9 as -part1, so they are not trusted here.
disk=""
for _ in $(seq 1 200); do
  disk="$(readlink -f "/dev/zvol/$volume" 2>/dev/null || true)"
  [ -b "$disk" ] && [ -b "${disk}p${part}" ] && break
  sleep 0.05
done
[ -b "$disk" ] || die "/dev/zvol/$volume did not appear"
device="${disk}p${part}"
[ -b "$device" ] || die "$device did not appear (wrong --root-partition?)"

mnt="$(mktemp -d)"
mount "$device" "$mnt"
[ -d "$mnt/etc/systemd/system" ] || die "$device does not look like a systemd root filesystem"

install -D -m 0755 "$guestd" "$mnt/usr/local/bin/teploy-guestd"
cat > "$mnt/etc/systemd/system/teploy-guestd.service" <<'UNIT'
[Unit]
Description=Teploy sandbox guest agent
After=systemd-modules-load.service

[Service]
ExecStart=/usr/local/bin/teploy-guestd
Restart=always
RestartSec=1
# Every command a run executes is a child of this service.
TasksMax=infinity
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT
mkdir -p "$mnt/etc/systemd/system/multi-user.target.wants"
ln -sf ../teploy-guestd.service "$mnt/etc/systemd/system/multi-user.target.wants/teploy-guestd.service"
# The transport that carries the host's connections; the agent also loads
# it itself, this just has it ready earlier.
mkdir -p "$mnt/etc/modules-load.d"
echo vmw_vsock_virtio_transport > "$mnt/etc/modules-load.d/teploy-guestd.conf"
mkdir -p "$mnt/work"

sync
umount "$mnt"
rmdir "$mnt"
mnt=""

zfs snapshot "$to"
echo "build-golden: $to is ready (serve --driver vm --vm-golden $to)"
