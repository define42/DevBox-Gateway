#!/usr/bin/env bash
# Boot a disposable overlay; requires qemu-system-x86_64, qemu-img and xorriso.
set -euo pipefail

if (( $# < 1 || $# > 2 )); then
    echo "Usage: $0 IMAGE [TIMEOUT_SECONDS=900]" >&2
    exit 2
fi
timeout_seconds=${2:-900}
if [[ ! $timeout_seconds =~ ^[1-9][0-9]*$ ]]; then
    echo "TIMEOUT_SECONDS must be a positive integer." >&2
    exit 2
fi
for tool in qemu-system-x86_64 qemu-img xorriso timeout realpath; do
    if ! command -v "$tool" >/dev/null; then
        echo "Missing $tool; install qemu-system-x86, qemu-utils, xorriso and coreutils." >&2
        exit 1
    fi
done
image_path=$(realpath -e -- "$1")
if [[ ! -f $image_path || ! -r $image_path ]]; then
    echo "Image must be a readable regular QCOW2 file: $image_path" >&2
    exit 1
fi

work_dir=$(mktemp -d /tmp/devbox-image-smoke.XXXXXX)
qemu_pid=
cleanup() {
    status=$?
    trap - EXIT
    if [[ -n $qemu_pid ]]; then
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    if (( status != 0 )) && [[ -f $work_dir/serial.log ]]; then
        echo "Image smoke test failed; guest serial output follows:" >&2
        cat "$work_dir/serial.log" >&2
    fi
    rm -rf -- "$work_dir"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

qemu-img create -q -f qcow2 -F qcow2 -b "$image_path" "$work_dir/disk.qcow2"
mkdir "$work_dir/seed"
cat >"$work_dir/seed/meta-data" <<EOF
instance-id: $(basename "$work_dir")
local-hostname: devbox-image-smoke
EOF
cat >"$work_dir/seed/network-config" <<'EOF'
version: 2
ethernets:
  ethernet:
    match:
      name: "en*"
    dhcp4: true
    dhcp6: false
    accept-ra: false
EOF
cat >"$work_dir/seed/user-data" <<'EOF'
#cloud-config
users: []
disable_root: true
ssh_pwauth: false
package_update: false
package_upgrade: false
write_files:
  - path: /usr/local/sbin/devbox-image-smoke
    permissions: '0700'
    content: |
      #!/bin/sh
      set -eu
      exec >/dev/ttyS0 2>&1
      finish() {
        status=$?
        trap - EXIT
        if [ "$status" -eq 0 ]; then
          echo DEVBOX_IMAGE_SMOKE_OK
        else
          echo DEVBOX_IMAGE_SMOKE_FAILED
          timeout 15s cloud-init status --long || true
          systemctl status --no-pager xrdp.service sauronagent.service || true
          journalctl --no-pager -n 100 -u cloud-final.service -u xrdp.service || true
        fi
        systemctl poweroff --no-block
        exit "$status"
      }
      trap finish EXIT
      echo 'Checking cloud-init completion'
      # This unit already runs after cloud-final. Avoid --wait, which retries
      # systemd queries indefinitely on some cloud-init versions.
      timeout 30s cloud-init status --long
      echo 'Checking XRDP and XFCE'
      systemctl is-active --quiet xrdp.service
      command -v startxfce4
      test -x /etc/xrdp/startwm.sh
      echo 'Checking SauronAgent installation and built-in configuration'
      test "$(systemctl is-enabled sauronagent.service)" = enabled
      /usr/bin/sauronagent -check-config
  - path: /etc/systemd/system/devbox-image-smoke.service
    permissions: '0644'
    content: |
      [Unit]
      Description=Verify the DevBox desktop image
      After=cloud-final.service xrdp.service
      [Service]
      Type=oneshot
      ExecStart=/usr/local/sbin/devbox-image-smoke
runcmd:
  - [systemctl, daemon-reload]
  # Queue the check after cloud-final; waiting here would deadlock cloud-init.
  - [systemctl, start, --no-block, devbox-image-smoke.service]
EOF
xorriso -as mkisofs -quiet -volid cidata -joliet -rock \
    -output "$work_dir/seed.iso" "$work_dir/seed" >/dev/null 2>&1

accel=tcg
cpu=max
if [[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]; then
    accel=kvm
    cpu=host
fi
echo "Booting $image_path with $accel (timeout ${timeout_seconds}s)."
qemu_status=0
timeout --signal=TERM --kill-after=10s "${timeout_seconds}s" \
    qemu-system-x86_64 -machine q35 -accel "$accel" -cpu "$cpu" \
    -m 4096 -smp 2 -display none -vga virtio -monitor none -serial stdio -no-reboot \
    -drive "file=$work_dir/disk.qcow2,format=qcow2,if=virtio" \
    -drive "file=$work_dir/seed.iso,format=raw,if=virtio,readonly=on" \
    -netdev user,id=smokenet,restrict=on -device virtio-net-pci,netdev=smokenet \
    </dev/null >"$work_dir/serial.log" 2>&1 &
qemu_pid=$!
wait "$qemu_pid" || qemu_status=$?
qemu_pid=
if (( qemu_status != 0 )); then
    echo "QEMU exited with status $qemu_status (124 means the boot timed out)." >&2
    exit 1
fi
if ! grep -Eq $'^DEVBOX_IMAGE_SMOKE_OK\r?$' "$work_dir/serial.log"; then
    echo "The guest shut down without passing all image checks." >&2
    exit 1
fi
echo "Image smoke test passed: cloud-init, XRDP, XFCE and SauronAgent configuration."
