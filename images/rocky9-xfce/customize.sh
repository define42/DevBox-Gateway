#!/usr/bin/env bash
# Runs inside virt-tools-container, with source/recipe mounted read-only.
set -euo pipefail
output_owner=$1
trap 'chown -R -- "$output_owner" /build' EXIT

qemu-img create -f qcow2 /build/disk.img 16G
# Expand the plain root partition; grow its XFS filesystem with the guest's
# xfsprogs because the builder appliance does not provide XFS resize tools.
virt-resize --format qcow2 --output-format qcow2 --no-expand-content --expand /dev/sda4 \
    /source.img /build/disk.img
# Leave empty machine-id files after cloud-init cleanup. Rocky's --machine-id
# option deletes /etc/machine-id, which breaks D-Bus during early read-only boot.
virt-customize --format qcow2 -a /build/disk.img --memsize 2048 \
    --commands-from-file /recipe/run-command.virt \
    --upload /build/sauronagent.rpm:/tmp/sauronagent.rpm \
    --run-command 'dnf -y install /tmp/sauronagent.rpm && rm /tmp/sauronagent.rpm' \
    --run-command 'systemd-sysusers /usr/lib/sysusers.d/sauronagent.conf' \
    --run-command 'systemd-tmpfiles --create /usr/lib/tmpfiles.d/sauronagent.conf' \
    --run-command 'systemctl enable sauronagent.service' \
    --run-command 'sauronagent -check-config' \
    --run-command 'command -v cloud-init && command -v python3 && command -v startxfce4 && getent group xrdp' \
    --run-command 'systemctl is-enabled xrdp.service sauronagent.service NetworkManager.service firewalld.service' \
    --run-command 'firewall-offline-cmd --check-config && firewall-offline-cmd --get-default-zone | grep -qx xrdp' \
    --run-command 'dnf clean all && rm -rf /var/cache/dnf/*' \
    --run-command 'cloud-init clean --logs' \
    --run-command 'truncate -s 0 /etc/machine-id /var/lib/dbus/machine-id' \
    --selinux-relabel
virt-sparsify --in-place --format qcow2 /build/disk.img
qemu-img convert -f qcow2 -c -O qcow2 /build/disk.img /build/desktop.img
qemu-img check -f qcow2 /build/desktop.img
qemu-img info --output=json /build/desktop.img
