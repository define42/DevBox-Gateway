#!/usr/bin/env bash
# Runs inside virt-tools-container, with source/recipe mounted read-only.
set -euo pipefail
output_owner=$1
trap 'chown -R -- "$output_owner" /build' EXIT

qemu-img create -f qcow2 /build/disk.img 16G
virt-resize --format qcow2 --output-format qcow2 --expand /dev/sda1 \
    /source.img /build/disk.img
virt-customize --format qcow2 -a /build/disk.img --memsize 2048 \
    --commands-from-file /recipe/run-command.virt
virt-sparsify --in-place --format qcow2 /build/disk.img
qemu-img convert -f qcow2 -c -O qcow2 /build/disk.img /build/desktop.img
qemu-img check -f qcow2 /build/desktop.img
# convert produces a self-contained disk; retain its format details in the log.
qemu-img info --output=json /build/desktop.img
