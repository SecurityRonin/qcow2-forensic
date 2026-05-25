#!/usr/bin/env bash
# Generate QCOW2 corpus images using qemu-img, and download CirrOS.
# Requires: qemu-utils (sudo apt-get install -y qemu-utils)
set -euo pipefail

DEST="$(cd "$(dirname "$0")" && pwd)"

# Minimal sparse QCOW2 created by qemu-img
qemu-img create -f qcow2 "${DEST}/sparse.qcow2" 10M

# CirrOS 0.6.3 — tiny (14 MiB), Apache-2.0 licensed, real multi-cluster QCOW2
# produced by a completely independent toolchain from our parser.
curl -fLo "${DEST}/cirros-0.6.3-x86_64-disk.img" \
  "https://download.cirros-cloud.net/0.6.3/cirros-0.6.3-x86_64-disk.img"
