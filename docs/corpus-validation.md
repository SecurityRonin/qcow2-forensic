# QCOW2 Corpus Validation

Byte-level differential tests comparing `Qcow2Reader` output against
`qemu-img convert -O raw` (QEMU 11.0.0, macOS/Apple Silicon).

## Test Environment

| Component | Version |
|-----------|---------|
| QEMU | 11.0.0 (Homebrew, `/opt/homebrew/bin/qemu-img`) |
| OS | macOS (Apple Silicon) |
| Rust | (see `rust-toolchain.toml`) |
| snap crate | n/a — QCOW2 uses zlib DEFLATE |

## Corpus Files

### cirros-0.6.3-x86_64-disk.img

| Field | Value |
|-------|-------|
| Format | QCOW2 v3 (`compat=1.1`), zlib compressed clusters |
| Virtual size | 112 MiB (117,440,512 bytes) |
| On-disk size | ~20.7 MiB |
| Source | https://download.cirros-cloud.net/0.6.3/cirros-0.6.3-x86_64-disk.img |
| License | Apache 2.0 (CirrOS project) |
| Creator | Official CirrOS 0.6.3 release, unmodified |

This image is the canonical QEMU/cloud test distribution. It exercises
compressed cluster reads across L1→L2 cluster lookup on a real filesystem.

## Test Results

### `reads_match_qemu_raw_convert` (synthetic)

Synthetic 1 MiB QCOW2 written by this library's test helpers; compared
byte-for-byte against `qemu-img convert -O raw`. **PASS** — validates the
test helper itself produces spec-compliant output.

### `corpus_cirros_reads_match_qemu_raw_convert` (real image)

Full byte scan of `cirros-0.6.3-x86_64-disk.img` at 64 KiB stride +
near-end 512-byte read, compared against `qemu-img convert -O raw`.

**PASS** — all sampled offsets match qemu-img reference.

Exercises: zlib-compressed cluster decoding, L1→L2 indirection,
unallocated (zero) cluster regions.

## Validation Coverage

| Feature | Covered | Notes |
|---------|---------|-------|
| Uncompressed clusters | Yes | synthetic test |
| Compressed clusters (zlib) | Yes | CirrOS image |
| Unallocated (zero) clusters | Yes | CirrOS has sparse regions |
| Backing files | No | Not in current corpus |
| QCOW2 v2 | No | CirrOS is v3 only |
| Encryption | No | Not in scope |

## Reproducing

```sh
# Download corpus
curl -L -o qcow2/tests/data/cirros-0.6.3-x86_64-disk.img \
  https://download.cirros-cloud.net/0.6.3/cirros-0.6.3-x86_64-disk.img

# Run validation tests
cargo test
```
