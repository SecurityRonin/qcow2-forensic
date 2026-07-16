# tests/data — QCOW2 Real-Image Corpus

The single repo-root home for this repository's test fixtures (fleet
"one repo-root `tests/data`" standard). Workspace members reach these files with a
relative path from their own `tests/`/`src/` (e.g. `core/` is one level down, so it
uses `../tests/data/...` via `CARGO_MANIFEST_DIR`).

See the fleet catalog `issen/docs/corpus-catalog.md` for the cross-repo index;
this README is the co-located per-file detail.

## Committed fixtures

### cirros-0.6.3-x86_64-disk.img

| Field        | Value |
|--------------|-------|
| Classification | REAL-ext (independent third-party artifact) |
| Format       | QCOW2 v3 (compat 1.1), zlib compression |
| Virtual size | 112 MiB |
| On-disk size | 20.7 MiB |
| Source       | CirrOS project — https://download.cirros-cloud.net/0.6.3/cirros-0.6.3-x86_64-disk.img |
| Version      | CirrOS 0.6.3 (official release, unmodified) |
| License      | Apache-2.0 (CirrOS project) — redistributable |
| MD5          | `87617e24a5e30cb3b87fda8c0764838f` |
| SHA-256      | `7d6355852aeb6dbcd191bcda7cd74f1536cfe5cbf8a10495a7283a8396e4b75b` |

CirrOS is a minimal Linux distribution purpose-built for cloud/QEMU testing. This is
the official 0.6.3 release image, unmodified — an independent real-world QCOW2 produced
by the CirrOS build system, so it cross-checks the reader against bytes we did not author.

Consumed by `core/tests/corpus.rs::cirros_committed_opens_and_has_correct_mbr`
(committed-bytes MBR check, no external tool) and the env-gated Tier-1 oracle test
`core/tests/real_images.rs::inspect_reads_real_cirros_corpus_as_clean` (differential
vs `qemu-img convert`, skips cleanly when the file or `qemu-img` is absent).

To re-download (writes to the repo-root `tests/data/`):

```sh
curl -L -o tests/data/cirros-0.6.3-x86_64-disk.img \
  https://download.cirros-cloud.net/0.6.3/cirros-0.6.3-x86_64-disk.img
```

## Generated-at-test-time fixtures (NOT committed)

`core/tests/corpus.rs` also reads QCOW2 fixtures (e.g. `sparse.qcow2`) from a directory
named by the `CORPUS_DIR` environment variable. These are SYNTHETIC images minted with
`qemu-img`, not committed here; the tests skip when `CORPUS_DIR` is unset or a file is
absent. Mint an empty sparse image with:

```sh
qemu-img create -f qcow2 "$CORPUS_DIR/sparse.qcow2" 64M
```

## In-test synthetic coverage fixtures (SYNTHETIC, built in code — no external tool)

The CI coverage gate is driven **entirely from committed bytes** — every reader
feature branch (compressed clusters, unallocated/zero clusters, seek variants,
refcount widths 1/2/4/8/16/32/64-bit, snapshot edge cases, header rejection arms)
is exercised by hand-built QCOW2 byte buffers constructed inside `#[cfg(test)]`
code, not by minting images with `qemu-img`. There are therefore **no committed
`.qcow2` fixture files** for these paths — the "generator" is the in-repo builder
function. Per the fleet Test-Data Provenance Standard, the builders are:

| Fixture (built in code) | Builder `fn` | Location |
|---|---|---|
| Minimal valid v2 image (1 data cluster) | `testutil::test_qcow2` | `core/src/testutil.rs` |
| Compressed (raw-deflate) data cluster | `tests::compressed_qcow2` | `core/src/lib.rs` |
| v2 header with arbitrary `cluster_bits`/`l1_size` | `tests::qcow2_header_bytes` | `core/src/lib.rs` |
| v3 image with a chosen refcount **width** (order 0..=6) | `tests::build_order` | `core/src/refcount.rs` |
| v3 image with a 16-bit refcount value | `tests::build` | `core/src/refcount.rs` |
| Snapshot table header + entries | `tests::header` / `tests::entry` | `core/src/snapshots.rs` |
| Header + extension-area encoder | `tests::build` / `tests::ext` | `core/src/header.rs` |

The `qemu-img`-driven differential tests (`core/tests/real_images.rs`,
`core/tests/corpus.rs` with `CORPUS_DIR`) remain the **Tier-1 correctness** path and
are env-gated / skip-when-absent — they do NOT drive the coverage number
(`deterministic-coverage-fixtures` discipline).

## Fuzz seed corpus

`fuzz/corpus/fuzz_open/` is meant to seed the cargo-fuzz `fuzz_open` target from the
committed image rather than duplicating bytes. NOTE: the checked-in symlink there points
at an external sibling path and is currently dangling; regenerate it against this repo-root
location if you run the fuzzer locally.
