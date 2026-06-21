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

Consumed by the gated tests `core/src/lib.rs::corpus_cirros_reads_match_qemu_raw_convert`
(differential vs `qemu-img convert`), `core/tests/corpus.rs::cirros_committed_opens_and_has_correct_mbr`,
and `core/tests/real_images.rs::inspect_reads_real_cirros_corpus_as_clean`. Each test
skips cleanly when the file (or `qemu-img`) is absent.

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

## Fuzz seed corpus

`fuzz/corpus/fuzz_open/` is meant to seed the cargo-fuzz `fuzz_open` target from the
committed image rather than duplicating bytes. NOTE: the checked-in symlink there points
at an external sibling path and is currently dangling; regenerate it against this repo-root
location if you run the fuzzer locally.
