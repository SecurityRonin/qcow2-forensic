# 4. Decode compressed clusters by the QCOW2 spec bit-layout, not QEMU's C source

Date: 2026-07-24

Status: Accepted

## Context

QCOW2 stores the compressed-cluster L2 entry as a packed bit-field: a host byte
offset and a "number of 512-byte sectors − 1" count, split at a bit position
derived from `cluster_bits`. The QEMU `docs/interop/qcow2.txt` spec and the QEMU
C source (`block/qcow2.c`, `csize_shift = 40 - cluster_bits`) partition the bits
**differently**: for the default 64 KiB cluster the spec yields split = 47 while
the C formula yields split = 24. Getting this wrong silently produces truncated
or wrong-offset reads — and a past-EOF offset makes `File::read` return 0 bytes,
which `flate2` then decodes to an empty buffer that the zero-pad guard turns into
*silently wrong data* (no panic, no error).

This was the single hardest correctness decision in the reader and is documented
at length in `docs/implementation-notes.md` §1, with an empirical test against a
real CirrOS 0.6.3 image (`L2[0] = 0x4040_0000_0005_0000`): only the spec formula
(split = 47, byte offset, no ×512) decodes a valid DEFLATE stream. `git log`:
`eececdb feat(qcow2): implement compressed cluster support (raw DEFLATE)`,
`90ddd46 handle QCOW_OFLAG_ZERO`.

Two adjacent format facts are load-bearing and settled here:
- **All header/table fields are big-endian** (`core/src/header.rs`: "All fields
  are big-endian").
- **The compression is raw DEFLATE**, not zlib/gzip — `windowBits = -15`, no
  header/trailer (`docs/implementation-notes.md` §6).

## Decision

- Decode compressed clusters using the **spec** bit-layout, derived from
  `cluster_bits` at runtime (never a hardcoded constant): `split = 63 −
  cluster_bits`, `file_offset = entry & ((1<<split)−1)` as a **byte** offset with
  no ×512, `nb_sectors = ((entry >> split) & count_mask) + 1`.
- After inflating, **validate that the decompressed length equals `cluster_size`
  or return an error** — never let an empty/short inflate zero-pad into silent
  wrong data (the fail-loud rule).
- Read all fields as big-endian.
- Use the vetted third-party `flate2` crate (`flate2::read::DeflateDecoder`) for
  the raw DEFLATE codec rather than hand-rolling decompression — this is the
  fleet "never hand-roll a codec; reuse the mature crate" rule
  (`~/src/ronin-issen/CLAUDE.md`), and `flate2` is the ecosystem standard.

## Consequences

- Compressed-cluster decode matches `qemu-img convert` on the real CirrOS image
  (see `docs/validation.md`); the divergence from the QEMU C `csize_shift`
  formula is deliberate and evidence-backed.
- A future contributor must not "correct" the split to the C-source value; the
  spec formula is the tested-correct one and the reasoning is preserved in
  `docs/implementation-notes.md` §1 (an upstream spec-clarification PR candidate).
- The reader depends on `flate2` for zlib/DEFLATE; non-default compression
  (`INCOMPAT_COMPRESSION_TYPE`, i.e. zstd) is rejected rather than mis-decoded
  (see ADR 0005).
