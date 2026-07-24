# 5. Separate a lenient `inspect()` from the strict decoding reader

Date: 2026-07-24

Status: Accepted

## Context

Forensically interesting QCOW2 images are exactly the ones a robust reader
*rejects*: encrypted images, overlays with a backing file, external-data-file
images, extended-L2 (v3 incompat bit 4) images, and non-zlib compression. A
decode-oriented `Qcow2Reader::open` must refuse these because it cannot correctly
produce a virtual disk from them (returning zeros for unallocated clusters in a
backed image is *silently wrong* — `docs/implementation-notes.md` §3). But an
auditor still needs to state the header facts about those very images.

Evidence:
- `core/src/header.rs`: `INCOMPAT_UNSUPPORTED = INCOMPAT_EXTERNAL_DATA |
  INCOMPAT_COMPRESSION_TYPE | INCOMPAT_EXTENDED_L2`; header doc "rejects encrypted
  images, backing files, external data files, and extended L2 entries."
- `core/src/lib.rs`: `inspect()` "for forensic facts … **without** decoding it —
  works on images the reader rejects (encrypted, backing-file, etc.)"; it reads a
  generous 8 KiB window and parses `Qcow2Info` with bounds-checked leniency.
- README "Inspect without decoding (works on images the reader can't open)":
  "`inspect()` is deliberately lenient … so the auditor can speak to images the
  strict reader rejects."
- `forensic/src/lib.rs` builds its findings from `qcow2::inspect`,
  `qcow2::snapshots`, `qcow2::refcount_report` — never from a successful full
  decode.

## Decision

Expose two distinct entry points in `qcow2-core`:

- **`Qcow2Reader::open` / `open_reader`** — strict: succeeds only on images it can
  correctly decode (v2/v3, uncompressed or zlib, no backing file, no encryption,
  no external data, no extended L2); rejects the rest with a typed `Qcow2Error`.
- **`inspect()`** — lenient: parses header facts (version, backing file,
  encryption method, snapshot count, incompatible-feature bits) from a bounded
  header window and returns `Qcow2Info` even when full decode is impossible.

The auditor (`qcow2-forensic`) is built on the lenient probes, so it grades images
the strict reader would refuse.

## Consequences

- An examiner gets graded findings on an encrypted or backing-file image (the
  common real-world case) without ever needing the key or the backing chain.
- The strict reader keeps its no-silent-wrong-output guarantee: it fails loud
  rather than fabricate a virtual disk it cannot faithfully produce.
- `Qcow2Info` is a superset of "facts extractable without decoding"; the reader
  and the auditor share it, so a new header fact is added in one place.
