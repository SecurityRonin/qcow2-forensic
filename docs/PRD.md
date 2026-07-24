# qcow2-forensic — Design, Purpose & Scope

This is a **library** repo (two published crates, no examiner-facing binary), so
this document is a design/scope note, not a PRD. The load-bearing decisions and
their rationale live in [`docs/decisions/`](decisions/); this page is the
one-paragraph-per-concern orientation for a contributor or a downstream integrator.

## Purpose

Read any QEMU/KVM/libvirt QCOW2 (v2/v3) disk image, and surface the facts an
examiner needs about it — a silently-depended-on backing file, internal snapshots
of earlier guest states, an encryption header, external data files, and QEMU's own
*dirty*/*corrupt* feature bits — as severity-graded findings on the shared
`forensicnomicon::report` model, so QCOW2 results aggregate uniformly with the rest
of a `disk-forensic` run.

## Who uses it

- **Fleet orchestration** (`disk-forensic`/`disk4n6`, Issen) — links
  `qcow2-forensic` to fold QCOW2 findings into a whole-image timeline, and links
  `qcow2-core` (optionally with the `vfs` feature) to decode the virtual disk into
  the shared VFS.
- **Rust developers** who need a pure-Rust, read-only QCOW2 reader (`Read + Seek`)
  that drops into any filesystem crate — `qcow2-core` alone, no forensic model.

## What it does

- **`qcow2-core`** — the reader.
  - `Qcow2Reader::open` / `open_reader`: `Read + Seek` over the virtual sector
    stream; two-level L1→L2 cluster lookup; v2/v3; uncompressed, sparse-zero, and
    zlib/raw-DEFLATE compressed clusters (via `flate2`).
  - `inspect()`: lenient header probe (version, backing file, encryption method,
    snapshots, incompatible-feature bits) that works on images the strict reader
    rejects (ADR 0005).
  - `snapshots()` and `refcount_report()`: structural probes the auditor grades.
  - Optional `vfs` feature: implements the `forensic-vfs` `ImageSource` contract
    (ADR 0008).
- **`qcow2-forensic`** — the auditor. `audit_path()` returns a `Vec<Qcow2Anomaly>`
  — the typed enum (BackingFile, Encrypted, InternalSnapshots, Snapshot, Dirty,
  Corrupt, ExternalDataFile, OrphanClusters, LegacyQcow1) in detection order (not
  severity-sorted). Each variant carries a `severity()` and a published `QCOW2-*`
  code and implements `forensicnomicon::report::Observation`, so a consumer
  converts it to a `report::Finding` *observation* ("consistent with …", never a
  legal conclusion) via `.to_finding(source)`.

## Scope / non-goals

The strict reader **decodes only what it can decode faithfully** and fails loud on
the rest (ADR 0005; `core/src/header.rs`):

- **Rejected for decode** (still described by `inspect()`/`audit_path()`): images
  with a backing file, encryption, an external data file, extended-L2 entries
  (v3 incompat bit 4), or non-zlib compression (`INCOMPAT_COMPRESSION_TYPE`, i.e.
  zstd).
- **Not resolved**: backing-file chains are named, never followed — reading an
  overlay's unallocated clusters from its backing image is out of scope (and doing
  it wrong would be silently wrong data; `docs/implementation-notes.md` §3).
- **Read-only**: the repo never writes to an evidence image.
- **No end-user CLI/GUI/MCP here**: the front-end is `disk4n6`/Issen downstream.

## Correctness & validation

Decoding is **differentially validated against `qemu-img convert`** (the reference
QEMU implementation) on the real CirrOS 0.6.3 cloud image; `inspect()`,
`snapshots()`, `refcount_report()`, and `audit_path()` are validated against real
qemu-img-produced backing-file, snapshot, encryption, and v1 images. The reader is
`#![forbid(unsafe_code)]`, panic-free by lint, and fuzzed (`open`/`read`/`inspect`/
`forensic` targets). The compressed-cluster bit-layout follows the QCOW2 spec, not
QEMU's C source, verified empirically (ADR 0004; `docs/implementation-notes.md` §1).
Full oracle/corpus evidence: [`docs/validation.md`](validation.md).

## Format quirks

Empirically verified format contradictions and traps (compressed-cluster split,
L1/L2 masking, `QCOW_OFLAG_ZERO`, raw-DEFLATE vs zlib) are recorded for
contributors in [`docs/implementation-notes.md`](implementation-notes.md).
