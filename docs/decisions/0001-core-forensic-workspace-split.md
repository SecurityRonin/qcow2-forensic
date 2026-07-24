# 1. Split the repo into a `qcow2-core` reader and a `qcow2-forensic` analyzer

Date: 2026-07-24

Status: Accepted

## Context

QCOW2 is a single container format (QEMU Copy-On-Write v2/v3). The fleet
constitution (`~/src/ronin-issen/CLAUDE.md` → "Crate-structure standard —
reader/analyzer split" and "Crate naming grammar", Pattern A) mandates that every
single-format container/filesystem repo ship exactly two crates: a `<x>-core`
reader (raw parsing, `Read + Seek`, no findings) and a `<x>-forensic` analyzer
(anomaly detection emitting `forensicnomicon::report::Finding`).

The repo began life as a single `qcow2` crate (`git log`: `90ddd46 test(red):
qcow2 crate`, `eececdb feat(qcow2): implement compressed cluster support`). It was
restructured into the two-member workspace by `d01605c feat: restructure into
qcow2-core + qcow2-forensic workspace (core/forensic standard)`.

A reader is built to read *valid* data robustly, so it normalizes away exactly the
detail an auditor must see (feature bits, unclean-shutdown flags, snapshot tables,
refcount inconsistencies). Bundling both concerns in one crate forces third-party
consumers who only want to decode a virtual disk to also pull the forensic model.

## Decision

Ship one workspace repo `qcow2-forensic` with two published members
(`Cargo.toml`: `members = ["core", "forensic"]`):

- **`core/` → crate `qcow2-core`** — the pure reader. Exposes `Qcow2Reader`
  (`Read + Seek` over the virtual sector stream) plus the low-level structural
  probes `inspect()`, `snapshots()`, and `refcount_report()`. Depends only on
  `thiserror` + `flate2` (and optionally `forensic-vfs`). No findings.
- **`forensic/` → crate `qcow2-forensic`** — the auditor. Consumes `qcow2-core`'s
  public API and grades header/structural facts into a `Vec<Qcow2Anomaly>` in
  detection order (`audit_path()` in `forensic/src/lib.rs` calls `qcow2::inspect`,
  `qcow2::snapshots`, `qcow2::refcount_report`). Each `Qcow2Anomaly` carries a
  `severity()` and implements `forensicnomicon::report::Observation`; the consumer
  converts to `report::Finding`s via `.to_finding(source)` (ADR 0006). The crate
  emits no `Finding`s itself and does not severity-sort the output.

A `fuzz/` member exists as a separate `publish = false` workspace for the
`cargo fuzz` harness. No end-user binary lives here — the CLI surface is
`disk4n6`/Issen downstream.

## Consequences

- A consumer that only needs to decode a QCOW2 virtual disk depends on
  `qcow2-core` alone and never pulls the `forensicnomicon` report model.
- The repo name keeps the `-forensic` headline even though it also holds the
  reader, per the Pattern A convention.
- The two crates version independently (`qcow2-core` 0.3.x, `qcow2-forensic`
  0.3.0), published via release-plz (ADR 0007).
- This is a LIBRARY-tier repo: it is linked, never run by an examiner directly.
