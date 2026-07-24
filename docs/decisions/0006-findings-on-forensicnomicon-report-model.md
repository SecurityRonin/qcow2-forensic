# 6. Dependency direction: the auditor consumes core and emits `forensicnomicon` findings

Date: 2026-07-24

Status: Accepted

## Context

The fleet aggregates every analyzer's output into one `forensicnomicon::report`
model so ORCHESTRATION (Issen / `disk4n6`) and a future GUI render findings
uniformly (`~/src/ronin-issen/CLAUDE.md` → "The Reporting Model"). An analyzer
keeps its own typed anomaly enum (domain knowledge) and converts to canonical
`Finding`s; it must never invent a bespoke `XxxAnalysis` type.

The fleet also allows `-forensic` to reach *below* `-core` when the reader's
happy-path API hides the anomaly. Here the opposite is true: `qcow2-core`
deliberately surfaces the low-level structural detail the auditor needs
(`inspect()`, `snapshots()`, `refcount_report()`), so the auditor stays on
core's public API rather than re-parsing raw bytes.

Evidence:
- `forensic/Cargo.toml` depends on `qcow2` (= `qcow2-core`) + `forensicnomicon`.
- `forensic/src/lib.rs`: `Qcow2Anomaly` enum (BackingFile, Encrypted,
  InternalSnapshots, Snapshot, Dirty, Corrupt, ExternalDataFile, OrphanClusters,
  LegacyQcow1) with a single-source-of-truth `severity()`; each converts to a
  `forensicnomicon::report::Finding` observation.
- README anomaly table: codes `QCOW2-CORRUPT`, `QCOW2-BACKING-FILE`,
  `QCOW2-ENCRYPTED`, `QCOW2-EXTERNAL-DATA`, `QCOW2-INTERNAL-SNAPSHOTS`,
  `QCOW2-DIRTY` (plus `QCOW2-SNAPSHOT`, `QCOW2-ORPHAN-CLUSTERS`, `QCOW2-QCOW1`).
- `git log`: `4f7d502 feat(orphan-finding): QCOW2-ORPHAN-CLUSTERS from refcount
  report`, `cf37b8c feat(refcount): refcount-based orphan-cluster detection
  (clean-room)`, `64d40b8 fix: surface refcount-table read I/O failure instead of
  reporting empty` — the fail-loud-not-empty fix.

## Decision

- `qcow2-forensic` depends **down** on `qcow2-core` (for structural facts) and on
  `forensicnomicon` (for the report model). It imports no container/filesystem
  crate and produces no bespoke analysis type.
- Keep the typed `Qcow2Anomaly` enum as the domain vocabulary, with `severity()`
  as the single source of truth, and convert each variant to a canonical
  `Finding` carrying a scheme-prefixed `SCREAMING-KEBAB` `code`
  (`QCOW2-…`) that is a published, never-reused contract.
- Emit orphan-cluster findings from `qcow2-core::refcount_report` — a
  clean-room refcount walk that core exposes precisely so the auditor can flag
  allocated-but-unreferenced clusters (candidate deleted/orphaned guest data).
- Frame every finding as an *observation* ("consistent with …"), never a legal
  conclusion; the examiner draws the conclusion (README + `forensic/src/lib.rs`
  doc-comment).
- On any structural read error (e.g. a refcount-table I/O failure), **error
  loudly** rather than report an empty/clean result (`64d40b8`).

## Consequences

- QCOW2 findings aggregate uniformly with the rest of a `disk-forensic` run on
  the shared model; no adapter is needed in ORCHESTRATION.
- Adding a new anomaly is a `Qcow2Anomaly` variant + a new `QCOW2-*` code; shipped
  codes are frozen (additive evolution only).
- Because core surfaces the structural probes, the auditor never re-implements
  header/snapshot/refcount parsing — the "-forensic may go below -core" escape
  hatch is unnecessary here.
