# 3. `forbid(unsafe)`, panic-free parsers, and a fuzz target per structure

Date: 2026-07-24

Status: Accepted

## Context

`qcow2-core` and `qcow2-forensic` parse untrusted, attacker-controllable disk
images. The fleet "Security & Robustness Standard — Paranoid Gatekeeper"
(`~/src/ronin-issen/CLAUDE.md`) requires such crates to never panic, never read
out of bounds, and never trust a length field, backed by the panic-free lint
recipe and a `cargo fuzz` target per parsed structure.

Unlike the mmap-based readers in the fleet (`ewf`, `memory-forensic`), the QCOW2
reader has no reason to touch raw memory: it reads through `std::fs::File` /
`Read + Seek`, so the base `unsafe_code = "forbid"` needs no per-site downgrade.

Evidence:
- `Cargo.toml` `[workspace.lints.rust] unsafe_code = "forbid"`;
  `[workspace.lints.clippy]` denies `correctness`, `suspicious`, `unwrap_used`,
  `expect_used`, and warns `all` + `pedantic`.
- `core/src/lib.rs` / `forensic/src/lib.rs`:
  `#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]` — tests
  may unwrap; production may not.
- `core/src/header.rs`: `be_u32` / `be_u64` are bounds-checked readers that
  return `0` for out-of-range offsets ("Never panics: out-of-range reads yield
  0"); callers validate `MIN_HEADER_SIZE` up front.
- `fuzz/fuzz_targets/`: `fuzz_open`, `fuzz_read`, `fuzz_inspect`, `fuzz_forensic`
  — one target per parsing entry point plus a full-pipeline forensic target.
  `git log`: `ea13e0f fix(ci): run cargo-fuzz on nightly`, `1475a51 ci: fix fuzz
  nightly + stale target name`.

## Decision

- Keep `unsafe_code = "forbid"` workspace-wide — no `unsafe`, no exceptions, so
  the whole repo is provably free of memory-corruption from crafted input.
- Enforce panic-freedom by lint (`unwrap_used`/`expect_used = deny`) in
  production; tests opt out via the `cfg(test)` allow.
- Read every integer field through bounds-checked helpers that return 0 out of
  range, and range-check every length/offset/count from the image before use.
- Maintain a `cargo fuzz` target per parsed structure (`open`, `read`,
  `inspect`, `forensic`) that must never panic.
- Because the README leads with the *measured* "fuzzed" claim and pairs it with
  the *static* "panic-free-by-construction" posture — never a bare "panic-free"
  absolute — this matches the fleet robustness-wording rule.

## Divergence from the fleet `safe-read` standard (documented, not recovered)

The Paranoid Gatekeeper standard says fixed-width integer reads should route
through the published `safe-read` crate and NOT be hand-rolled per crate.
`qcow2-core` instead hand-rolls `be_u32`/`be_u64` in `core/src/header.rs`. The
readers are big-endian (QCOW2 is a big-endian format) whereas `safe-read` exposes
`le/be` helpers, so the divergence is not a correctness gap, but it is a DRY
divergence from the fleet single-audited-reader rule. Whether this predates the
repo's `safe-read` adoption or was a deliberate clean-room choice is not recorded.
Rationale reconstructed from structure; original intent not recovered in available
history. Migrating the header/refcount/snapshot readers onto `safe-read` (or its
`be_*` helpers) is the follow-up this ADR flags.

## Consequences

- The repo can wear the `unsafe-forbidden` trust badge honestly (it is genuinely
  `forbid`, not `deny` + allow).
- A crafted image can produce a *wrong* decode only where a length field is
  mis-validated — never a panic or OOB read — and the fuzz targets guard the
  no-panic invariant empirically.
- The hand-rolled readers remain outstanding technical debt against the
  `safe-read` DRY rule (see divergence above).
