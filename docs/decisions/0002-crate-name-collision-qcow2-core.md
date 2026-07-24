# 2. Publish the reader as `qcow2-core` while keeping the `qcow2` import path

Date: 2026-07-24

Status: Accepted

## Context

The bare crate name `qcow2` is already taken on crates.io by an unrelated
third party. The fleet naming grammar (`~/src/ronin-issen/CLAUDE.md` → "Crate
naming grammar" and "Naming / imports") covers this case: if the bare `<x>` name
is taken by an obscure third party we can coexist with, publish the reader as
`<x>-core` but preserve the ergonomic import path with `[lib] name = "<x>"`, so
consumers still write `use <x>::…`.

Evidence: `core/Cargo.toml` — `name = "qcow2-core"`, `[lib] name = "qcow2"`, with
the inline comment "The crates.io name `qcow2` is taken (third-party), so we
publish the reader as `qcow2-core` while keeping the ergonomic import path
`use qcow2::…`." The workspace declares the inter-crate dependency once as
`qcow2 = { path = "core", version = "0.3.1", package = "qcow2-core" }`.

## Decision

- Publish the reader crate as **`qcow2-core`** on crates.io.
- Set `[lib] name = "qcow2"` so the import path stays `use qcow2::…`
  (`core/src/lib.rs`, `forensic/src/lib.rs`, README examples all use `qcow2::`).
- Keep the analyzer crate named **`qcow2-forensic`** (the bare `-forensic`
  analyzer name is reserved for the one-reader/one-analyzer Pattern A shape).
- Reference the reader from the analyzer and fuzz members by the `package =
  "qcow2-core"` alias so the source `use qcow2::…` never changes.

## Decision context not recovered

The identity of the third-party `qcow2` crate we coexist with, and any explicit
coexistence-safety assessment, are not recorded in the repo or git history.
Rationale reconstructed from structure; original intent not recovered in
available history beyond "the name is taken."

## Consequences

- Downstream code and this repo's own modules import `qcow2::…` regardless of the
  published package name — the collision is invisible at the call site.
- A `cargo add qcow2` gets the third-party crate, not ours; consumers must
  `cargo add qcow2-core`. The README install block reflects this.
- The analyzer name `qcow2-forensic` is free and self-describing on crates.io.
