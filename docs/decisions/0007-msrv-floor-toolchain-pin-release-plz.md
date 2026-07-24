# 7. Low published MSRV, a pinned dev toolchain, and release-plz for publishing

Date: 2026-07-24

Status: Accepted

## Context

The fleet MSRV/toolchain policy (`~/src/ronin-issen/CLAUDE.md` and
`~/.claude/CLAUDE.core.md` → "Rust MSRV & Toolchain Policy") separates the **dev
toolchain** (pinned to current stable, one version fleet-wide) from the **declared
MSRV** of published libraries (kept low and CI-verified — a downstream
compatibility promise). Library crates release via **release-plz** (PR-based, on
merge to `main`), not a hand-cut version bump.

Evidence:
- `rust-toolchain.toml`: `channel = "1.96.0"`, `components = ["clippy",
  "rustfmt"]` (`git log`: `762ce47 chore: pin toolchain to 1.96.0 (fleet
  toolchain policy)`) — the dev/CI toolchain, single source of truth, with
  components declared in the toml so `@stable` CI jobs don't lose them.
- `Cargo.toml` `[workspace.package] rust-version = "1.85"` — the declared MSRV
  floor inherited by both published crates (`edition = "2021"`).
- `release-plz.toml` + `git log`: `5f3b2a6 chore(release): adopt release-plz for
  library publishing (fleet standard)`, `216972d ci(release-plz): set
  git_tag_name to <crate>-vX.Y.Z form (avoid v* binary-tag collision)`,
  `f4893b4 ci: bootstrap cargo-vet with aggregate audit imports`.

## Decision

- **Dev/CI toolchain** pinned to the fleet stable (`1.96.0`) via
  `rust-toolchain.toml`, with `clippy`/`rustfmt` declared in the toml.
- **Declared MSRV** = `1.85` for both published library crates — decoupled from
  the dev pin, verified as the downstream-facing floor.
- **Publish via release-plz**: per-crate SemVer bumps computed from
  conventional-commit types, a release PR whose merge publishes, and
  `git_tag_name = "{{ package }}-v{{ version }}"` so release-plz's per-crate tags
  never collide with the `v[0-9]*` binary-release tag glob.

## Decision context not recovered

The fleet's typical published-library MSRV floor is `1.75`/`1.80`; this repo
declares `1.85`, which is higher. The specific driver (a transitive dependency
such as `forensic-vfs`/`safe-read`, or a language feature actually used) is not
recorded in the repo or git history. Rationale reconstructed from structure;
original intent not recovered in available history — the honest floor is "the
lowest version CI verifies builds," currently `1.85`.

## Consequences

- Contributors and CI build on one stable toolchain; MSRV is a separate, tested
  promise that can stay below the dev pin.
- A `feat`/`fix` conventional commit drives the next release automatically; a
  `chore`/`docs`/`test`-only change rides along without cutting one.
- The `<crate>-vX.Y.Z` tag form keeps library releases from triggering a binary
  build pipeline (a fleet-wide gotcha this repo already guards against).
