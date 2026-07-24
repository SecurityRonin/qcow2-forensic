# 8. Compose into the fleet VFS and read images out of archives, without temp files

Date: 2026-07-24

Status: Accepted

## Context

The fleet "VFS & Universal Container Abstraction" policy
(`~/src/ronin-issen/CLAUDE.md`) requires container readers to implement the
`forensic-vfs` `ImageSource` contract so a decoded image composes into one
uniform, shareable, read-only byte source alongside every other format. Separately,
evidence QCOW2 images frequently arrive compressed inside a `.zip`; extracting a
multi-GB image to a temp file just to open it is wasteful when the reader only
needs a seekable byte range.

Evidence:
- `core/src/lib.rs`: `trait ReadSeekSend: Read + Seek + Send + Sync` and
  `Qcow2Reader::open_reader(Box<dyn ReadSeekSend>)` — "so an image stored inside
  an archive can be read without extracting it to a temp file first"
  (`git log`: `71e631f feat(qcow2-core): GREEN — open_reader over any seekable
  backing`, `7c2afd7 test(qcow2-core): RED`).
- `core/Cargo.toml`: `[features] vfs = ["dep:forensic-vfs"]`, optional
  `forensic-vfs = { version = "0.3", optional = true }`; `core/src/vfs.rs`
  (`git log`: `7519129 feat(vfs): implement forensic-vfs ImageSource for decoded
  QCOW2`, `902e09c test(vfs): RED`, `0c34c97 build(vfs): bump forensic-vfs to
  0.3`).

## Decision

- Expose `Qcow2Reader::open_reader` over any `Read + Seek + Send + Sync` backing
  (a `File`, an in-RAM `Cursor`, or a positioned sub-range of a `.zip`), keeping
  `open(path)` as the file convenience. The `Send + Sync` bound lets one reader be
  shared across worker threads.
- Implement the `forensic-vfs` `ImageSource` contract behind an **optional,
  off-by-default `vfs` Cargo feature**, so a decoded QCOW2 slots into the fleet
  VFS stack while a bare `qcow2-core` consumer pays no `forensic-vfs` dependency.

## Consequences

- A QCOW2 image inside a `.zip` is opened by handing `open_reader` a positioned
  archive sub-range — no temp-file extraction.
- With `--features vfs`, `E01 → … → QCOW2` (and filesystems above it) read as one
  `Arc<dyn ImageSource>` in the shared VFS engine.
- The `vfs` feature is off by default per the fleet rule that a `-core` reader
  stays lean for third-party reuse; fleet binaries enable it. (This is the
  narrow, sanctioned "optional heavy subsystem" exception to batteries-included:
  the slim default path is for outside consumers, and every fleet binary that
  needs VFS composition turns the feature on.)
