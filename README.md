[![Crates.io (core)](https://img.shields.io/crates/v/qcow2-core.svg?label=qcow2-core)](https://crates.io/crates/qcow2-core)
[![Crates.io (forensic)](https://img.shields.io/crates/v/qcow2-forensic.svg?label=qcow2-forensic)](https://crates.io/crates/qcow2-forensic)
[![Docs.rs](https://img.shields.io/docsrs/qcow2-core?label=docs.rs)](https://docs.rs/qcow2-core)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/qcow2-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/qcow2-forensic/actions/workflows/ci.yml)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Pure-Rust QCOW2 forensics: read any QEMU/KVM/libvirt disk image, and flag what an examiner needs to know about it — in two lines.**

QCOW2 images hide things a raw `dd` never would: a backing file the evidence silently depends on, internal snapshots of earlier guest states, an encryption header, or QEMU's own *dirty* / *corrupt* flags. This workspace gives you a panic-free reader **and** an auditor that surfaces those facts as graded findings.

```rust
// What is this image, and what should I worry about? — no decoding, no key needed.
for finding in qcow2_forensic::audit_path("evidence.qcow2".as_ref())? {
    println!("[{:?}] {}", finding.severity(), finding.note());
}
// [Medium] image references a backing file — it is an overlay and does not alone contain the full guest data
// [Low]    image carries 3 internal snapshot(s) — additional captured guest states to examine
// [High]   the corrupt bit is set — QEMU flagged the image as corrupt
```

```toml
[dependencies]
qcow2-core     = "0.2"   # the reader: Read + Seek over the virtual disk
qcow2-forensic = "0.1"   # the auditor: header anomalies as report::Finding
```

---

## Two crates, one job

| Crate | Role | Use it when you want to… |
|-------|------|--------------------------|
| **`qcow2-core`** (`use qcow2::…`) | Reader | Decode the virtual disk — `Read + Seek`, v2/v3, deflate clusters, sparse zeros — or `inspect()` the header without decoding. |
| **`qcow2-forensic`** | Analyzer | Grade the image's header facts into severity-ranked `forensicnomicon::report::Finding`s. |

### Read the virtual disk

```rust
use qcow2::Qcow2Reader;
use std::io::{Read, Seek, SeekFrom};

let mut reader = Qcow2Reader::open("disk.qcow2".as_ref())?;
println!("virtual size: {} bytes", reader.virtual_disk_size());

let mut sector = [0u8; 512];
reader.read_exact(&mut sector)?;          // first sector
reader.seek(SeekFrom::Start(1 << 20))?;   // two-level L1→L2 cluster lookup
```

`Qcow2Reader` is `Read + Seek`, so it drops straight into any filesystem crate that takes a reader.

### Inspect without decoding (works on images the reader can't open)

```rust
let info = qcow2::inspect("encrypted.qcow2".as_ref())?;
assert!(info.encryption_method != 0);     // header facts even when the data is inaccessible
assert!(info.has_backing_file);
```

`inspect()` is deliberately lenient — it reports backing files, encryption, snapshots, and the v3 incompatible-feature bits instead of refusing, so the auditor can speak to images the strict reader rejects.

---

## What the auditor flags

| Code | Severity | Meaning |
|------|:--------:|---------|
| `QCOW2-CORRUPT` | High | QEMU set the corrupt incompatible-feature bit |
| `QCOW2-BACKING-FILE` | Medium | Overlay/differential image — not self-contained |
| `QCOW2-ENCRYPTED` | Medium | AES/LUKS encrypted — contents inaccessible without the key |
| `QCOW2-EXTERNAL-DATA` | Medium | Guest data stored in an external data file |
| `QCOW2-INTERNAL-SNAPSHOTS` | Low | Additional captured guest states to examine |
| `QCOW2-DIRTY` | Low | Not closed cleanly (in use or crashed) |

Each is an *observation* ("consistent with …") on the shared [`forensicnomicon`](https://crates.io/crates/forensicnomicon) report model, so QCOW2 findings aggregate uniformly with the rest of a disk-forensic run. The examiner draws the conclusions.

---

## Trust, but verify

Read-only and panic-free by construction: `#![forbid(unsafe_code)]`, no `unwrap`/`expect`/unchecked indexing in production parsers, every length/offset bounds-checked, and `cargo fuzz` targets (`open`/`read`/`inspect`/`forensic`) that must never panic on crafted bytes. Decoding is **differentially validated against `qemu-img convert`** and a real CirrOS cloud image; `inspect()` is validated against real qemu-img-produced backing-file, snapshot, and LUKS images. See [`docs/validation.md`](docs/validation.md).

---

## Related crates

Part of the SecurityRonin forensic fleet — each container format is a `*-core` reader plus a `*-forensic` analyzer on the shared `forensicnomicon` report model:
[`ewf-forensic`](https://github.com/SecurityRonin/ewf-forensic) (E01) ·
[`vmdk-forensic`](https://github.com/SecurityRonin/vmdk-forensic) (VMware) ·
[`vhdx-forensic`](https://github.com/SecurityRonin/vhdx-forensic) (Hyper-V) ·
[`ntfs-forensic`](https://github.com/SecurityRonin/ntfs-forensic) (NTFS) ·
[`iso9660-forensic`](https://github.com/SecurityRonin/iso9660-forensic) (optical) ·
[`disk-forensic`](https://github.com/SecurityRonin/disk-forensic) (the `disk4n6` orchestrator).

---

[Privacy Policy](https://securityronin.github.io/qcow2-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/qcow2-forensic/terms/) · © 2026 Security Ronin Ltd
