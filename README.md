[![Crates.io](https://img.shields.io/crates/v/qcow2.svg)](https://crates.io/crates/qcow2)
[![Docs.rs](https://img.shields.io/docsrs/qcow2)](https://docs.rs/qcow2)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/qcow2/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/qcow2/actions/workflows/ci.yml)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Pure-Rust read-only QCOW2 v2/v3 disk image reader.**

Decodes QCOW2 containers produced by QEMU, KVM, and libvirt and exposes a `Read + Seek` interface over the virtual sector stream. Implements the two-level L1→L2 cluster lookup matching QEMU's own design, with support for deflate-compressed clusters and sparse zero regions. Zero unsafe code, no C bindings.

```toml
[dependencies]
qcow2 = "0.1"
```

---

## Usage

### Open a QCOW2 image and read sectors

```rust
use qcow2::Qcow2Reader;
use std::io::{Read, Seek, SeekFrom};

let mut reader = Qcow2Reader::open("disk.qcow2")?;

println!("Virtual disk size: {} bytes", reader.virtual_disk_size());

// Read the first sector
let mut sector = [0u8; 512];
reader.read_exact(&mut sector)?;

// Seek anywhere — two-level cluster table lookup
reader.seek(SeekFrom::Start(1_048_576))?;
```

### Pass to a filesystem crate

`Qcow2Reader` implements `Read + Seek`, so it drops directly into any crate that accepts a reader:

```rust
use qcow2::Qcow2Reader;

let reader = Qcow2Reader::open("disk.qcow2")?;
// e.g. ext4fs_forensic::Filesystem::open(reader)?;
```

---

## Supported features

| Feature | Supported |
|---------|:---------:|
| QCOW2 version 2 | ✓ |
| QCOW2 version 3 | ✓ |
| Unallocated (zero-filled) clusters | ✓ |
| Deflate-compressed clusters | ✓ |
| Standard cluster data | ✓ |
| Backing file (overlay images) | planned |
| Encryption | not planned |
| External data file (v3 extension) | not planned |

Read-only. Backing file chains and encryption are out of scope for a forensic reader.

---

## Related crates

### Container readers

| Crate | Format | Notes |
|-------|--------|-------|
| [`ewf`](https://github.com/SecurityRonin/ewf) | E01 / EWF / Ex01 | Dominant professional forensic acquisition format |
| [`aff4`](https://github.com/SecurityRonin/aff4) | AFF4 v1 | Evimetry / aff4-imager forensic disk images with Map streams |
| [`vmdk`](https://github.com/SecurityRonin/vmdk) | VMware VMDK | Monolithic sparse disk images from VMware Workstation / ESXi |
| [`vhdx`](https://github.com/SecurityRonin/vhdx) | Microsoft VHDX | Hyper-V, Windows 8+, WSL2, Azure disk container |
| [`vhd`](https://github.com/SecurityRonin/vhd) | Legacy VHD | Virtual PC / Hyper-V Generation-1 fixed and dynamic disk images |
| [`ufed`](https://github.com/SecurityRonin/ufed) | Cellebrite UFED | Physical mobile device dumps with UFD XML segment mapping |
| [`dd`](https://github.com/SecurityRonin/dd) | Raw / flat / gz | dd, dcfldd, and gzip-wrapped raw images |
| [`iso`](https://github.com/SecurityRonin/iso) | ISO 9660 | Optical disc images: multi-session, UDF bridge, Rock Ridge, Joliet, El Torito |
| [`dmg`](https://github.com/SecurityRonin/dmg) | Apple DMG / UDIF | macOS disk images with koly trailer, mish block tables, zlib decompression |
| [`dar`](https://github.com/SecurityRonin/dar) | DAR archive | Disk ARchiver archives with catalog index and CRC32 validation |

### Forensic analysers

| Crate | Format | Notes |
|-------|--------|-------|
| [`ewf-forensic`](https://github.com/SecurityRonin/ewf-forensic) | E01 | Structural integrity audit, Adler-32 / MD5 hash verification, and in-memory repair |
| [`vhdx-forensic`](https://github.com/SecurityRonin/vhdx-forensic) | VHDX | Forensic integrity analyser and in-memory repair tool for VHDX containers |

---

[Privacy Policy](https://securityronin.github.io/qcow2/privacy/) · [Terms of Service](https://securityronin.github.io/qcow2/terms/) · © 2026 Security Ronin Ltd
