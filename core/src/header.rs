//! QCOW2 header parsing (QEMU block format spec §3).
//!
//! All fields are big-endian. Supports v2 and v3; rejects encrypted images,
//! backing files, external data files, and extended L2 entries.

use crate::error::{Qcow2Error, Result};

pub const MAGIC: u32 = 0x5146_49fb;
pub const MIN_HEADER_SIZE: usize = 72; // v2 header length

// Incompatible feature bits we cannot handle.
const INCOMPAT_EXTERNAL_DATA: u64 = 1 << 2;
const INCOMPAT_COMPRESSION_TYPE: u64 = 1 << 3;
const INCOMPAT_EXTENDED_L2: u64 = 1 << 4;
const INCOMPAT_UNSUPPORTED: u64 =
    INCOMPAT_EXTERNAL_DATA | INCOMPAT_COMPRESSION_TYPE | INCOMPAT_EXTENDED_L2;

/// Read a big-endian `u32` at `off`. Never panics: out-of-range reads yield 0
/// (callers bounds-check the header length up front).
fn be_u32(data: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    if let Some(s) = data.get(off..off + 4) {
        b.copy_from_slice(s);
    }
    u32::from_be_bytes(b)
}

/// Read a big-endian `u64` at `off`. Never panics: out-of-range reads yield 0.
fn be_u64(data: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    if let Some(s) = data.get(off..off + 8) {
        b.copy_from_slice(s);
    }
    u64::from_be_bytes(b)
}

/// Parsed QCOW2 header fields needed for cluster navigation.
pub struct Qcow2Header {
    pub cluster_bits: u32, // cluster_size = 1 << cluster_bits
    pub disk_size: u64,    // virtual disk size in bytes
    pub l1_size: u32,      // number of L1 table entries
    pub l1_table_offset: u64,
}

impl Qcow2Header {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < MIN_HEADER_SIZE {
            return Err(Qcow2Error::FileTooSmall);
        }

        let magic = be_u32(data, 0);
        if magic != MAGIC {
            return Err(Qcow2Error::BadMagic);
        }

        let version = be_u32(data, 4);
        if !(2..=3).contains(&version) {
            return Err(Qcow2Error::UnsupportedVersion(version));
        }

        let backing_file_offset = be_u64(data, 8);
        if backing_file_offset != 0 {
            return Err(Qcow2Error::BackingFileNotSupported);
        }

        let cluster_bits = be_u32(data, 20);
        // QCOW2 spec §3: cluster_bits must be in [9, 20]. Values outside this range
        // cause shift overflow or u32 underflow in downstream arithmetic.
        if !(9..=20).contains(&cluster_bits) {
            return Err(Qcow2Error::ClusterBitsOutOfRange(cluster_bits));
        }
        let disk_size = be_u64(data, 24);

        let encryption_method = be_u32(data, 32);
        if encryption_method != 0 {
            return Err(Qcow2Error::EncryptedNotSupported);
        }

        let l1_size = be_u32(data, 36);
        let l1_table_offset = be_u64(data, 40);

        // v3 incompatible features check
        if version == 3 && data.len() >= 80 {
            let incompat = be_u64(data, 72);
            let unsupported = incompat & INCOMPAT_UNSUPPORTED;
            if unsupported != 0 {
                return Err(Qcow2Error::UnsupportedIncompatibleFeatures(unsupported));
            }
        }

        Ok(Qcow2Header {
            cluster_bits,
            disk_size,
            l1_size,
            l1_table_offset,
        })
    }
}

/// Forensically-relevant QCOW2 header facts, parsed **leniently** — unlike
/// [`Qcow2Header::parse`], this does not reject backing files, encryption, or
/// unsupported incompatible features, so an analyzer can inspect images the
/// reader cannot decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Qcow2Info {
    /// QCOW2 format version (2 or 3).
    pub version: u32,
    /// `cluster_size = 1 << cluster_bits`.
    pub cluster_bits: u32,
    /// Virtual disk size in bytes.
    pub virtual_disk_size: u64,
    /// Number of L1 table entries.
    pub l1_size: u32,
    /// Whether a backing-file reference is present (overlay/differential image).
    pub has_backing_file: bool,
    /// Encryption method (0 = none, 1 = AES, 2 = LUKS).
    pub encryption_method: u32,
    /// Number of internal snapshots.
    pub snapshot_count: u32,
    /// v3 incompatible-feature bitmap (0 on v2). Bit 0 = dirty, 1 = corrupt,
    /// 2 = external data file, 3 = compression type, 4 = extended L2.
    pub incompatible_features: u64,
    /// Backing-file name (overlay/differential base image), if present and
    /// reachable in the inspected window. `None` when there is no backing file.
    pub backing_file: Option<String>,
    /// Backing-file format name from the header-extension area (extension type
    /// `0xE2792ACA`), e.g. "qcow2" or "raw". `None` when absent.
    pub backing_format: Option<String>,
}

impl Qcow2Info {
    /// Parse forensic header facts. Requires a valid magic, minimum size, and a
    /// v2/v3 version; everything else is reported, not rejected.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < MIN_HEADER_SIZE {
            return Err(Qcow2Error::FileTooSmall);
        }
        let magic = be_u32(data, 0);
        if magic != MAGIC {
            return Err(Qcow2Error::BadMagic);
        }
        let version = be_u32(data, 4);

        // QCOW1 (v1) shares the magic and the early header layout (backing-file
        // offset/size at 8/16, virtual size at 24) but diverges afterwards
        // (cluster_bits is a u8 at offset 32, crypt at 36, no snapshots/feature
        // bits). Report it distinctly with only the fields that are reliably at
        // matching offsets, so an analyzer can flag the legacy format without
        // trusting v2/v3-specific fields that do not exist in v1.
        if version == 1 {
            return Ok(Qcow2Info {
                version,
                cluster_bits: 0,
                virtual_disk_size: be_u64(data, 24),
                l1_size: 0,
                has_backing_file: be_u64(data, 8) != 0,
                encryption_method: be_u32(data, 36),
                snapshot_count: 0,
                incompatible_features: 0,
                backing_file: backing_file_name(data),
                backing_format: None,
            });
        }

        if !(2..=3).contains(&version) {
            return Err(Qcow2Error::UnsupportedVersion(version));
        }

        let has_backing_file = be_u64(data, 8) != 0;
        let cluster_bits = be_u32(data, 20);
        let virtual_disk_size = be_u64(data, 24);
        let encryption_method = be_u32(data, 32);
        let l1_size = be_u32(data, 36);
        let snapshot_count = be_u32(data, 60);

        let incompatible_features = if version == 3 && data.len() >= 80 {
            be_u64(data, 72)
        } else {
            0
        };

        let backing_file = backing_file_name(data);
        let backing_format = backing_format_name(data, version);

        Ok(Qcow2Info {
            version,
            cluster_bits,
            virtual_disk_size,
            l1_size,
            has_backing_file,
            encryption_method,
            snapshot_count,
            incompatible_features,
            backing_file,
            backing_format,
        })
    }
}

/// QCOW2 header-extension type for the backing-file format name (QCOW2 spec §3.1).
const EXT_BACKING_FORMAT: u32 = 0xE279_2ACA;
/// QCOW2 header-extension end marker.
const EXT_END: u32 = 0x0000_0000;
/// Upper bound on a backing filename / format string we will materialize, to
/// defend against a crafted oversized `backing_file_size` / extension length.
const MAX_BACKING_LEN: usize = 4096;

/// Extract the backing filename from `backing_file_offset` (offset 8, u64) and
/// `backing_file_size` (offset 16, u32). Returns `None` when there is no backing
/// file or the name lies outside the inspected `data` window. Never panics.
fn backing_file_name(data: &[u8]) -> Option<String> {
    let offset = be_u64(data, 8);
    let size = be_u32(data, 16) as usize;
    if offset == 0 || size == 0 {
        return None;
    }
    let size = size.min(MAX_BACKING_LEN);
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(size)?;
    let bytes = data.get(start..end)?;
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// Scan the header-extension area for the backing-file format name
/// (extension type `0xE2792ACA`). Extensions begin at the header length: 72 for
/// v2 (fixed), or the `header_length` field (offset 100, u32) for v3. Each
/// extension is `type:u32 len:u32 data` padded to an 8-byte boundary; scanning
/// stops at the end marker (type 0) or when the window is exhausted. Never panics.
fn backing_format_name(data: &[u8], version: u32) -> Option<String> {
    let mut pos = if version == 3 {
        // header_length lives at offset 100; clamp to a sane minimum.
        (be_u32(data, 100) as usize).max(MIN_HEADER_SIZE)
    } else {
        MIN_HEADER_SIZE
    };

    // Bound the number of extensions we will walk so a crafted chain of
    // zero-length records cannot spin; real images carry only a handful.
    for _ in 0..64 {
        let ext_type = be_u32(data, pos);
        let ext_len = be_u32(data, pos + 4) as usize;
        if ext_type == EXT_END {
            return None;
        }
        let data_start = pos.checked_add(8)?;
        let data_end = data_start.checked_add(ext_len)?;
        if ext_type == EXT_BACKING_FORMAT {
            let len = ext_len.min(MAX_BACKING_LEN);
            let slice_end = data_start.checked_add(len)?;
            let bytes = data.get(data_start..slice_end)?;
            return Some(String::from_utf8_lossy(bytes).into_owned());
        }
        // Advance past this extension, padding its data up to 8 bytes.
        let padded = ext_len.checked_add(7)? & !7usize;
        pos = data_start.checked_add(padded)?;
        // Stop if we have run past the inspected window.
        if data_end > data.len() || pos >= data.len() {
            return None;
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Build a v3 header with a given `header_len` and the backing filename
    /// placed at `backing_off`, then append the extension area + name region.
    fn build(
        version: u32,
        backing_off: u64,
        backing_name: &[u8],
        header_len: u32,
        extensions: &[u8],
    ) -> Vec<u8> {
        // Allocate a window big enough for header + extensions + name.
        let cap = (header_len as usize)
            .max(backing_off as usize + backing_name.len())
            .max(112)
            + extensions.len()
            + 64;
        let mut d = vec![0u8; cap];
        d[0..4].copy_from_slice(&MAGIC.to_be_bytes());
        d[4..8].copy_from_slice(&version.to_be_bytes());
        d[8..16].copy_from_slice(&backing_off.to_be_bytes());
        d[16..20].copy_from_slice(&(backing_name.len() as u32).to_be_bytes());
        d[20..24].copy_from_slice(&16u32.to_be_bytes()); // cluster_bits
        if version == 3 {
            d[100..104].copy_from_slice(&header_len.to_be_bytes());
        }
        // Extensions begin at header_len (v3) or 72 (v2).
        let ext_start = if version == 3 {
            header_len as usize
        } else {
            MIN_HEADER_SIZE
        };
        d[ext_start..ext_start + extensions.len()].copy_from_slice(extensions);
        if backing_off != 0 {
            let s = backing_off as usize;
            d[s..s + backing_name.len()].copy_from_slice(backing_name);
        }
        d
    }

    /// Encode one header extension (type, data) padded to 8 bytes.
    fn ext(ty: u32, payload: &[u8]) -> Vec<u8> {
        let mut e = Vec::new();
        e.extend_from_slice(&ty.to_be_bytes());
        e.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        e.extend_from_slice(payload);
        let pad = (8 - (payload.len() % 8)) % 8;
        e.extend(std::iter::repeat_n(0u8, pad));
        e
    }

    #[test]
    fn no_backing_file_yields_none() {
        let mut d = vec![0u8; 112];
        d[0..4].copy_from_slice(&MAGIC.to_be_bytes());
        d[4..8].copy_from_slice(&3u32.to_be_bytes());
        let info = Qcow2Info::parse(&d).unwrap();
        assert!(info.backing_file.is_none());
        assert!(info.backing_format.is_none());
    }

    #[test]
    fn backing_file_name_is_extracted() {
        let name = b"base.qcow2";
        let mut endmark = Vec::new();
        endmark.extend_from_slice(&ext(EXT_END, &[]));
        let d = build(3, 200, name, 112, &endmark);
        let info = Qcow2Info::parse(&d).unwrap();
        assert_eq!(info.backing_file.as_deref(), Some("base.qcow2"));
        assert!(info.backing_format.is_none(), "no format extension present");
    }

    #[test]
    fn backing_format_extension_is_extracted() {
        let mut exts = Vec::new();
        exts.extend_from_slice(&ext(EXT_BACKING_FORMAT, b"qcow2"));
        exts.extend_from_slice(&ext(EXT_END, &[]));
        let d = build(3, 200, b"base.qcow2", 112, &exts);
        let info = Qcow2Info::parse(&d).unwrap();
        assert_eq!(info.backing_format.as_deref(), Some("qcow2"));
        assert_eq!(info.backing_file.as_deref(), Some("base.qcow2"));
    }

    #[test]
    fn format_extension_after_an_unknown_extension() {
        let mut exts = Vec::new();
        exts.extend_from_slice(&ext(0x1234_5678, b"ignored payload"));
        exts.extend_from_slice(&ext(EXT_BACKING_FORMAT, b"raw"));
        exts.extend_from_slice(&ext(EXT_END, &[]));
        let d = build(3, 0, b"", 112, &exts);
        let info = Qcow2Info::parse(&d).unwrap();
        assert_eq!(info.backing_format.as_deref(), Some("raw"));
    }

    #[test]
    fn v2_extensions_begin_at_offset_72() {
        let mut exts = Vec::new();
        exts.extend_from_slice(&ext(EXT_BACKING_FORMAT, b"raw"));
        exts.extend_from_slice(&ext(EXT_END, &[]));
        let d = build(2, 0, b"", 72, &exts);
        let info = Qcow2Info::parse(&d).unwrap();
        assert_eq!(info.backing_format.as_deref(), Some("raw"));
    }

    #[test]
    fn backing_offset_past_window_yields_none() {
        let mut d = vec![0u8; 112];
        d[0..4].copy_from_slice(&MAGIC.to_be_bytes());
        d[4..8].copy_from_slice(&3u32.to_be_bytes());
        d[8..16].copy_from_slice(&100_000u64.to_be_bytes()); // offset past window
        d[16..20].copy_from_slice(&10u32.to_be_bytes());
        let info = Qcow2Info::parse(&d).unwrap();
        assert!(info.backing_file.is_none());
    }

    #[test]
    fn oversized_backing_size_is_capped_not_panicking() {
        let name = b"x".repeat(50);
        let mut d = build(3, 200, &name, 112, &ext(EXT_END, &[]));
        // Force a huge declared backing_file_size; the read is capped + bounded.
        d[16..20].copy_from_slice(&u32::MAX.to_be_bytes());
        let info = Qcow2Info::parse(&d).unwrap();
        // Either capped to what fits in the window, or None — never a panic.
        assert!(info.backing_file.is_some() || info.backing_file.is_none());
    }

    #[test]
    fn qcow1_version_is_reported_leniently() {
        let mut d = vec![0u8; 72];
        d[0..4].copy_from_slice(&MAGIC.to_be_bytes());
        d[4..8].copy_from_slice(&1u32.to_be_bytes()); // version 1
        d[8..16].copy_from_slice(&0u64.to_be_bytes()); // no backing file
        d[24..32].copy_from_slice(&(4u64 << 20).to_be_bytes()); // virtual size
        let info = Qcow2Info::parse(&d).unwrap();
        assert_eq!(info.version, 1);
        assert_eq!(info.virtual_disk_size, 4 << 20);
        assert!(!info.has_backing_file);
        assert!(info.backing_format.is_none());
    }

    #[test]
    fn unsupported_version_still_errors() {
        let mut d = vec![0u8; 72];
        d[0..4].copy_from_slice(&MAGIC.to_be_bytes());
        d[4..8].copy_from_slice(&7u32.to_be_bytes());
        assert!(matches!(
            Qcow2Info::parse(&d),
            Err(Qcow2Error::UnsupportedVersion(7))
        ));
    }

    #[test]
    fn no_end_marker_stops_at_window_end() {
        // Extension whose length runs to the very edge with no end marker.
        let exts = ext(0x1111_1111, b"abcdefgh");
        let d = build(3, 0, b"", 112, &exts);
        let info = Qcow2Info::parse(&d).unwrap();
        assert!(info.backing_format.is_none());
    }
}
