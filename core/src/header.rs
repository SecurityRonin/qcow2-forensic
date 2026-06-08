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
const INCOMPAT_UNSUPPORTED: u64 = INCOMPAT_EXTERNAL_DATA | INCOMPAT_COMPRESSION_TYPE | INCOMPAT_EXTENDED_L2;

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
    pub cluster_bits: u32,   // cluster_size = 1 << cluster_bits
    pub disk_size: u64,      // virtual disk size in bytes
    pub l1_size: u32,        // number of L1 table entries
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
        if version < 2 || version > 3 {
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

        Ok(Qcow2Header { cluster_bits, disk_size, l1_size, l1_table_offset })
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
        if version < 2 || version > 3 {
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

        Ok(Qcow2Info {
            version,
            cluster_bits,
            virtual_disk_size,
            l1_size,
            has_backing_file,
            encryption_method,
            snapshot_count,
            incompatible_features,
        })
    }
}
