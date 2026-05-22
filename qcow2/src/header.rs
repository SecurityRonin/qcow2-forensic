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

        let magic = u32::from_be_bytes(data[0..4].try_into().unwrap());
        if magic != MAGIC {
            return Err(Qcow2Error::BadMagic);
        }

        let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
        if version < 2 || version > 3 {
            return Err(Qcow2Error::UnsupportedVersion(version));
        }

        let backing_file_offset = u64::from_be_bytes(data[8..16].try_into().unwrap());
        if backing_file_offset != 0 {
            return Err(Qcow2Error::BackingFileNotSupported);
        }

        let cluster_bits = u32::from_be_bytes(data[20..24].try_into().unwrap());
        // QCOW2 spec §3: cluster_bits must be in [9, 20]. Values outside this range
        // cause shift overflow or u32 underflow in downstream arithmetic.
        if !(9..=20).contains(&cluster_bits) {
            return Err(Qcow2Error::ClusterBitsOutOfRange(cluster_bits));
        }
        let disk_size = u64::from_be_bytes(data[24..32].try_into().unwrap());

        let encryption_method = u32::from_be_bytes(data[32..36].try_into().unwrap());
        if encryption_method != 0 {
            return Err(Qcow2Error::EncryptedNotSupported);
        }

        let l1_size = u32::from_be_bytes(data[36..40].try_into().unwrap());
        let l1_table_offset = u64::from_be_bytes(data[40..48].try_into().unwrap());

        // v3 incompatible features check
        if version == 3 && data.len() >= 80 {
            let incompat = u64::from_be_bytes(data[72..80].try_into().unwrap());
            let unsupported = incompat & INCOMPAT_UNSUPPORTED;
            if unsupported != 0 {
                return Err(Qcow2Error::UnsupportedIncompatibleFeatures(unsupported));
            }
        }

        Ok(Qcow2Header { cluster_bits, disk_size, l1_size, l1_table_offset })
    }
}
