//! Pure-Rust read-only QCOW2 disk image reader.
//!
//! Supports QCOW2 v2 and v3 (uncompressed, no backing file, no encryption).
//! Uses a two-level L1→L2 cluster lookup matching QEMU's own design.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

mod error;
mod header;

pub use error::Qcow2Error;

use header::Qcow2Header;

/// Read-only QCOW2 container reader.
///
/// Implements `Read + Seek` over the virtual sector stream.
pub struct Qcow2Reader {
    file: File,
    virtual_disk_size: u64,
    cluster_size: u64,
    l1_table: Vec<u64>,   // L1 entries (masked byte offsets of L2 tables)
    l2_bits: u32,         // log2(entries per L2 table)
    l2_mask: u64,
    pos: u64,
}

impl Qcow2Reader {
    /// Open a QCOW2 disk image (v2 or v3, uncompressed, no backing file).
    pub fn open(path: &Path) -> Result<Self, Qcow2Error> {
        let mut file = File::open(path)?;

        // Read enough bytes to cover both v2 (72 bytes) and v3 (104 bytes) headers.
        let mut hdr_buf = [0u8; 104];
        let hdr_read = file.read(&mut hdr_buf)?;
        let hdr = Qcow2Header::parse(&hdr_buf[..hdr_read])?;

        let cluster_size = 1u64 << hdr.cluster_bits;
        // Each L2 table occupies one cluster; each entry is 8 bytes.
        let l2_entries = cluster_size / 8;
        let l2_bits = hdr.cluster_bits - 3; // log2(l2_entries)
        let l2_mask = l2_entries - 1;

        // Load L1 table into memory.
        file.seek(SeekFrom::Start(hdr.l1_table_offset))?;
        let l1_bytes = u64::from(hdr.l1_size) * 8;
        let mut l1_buf = vec![0u8; l1_bytes as usize];
        file.read_exact(&mut l1_buf)?;
        let l1_table: Vec<u64> = l1_buf
            .chunks_exact(8)
            .map(|c| u64::from_be_bytes(c.try_into().unwrap()))
            .collect();

        Ok(Qcow2Reader {
            file,
            virtual_disk_size: hdr.disk_size,
            cluster_size,
            l1_table,
            l2_bits,
            l2_mask,
            pos: 0,
        })
    }

    /// Virtual disk size in bytes as recorded in the QCOW2 header.
    pub fn virtual_disk_size(&self) -> u64 {
        self.virtual_disk_size
    }

    /// Resolve `virtual_offset` → file byte offset, or `None` for a sparse cluster.
    fn file_offset_for(&mut self, virtual_offset: u64) -> io::Result<Option<u64>> {
        let cluster_idx = virtual_offset >> self.cluster_size.trailing_zeros();
        let offset_in_cluster = virtual_offset & (self.cluster_size - 1);

        let l1_idx = (cluster_idx >> self.l2_bits) as usize;
        let l2_idx = cluster_idx & self.l2_mask;

        let l1_entry = self.l1_table.get(l1_idx).copied().unwrap_or(0);
        let l2_table_offset = l1_entry & 0x7FFF_FFFF_FFFF_FFFF; // mask COPIED bit
        if l2_table_offset == 0 {
            return Ok(None);
        }

        let l2_entry_pos = l2_table_offset + l2_idx * 8;
        self.file.seek(SeekFrom::Start(l2_entry_pos))?;
        let mut l2_bytes = [0u8; 8];
        self.file.read_exact(&mut l2_bytes)?;
        let l2_entry = u64::from_be_bytes(l2_bytes);

        if l2_entry & (1 << 62) != 0 {
            // Compressed cluster — not supported for reads.
            return Err(io::Error::other("compressed qcow2 cluster not supported"));
        }

        let cluster_offset = l2_entry & 0x3FFF_FFFF_FFFF_FFFF; // mask COPIED + COMPRESSED
        if cluster_offset == 0 {
            return Ok(None); // unallocated
        }

        Ok(Some(cluster_offset + offset_in_cluster))
    }
}

impl Read for Qcow2Reader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.virtual_disk_size || buf.is_empty() {
            return Ok(0);
        }

        let remaining_virtual = (self.virtual_disk_size - self.pos) as usize;
        let remaining_in_cluster =
            (self.cluster_size - (self.pos & (self.cluster_size - 1))) as usize;
        let to_read = buf.len().min(remaining_virtual).min(remaining_in_cluster);

        let n = match self.file_offset_for(self.pos)? {
            Some(file_off) => {
                self.file.seek(SeekFrom::Start(file_off))?;
                self.file.read(&mut buf[..to_read])?
            }
            None => {
                buf[..to_read].fill(0);
                to_read
            }
        };

        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for Qcow2Reader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(n) => n as i64,
            SeekFrom::Current(n) => self.pos as i64 + n,
            SeekFrom::End(n) => self.virtual_disk_size as i64 + n,
        };
        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = new_pos as u64;
        Ok(self.pos)
    }
}

// ── Test helpers ──────────────────────────────────────────────────────────────

#[cfg(feature = "test-helpers")]
pub mod testutil;
#[cfg(not(feature = "test-helpers"))]
mod testutil;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use testutil::test_qcow2;

    fn write_tmp(data: &[u8]) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(data).unwrap();
        f
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Build a minimal valid QCOW2 v2 header (72 bytes) with arbitrary cluster_bits.
    fn qcow2_header_bytes(cluster_bits: u32) -> Vec<u8> {
        let mut h = vec![0u8; 72];
        h[0..4].copy_from_slice(&0x5146_49fb_u32.to_be_bytes()); // magic
        h[4..8].copy_from_slice(&2u32.to_be_bytes());             // version 2
        // bytes 8..16: backing_file_offset = 0
        // bytes 16..20: backing_file_size = 0
        h[20..24].copy_from_slice(&cluster_bits.to_be_bytes());   // cluster_bits
        h[24..32].copy_from_slice(&512u64.to_be_bytes());         // disk_size
        // bytes 32..36: encryption = 0
        h[36..40].copy_from_slice(&0u32.to_be_bytes());           // l1_size = 0
        h[40..48].copy_from_slice(&0u64.to_be_bytes());           // l1_table_offset
        h
    }

    // ── Panic regression tests (RED until header.rs validates cluster_bits) ───

    #[test]
    fn cluster_bits_too_large_rejected() {
        // cluster_bits=200 triggers "attempt to shift left with overflow" on
        // `1u64 << hdr.cluster_bits` (lib.rs line 40) in debug builds.
        let f = write_tmp(&qcow2_header_bytes(200));
        assert!(Qcow2Reader::open(f.path()).is_err());
    }

    #[test]
    fn cluster_bits_zero_rejected() {
        // cluster_bits=0 triggers u32 underflow on `cluster_bits - 3` (lib.rs line 43).
        let f = write_tmp(&qcow2_header_bytes(0));
        assert!(Qcow2Reader::open(f.path()).is_err());
    }

    #[test]
    fn cluster_bits_below_minimum_rejected() {
        // cluster_bits=2 also triggers the same underflow (2 - 3 wraps for u32).
        let f = write_tmp(&qcow2_header_bytes(2));
        assert!(Qcow2Reader::open(f.path()).is_err());
    }

    // ── Existing tests ────────────────────────────────────────────────────────

    #[test]
    fn open_nonexistent_returns_err() {
        assert!(Qcow2Reader::open(Path::new("/tmp/no_such.qcow2")).is_err());
    }

    #[test]
    fn open_empty_file_returns_err() {
        let f = write_tmp(&[]);
        assert!(Qcow2Reader::open(f.path()).is_err());
    }

    #[test]
    fn open_non_qcow2_file_returns_err() {
        let f = write_tmp(b"this is not a qcow2 image at all");
        assert!(Qcow2Reader::open(f.path()).is_err());
    }

    #[test]
    fn qcow2_virtual_disk_size() {
        let img = test_qcow2(&[0u8; 512]);
        let f = write_tmp(&img);
        let reader = Qcow2Reader::open(f.path()).expect("open");
        assert_eq!(reader.virtual_disk_size(), testutil::CLUSTER_SIZE as u64);
    }

    #[test]
    fn qcow2_read_returns_cluster_data() {
        let mut data = vec![0u8; 512];
        data[42] = 0xDE;
        data[43] = 0xAD;
        let img = test_qcow2(&data);
        let f = write_tmp(&img);
        let mut reader = Qcow2Reader::open(f.path()).expect("open");
        let mut buf = vec![0u8; 512];
        reader.read_exact(&mut buf).expect("read");
        assert_eq!(buf[42], 0xDE);
        assert_eq!(buf[43], 0xAD);
    }

    #[test]
    fn seek_and_read_at_offset() {
        let mut data = vec![0u8; testutil::CLUSTER_SIZE];
        data[100] = 0xBE;
        data[101] = 0xEF;
        let img = test_qcow2(&data);
        let f = write_tmp(&img);
        let mut reader = Qcow2Reader::open(f.path()).expect("open");
        reader.seek(SeekFrom::Start(100)).unwrap();
        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [0xBE, 0xEF]);
    }

    #[test]
    fn qcow2_reader_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<Qcow2Reader>();
    }
}
