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
        todo!("implement Qcow2Reader::open")
    }

    /// Virtual disk size in bytes as recorded in the QCOW2 header.
    pub fn virtual_disk_size(&self) -> u64 {
        self.virtual_disk_size
    }
}

impl Read for Qcow2Reader {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        todo!("implement Qcow2Reader::read")
    }
}

impl Seek for Qcow2Reader {
    fn seek(&mut self, _pos: SeekFrom) -> io::Result<u64> {
        todo!("implement Qcow2Reader::seek")
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
