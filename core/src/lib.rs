//! Pure-Rust read-only QCOW2 disk image reader.
//!
//! Supports QCOW2 v2 and v3 (uncompressed, no backing file, no encryption).
//! Uses a two-level L1→L2 cluster lookup matching QEMU's own design.

// Production code is panic-free (no unwrap/expect, enforced by the workspace
// lints); tests legitimately use them.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

mod error;
mod header;
mod refcount;
mod snapshots;

pub use error::Qcow2Error;
pub use header::Qcow2Info;
pub use refcount::{refcount_report, Qcow2RefcountReport};
pub use snapshots::{snapshots, Qcow2Snapshot};

use header::Qcow2Header;

/// Inspect a QCOW2 image's header for forensic facts (version, backing file,
/// encryption, snapshots, incompatible-feature bits) **without** decoding it —
/// works on images the reader rejects (encrypted, backing-file, etc.).
pub fn inspect(path: &Path) -> Result<Qcow2Info, Qcow2Error> {
    let mut file = File::open(path)?;
    // Read a generous window so the parser can also reach the header-extension
    // area and the backing filename, which qemu stores immediately after the
    // fixed header (well within the first cluster). 8 KiB covers real images;
    // a short file simply yields a shorter slice (parse is bounds-checked).
    let mut hdr_buf = [0u8; 8192];
    let n = read_window(&mut file, &mut hdr_buf)?;
    Qcow2Info::parse(&hdr_buf[..n])
}

/// Fill `buf` from the start of `file`, returning the number of bytes read.
/// Handles short reads (small files) by looping until EOF or `buf` is full.
fn read_window(file: &mut File, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

/// Read-only QCOW2 container reader.
///
/// Implements `Read + Seek` over the virtual sector stream.
pub struct Qcow2Reader<T: Read + Seek> {
    file: T,
    virtual_disk_size: u64,
    cluster_size: u64,
    l1_table: Vec<u64>,   // L1 entries (masked byte offsets of L2 tables)
    l2_bits: u32,         // log2(entries per L2 table)
    l2_mask: u64,
    pos: u64,
}

impl Qcow2Reader<File> {
    pub fn open(path: &Path) -> Result<Self, Qcow2Error> {
        let file = File::open(path)?;
        Self::from_reader(file)
    }
}

impl<T> Qcow2Reader<T> 
where
    T: Read + Seek
{
    /// Open a QCOW2 disk image (v2 or v3, uncompressed, no backing file).
    pub fn from_reader(mut reader: T) -> Result<Self, Qcow2Error> {
        // 8 MiB max L1 table — prevents OOM on crafted images.
        const MAX_L1_ENTRIES: u32 = 1 << 20;

        // Read enough bytes to cover both v2 (72 bytes) and v3 (104 bytes) headers.
        let mut hdr_buf = [0u8; 104];
        let hdr_read = reader.read(&mut hdr_buf)?;
        let hdr = Qcow2Header::parse(&hdr_buf[..hdr_read])?;

        let cluster_size = 1u64 << hdr.cluster_bits;
        // Each L2 table occupies one cluster; each entry is 8 bytes.
        let l2_entries = cluster_size / 8;
        let l2_bits = hdr.cluster_bits - 3; // log2(l2_entries)
        let l2_mask = l2_entries - 1;

        // Load L1 table into memory.
        if hdr.l1_size > MAX_L1_ENTRIES {
            return Err(Qcow2Error::L1TableTooLarge(hdr.l1_size));
        }
        reader.seek(SeekFrom::Start(hdr.l1_table_offset))?;
        let l1_bytes = u64::from(hdr.l1_size) * 8;
        let mut l1_buf = vec![0u8; l1_bytes as usize];
        reader.read_exact(&mut l1_buf)?;
        let l1_table: Vec<u64> = l1_buf
            .chunks_exact(8)
            .map(|c| {
                let mut a = [0u8; 8];
                a.copy_from_slice(c); // chunks_exact(8) guarantees len == 8
                u64::from_be_bytes(a)
            })
            .collect();

        Ok(Qcow2Reader {
            file: reader,
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

    /// Resolve `virtual_offset` to a cluster reference.
    fn cluster_ref_for(&mut self, virtual_offset: u64) -> io::Result<ClusterRef> {
        let cluster_idx = virtual_offset >> self.cluster_size.trailing_zeros();

        let l1_idx = (cluster_idx >> self.l2_bits) as usize;
        let l2_idx = cluster_idx & self.l2_mask;

        let l1_entry = self.l1_table.get(l1_idx).copied().unwrap_or(0);
        let l2_table_offset = l1_entry & 0x7FFF_FFFF_FFFF_FFFF; // mask COPIED bit
        if l2_table_offset == 0 {
            return Ok(ClusterRef::Unallocated);
        }

        let l2_entry_pos = l2_table_offset + l2_idx * 8;
        self.file.seek(SeekFrom::Start(l2_entry_pos))?;
        let mut l2_bytes = [0u8; 8];
        self.file.read_exact(&mut l2_bytes)?;
        let l2_entry = u64::from_be_bytes(l2_bytes);

        if l2_entry & (1 << 62) != 0 {
            // Compressed cluster. QCOW2 spec (QEMU implementation):
            //   csize_shift = 40 - cluster_bits
            //   lower csize_shift bits = file BYTE offset (already bytes, no ×512)
            //   next (cluster_bits - 8) bits = compressed_sectors - 1
            // QCOW2 spec: lower (63 - cluster_bits) bits = file byte offset;
            // next (cluster_bits - 1) bits = compressed_sectors - 1.
            // The offset is already in bytes — no sector-to-byte conversion.
            let cluster_bits = self.cluster_size.trailing_zeros(); // u32, in [9, 20]
            let split = 63u32 - cluster_bits; // bits in offset field
            let count_mask = (1u64 << (cluster_bits - 1)) - 1; // cluster_bits-1 count bits
            let file_offset = l2_entry & ((1u64 << split) - 1);
            let nb_sectors = ((l2_entry >> split) & count_mask) + 1;
            let compressed_bytes = (nb_sectors * 512) as usize;
            return Ok(ClusterRef::Compressed { file_offset, compressed_bytes });
        }

        // QCOW_OFLAG_ZERO (bit 0): guest must see zeros regardless of cluster offset.
        // Covers ZERO_PLAIN (l2_entry=1, no backing cluster) and ZERO_ALLOC (cluster
        // allocated but zeroed out), both mandated by the QCOW2 spec.
        if l2_entry & 1 != 0 {
            return Ok(ClusterRef::ZeroCluster);
        }

        let cluster_offset = l2_entry & 0x3FFF_FFFF_FFFF_FFFF;
        if cluster_offset == 0 {
            return Ok(ClusterRef::Unallocated);
        }
        Ok(ClusterRef::Normal(cluster_offset))
    }

    /// Read and raw-deflate-decompress a compressed cluster; return the
    /// full `cluster_size` bytes of decompressed data.
    ///
    /// `compressed_bytes` is an upper bound (`nb_sectors` × 512); the actual
    /// compressed stream may be shorter, and near the end of the file the read
    /// may hit EOF before reaching `compressed_bytes`. Both are normal.
    fn decompress_cluster(&mut self, file_offset: u64, compressed_bytes: usize) -> io::Result<Vec<u8>> {
        use flate2::read::DeflateDecoder;

        self.file.seek(SeekFrom::Start(file_offset))?;
        let mut raw = vec![0u8; compressed_bytes];
        let mut filled = 0;
        while filled < compressed_bytes {
            match self.file.read(&mut raw[filled..])? {
                0 => break, // EOF — normal for the last compressed cluster
                n => filled += n,
            }
        }

        let mut decoder = DeflateDecoder::new(&raw[..filled]);
        let mut out = Vec::with_capacity(self.cluster_size as usize);
        decoder.read_to_end(&mut out).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("qcow2 deflate: {e}"))
        })?;
        if out.len() < self.cluster_size as usize {
            out.resize(self.cluster_size as usize, 0);
        }
        Ok(out)
    }
}

/// Cluster location resolved from an L2 entry.
enum ClusterRef {
    Unallocated,
    ZeroCluster,
    Normal(u64),
    Compressed { file_offset: u64, compressed_bytes: usize },
}

impl<T> Read for Qcow2Reader<T>
where
    T: Read + Seek
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.virtual_disk_size || buf.is_empty() {
            return Ok(0);
        }

        let remaining_virtual = (self.virtual_disk_size - self.pos) as usize;
        let offset_in_cluster = (self.pos & (self.cluster_size - 1)) as usize;
        let remaining_in_cluster = self.cluster_size as usize - offset_in_cluster;
        let to_read = buf.len().min(remaining_virtual).min(remaining_in_cluster);

        let n = match self.cluster_ref_for(self.pos)? {
            ClusterRef::Normal(cluster_offset) => {
                let file_off = cluster_offset + offset_in_cluster as u64;
                self.file.seek(SeekFrom::Start(file_off))?;
                self.file.read(&mut buf[..to_read])?
            }
            ClusterRef::Compressed { file_offset, compressed_bytes } => {
                let decompressed = self.decompress_cluster(file_offset, compressed_bytes)?;
                let src = &decompressed[offset_in_cluster..offset_in_cluster + to_read];
                buf[..to_read].copy_from_slice(src);
                to_read
            }
            ClusterRef::ZeroCluster | ClusterRef::Unallocated => {
                buf[..to_read].fill(0);
                to_read
            }
        };

        self.pos += n as u64;
        Ok(n)
    }
}

impl<T> Seek for Qcow2Reader<T>
where
    T: Read + Seek
{
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

    /// Build a minimal valid QCOW2 v2 header (72 bytes) with arbitrary `cluster_bits`.
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
        assert_send::<Qcow2Reader<File>>();
    }

    // ── Property tests: open() never panics on arbitrary input ────────────────

    proptest::proptest! {
        #[test]
        fn open_never_panics_on_arbitrary_bytes(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..8192)
        ) {
            let f = write_tmp(&bytes);
            let _ = Qcow2Reader::open(f.path());
        }

        #[test]
        fn open_never_panics_on_valid_magic_plus_garbage(
            suffix in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..8192)
        ) {
            // Correct magic + version 2 prefix ensures the parser gets past early
            // rejection and exercises field parsing with random data.
            let mut bytes = vec![0u8; 8];
            bytes[0..4].copy_from_slice(&0x5146_49fb_u32.to_be_bytes());
            bytes[4..8].copy_from_slice(&2u32.to_be_bytes());
            bytes.extend_from_slice(&suffix);
            let f = write_tmp(&bytes);
            let _ = Qcow2Reader::open(f.path());
        }
    }

    // ── QCOW_OFLAG_ZERO (bit 0): ZERO_PLAIN clusters must read as zeros ─────────
    // L2 entry = 1 (ZERO_PLAIN): bit 62=0 (not compressed), bit 0=1 (zero flag),
    // offset field = 0. Correct behaviour: reads return cluster_size zeros.
    // Bug path: our code masks with 0x3FFF.., gets cluster_offset=1, then seeks to
    // file byte 1 and reads header bytes instead of returning zeros.
    #[test]
    fn zero_plain_cluster_reads_as_zeros() {
        use std::io::Write;

        // Build test_qcow2 but with L2[0] = 1 (ZERO_PLAIN) instead of DATA_OFFSET.
        let img = test_qcow2(&[0xABu8; 512]); // produces a valid image
        // Patch L2[0] = 1 at offset 1536 (L2_OFFSET from testutil).
        let mut patched = img.clone();
        let l2_offset = 1536usize;
        patched[l2_offset..l2_offset + 8].copy_from_slice(&1u64.to_be_bytes());

        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&patched).unwrap();
        let mut reader = Qcow2Reader::open(f.path()).expect("open");
        let mut buf = [0xFFu8; 512];
        reader.seek(SeekFrom::Start(0)).unwrap();
        reader.read_exact(&mut buf).expect("read");
        assert_eq!(
            buf,
            [0u8; 512],
            "ZERO_PLAIN cluster (L2 entry=1) must read as all zeros"
        );
    }

    // ── Differential test: bytes must match qemu-img convert -O raw output ────

    #[test]
    fn reads_match_qemu_raw_convert() {
        const QEMU_IMG: &str = "/opt/homebrew/bin/qemu-img";
        if !Path::new(QEMU_IMG).exists() {
            return;
        }
        let tmp = tempfile::tempdir().expect("tempdir");

        // 1 MiB source with a deterministic non-trivial pattern covering
        // sector boundaries and cluster boundaries (default cluster = 65536 B).
        let size: usize = 1 << 20;
        let raw_data: Vec<u8> = (0..size).map(|i| (i ^ (i >> 8)) as u8).collect();
        let raw_path = tmp.path().join("source.raw");
        std::fs::write(&raw_path, &raw_data).expect("write raw");

        let qcow2_path = tmp.path().join("test.qcow2");
        let status = std::process::Command::new(QEMU_IMG)
            .args(["convert", "-O", "qcow2",
                   raw_path.to_str().unwrap(),
                   qcow2_path.to_str().unwrap()])
            .status()
            .expect("spawn qemu-img");
        assert!(status.success(), "qemu-img convert failed");

        let mut reader = Qcow2Reader::open(&qcow2_path).expect("open");
        assert_eq!(reader.virtual_disk_size(), size as u64);

        // Sample: start, mid-sector, cluster boundary, cluster+sector, near-end.
        let cluster = 65536usize;
        for &offset in &[0usize, 511, cluster, cluster + 512, size - 512] {
            let len = 512.min(size - offset);
            let mut buf = vec![0u8; len];
            reader.seek(SeekFrom::Start(offset as u64)).expect("seek");
            reader.read_exact(&mut buf).expect("read");
            assert_eq!(
                buf,
                raw_data[offset..offset + len],
                "byte mismatch at offset {offset:#x}",
            );
        }
    }

    // ── Corpus differential test: real CirrOS image vs qemu-img convert ───────

    #[test]
    fn corpus_cirros_reads_match_qemu_raw_convert() {
        const QEMU_IMG: &str = "/opt/homebrew/bin/qemu-img";
        if !Path::new(QEMU_IMG).exists() {
            return;
        }
        let corpus = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/cirros-0.6.3-x86_64-disk.img");
        if !corpus.exists() {
            return; // skip if corpus not present
        }
        let tmp = tempfile::tempdir().expect("tempdir");
        let raw_path = tmp.path().join("cirros.raw");
        let ok = std::process::Command::new(QEMU_IMG)
            .args(["convert", "-O", "raw",
                   corpus.to_str().unwrap(),
                   raw_path.to_str().unwrap()])
            .status().expect("spawn qemu-img").success();
        assert!(ok, "qemu-img convert failed");
        let ref_data = std::fs::read(&raw_path).expect("read raw");

        let mut reader = Qcow2Reader::open(&corpus).expect("open corpus");
        assert_eq!(reader.virtual_disk_size(), ref_data.len() as u64,
            "virtual_disk_size must match reference raw length");

        // CirrOS is 112 MiB virtual. Sample across the full range:
        // MBR, partition table, multiple cluster boundaries, mid-image, near-end.
        let vsize = ref_data.len();
        let cluster = 65536usize;
        let samples = [
            0usize,               // MBR / boot sector
            446,                  // partition table entries
            510,                  // MBR boot signature (0x55 0xAA)
            cluster,              // second cluster
            cluster * 10,         // tenth cluster
            vsize / 2,            // mid-image
            vsize / 2 + cluster,  // mid-image + one cluster
            vsize - 512,          // last sector
        ];
        for &offset in &samples {
            let len = 512.min(vsize - offset);
            let mut buf = vec![0u8; len];
            reader.seek(SeekFrom::Start(offset as u64)).expect("seek");
            reader.read_exact(&mut buf).expect("read");
            assert_eq!(
                buf, ref_data[offset..offset + len],
                "byte mismatch at offset {offset:#x}",
            );
        }
    }
}
