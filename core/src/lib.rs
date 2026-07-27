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

/// A seekable, thread-safe byte source the reader can sit on: a `File`, an
/// in-RAM `Cursor`, or a positioned sub-range of a `.zip`. Lets a caller open a
/// QCOW2 image straight out of an archive (no temp-file extraction) via
/// [`Qcow2Reader::open_reader`], while [`Qcow2Reader::open`] keeps the
/// file-path convenience.
pub trait ReadSeekSend: Read + Seek + Send + Sync {}
impl<T: Read + Seek + Send + Sync> ReadSeekSend for T {}

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
pub struct Qcow2Reader {
    backing: Box<dyn ReadSeekSend>,
    virtual_disk_size: u64,
    cluster_size: u64,
    l1_table: Vec<u64>, // L1 entries (masked byte offsets of L2 tables)
    l2_bits: u32,       // log2(entries per L2 table)
    l2_mask: u64,
    pos: u64,
}

impl Qcow2Reader {
    /// Open a QCOW2 disk image (v2 or v3, uncompressed, no backing file).
    pub fn open(path: &Path) -> Result<Self, Qcow2Error> {
        Self::from_backing(Box::new(File::open(path)?))
    }

    /// Open a QCOW2 image from any seekable byte source (a `Cursor` over
    /// inflated bytes, a positioned sub-range of a `.zip`, …) rather than a file
    /// path — so an image stored inside an archive can be read without
    /// extracting it to a temp file first.
    pub fn open_reader(backing: Box<dyn ReadSeekSend>) -> Result<Self, Qcow2Error> {
        Self::from_backing(backing)
    }

    /// Parse the header + L1 table off any seekable backing and build the reader.
    /// Shared by [`Self::open`] (a file) and [`Self::open_reader`] (a Cursor /
    /// zip sub-range).
    fn from_backing(mut backing: Box<dyn ReadSeekSend>) -> Result<Self, Qcow2Error> {
        // 8 MiB max L1 table — prevents OOM on crafted images.
        const MAX_L1_ENTRIES: u32 = 1 << 20;

        // Read enough bytes to cover both v2 (72 bytes) and v3 (104 bytes) headers.
        let mut hdr_buf = [0u8; 104];
        let hdr_read = backing.read(&mut hdr_buf)?;
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
        backing.seek(SeekFrom::Start(hdr.l1_table_offset))?;
        let l1_bytes = u64::from(hdr.l1_size) * 8;
        let mut l1_buf = vec![0u8; l1_bytes as usize];
        backing.read_exact(&mut l1_buf)?;
        let l1_table: Vec<u64> = l1_buf
            .chunks_exact(8)
            .map(|c| {
                let mut a = [0u8; 8];
                a.copy_from_slice(c); // chunks_exact(8) guarantees len == 8
                u64::from_be_bytes(a)
            })
            .collect();

        Ok(Qcow2Reader {
            backing,
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
        self.backing.seek(SeekFrom::Start(l2_entry_pos))?;
        let mut l2_bytes = [0u8; 8];
        self.backing.read_exact(&mut l2_bytes)?;
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
            return Ok(ClusterRef::Compressed {
                file_offset,
                compressed_bytes,
            });
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
    fn decompress_cluster(
        &mut self,
        file_offset: u64,
        compressed_bytes: usize,
    ) -> io::Result<Vec<u8>> {
        use flate2::read::DeflateDecoder;

        self.backing.seek(SeekFrom::Start(file_offset))?;
        let mut raw = vec![0u8; compressed_bytes];
        let mut filled = 0;
        while filled < compressed_bytes {
            match self.backing.read(&mut raw[filled..])? {
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
    Compressed {
        file_offset: u64,
        compressed_bytes: usize,
    },
}

impl Read for Qcow2Reader {
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
                self.backing.seek(SeekFrom::Start(file_off))?;
                self.backing.read(&mut buf[..to_read])?
            }
            ClusterRef::Compressed {
                file_offset,
                compressed_bytes,
            } => {
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

// ── forensic-vfs integration ──────────────────────────────────────────────────

#[cfg(feature = "vfs")]
mod vfs;
#[cfg(feature = "vfs")]
pub use vfs::Qcow2Source;

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
    fn open_reader_over_cursor_matches_open_path() {
        use std::io::{Cursor, Read};
        // A real QCOW2 image with known sector content.
        let sector: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let image = test_qcow2(&sector);

        // Oracle: open(path) and read the whole virtual disk.
        let tmp = write_tmp(&image);
        let mut via_path = Qcow2Reader::open(tmp.path()).expect("open path");
        let mut want = Vec::new();
        via_path.read_to_end(&mut want).expect("read path");

        // Under test: open_reader over an in-RAM Cursor of the SAME bytes — the
        // zip-direct backing path.
        let mut via_reader =
            Qcow2Reader::open_reader(Box::new(Cursor::new(image.clone()))).expect("open_reader");
        let mut got = Vec::new();
        via_reader.read_to_end(&mut got).expect("read reader");

        assert_eq!(
            got, want,
            "open_reader must read byte-identically to open(path)"
        );
        assert_eq!(via_reader.virtual_disk_size(), via_path.virtual_disk_size());
    }

    /// A backing that returns at most one byte per `read()`, wrapping any inner
    /// seekable source. `open_reader` accepts arbitrary `Read + Seek` backings,
    /// which are free to short-read; this locks in that the header parse does not
    /// assume a single `read()` fills its 104-byte window.
    struct OneByteAtATime<R>(R);

    impl<R: Read> Read for OneByteAtATime<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            self.0.read(&mut buf[..1])
        }
    }

    impl<R: Seek> Seek for OneByteAtATime<R> {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.0.seek(pos)
        }
    }

    #[test]
    fn chunking_backing_still_opens() {
        use std::io::{Cursor, Read};
        let sector: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let image = test_qcow2(&sector);

        // Oracle: open(path) and read the whole virtual disk.
        let tmp = write_tmp(&image);
        let mut via_path = Qcow2Reader::open(tmp.path()).expect("open path");
        let mut want = Vec::new();
        via_path.read_to_end(&mut want).expect("read path");

        // Under test: a backing that hands back one byte at a time. A valid image
        // must still open and read byte-identically — with a single-`read()`
        // header assumption it is silently mis-rejected instead.
        let backing = OneByteAtATime(Cursor::new(image.clone()));
        let mut via_reader = Qcow2Reader::open_reader(Box::new(backing)).expect("open_reader");
        let mut got = Vec::new();
        via_reader.read_to_end(&mut got).expect("read reader");

        assert_eq!(got, want, "chunking backing must read byte-identically");
        assert_eq!(via_reader.virtual_disk_size(), via_path.virtual_disk_size());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Build a minimal valid QCOW2 v2 header (72 bytes) with arbitrary `cluster_bits`.
    fn qcow2_header_bytes(cluster_bits: u32) -> Vec<u8> {
        let mut h = vec![0u8; 72];
        h[0..4].copy_from_slice(&0x5146_49fb_u32.to_be_bytes()); // magic
        h[4..8].copy_from_slice(&2u32.to_be_bytes()); // version 2
                                                      // bytes 8..16: backing_file_offset = 0
                                                      // bytes 16..20: backing_file_size = 0
        h[20..24].copy_from_slice(&cluster_bits.to_be_bytes()); // cluster_bits
        h[24..32].copy_from_slice(&512u64.to_be_bytes()); // disk_size
                                                          // bytes 32..36: encryption = 0
        h[36..40].copy_from_slice(&0u32.to_be_bytes()); // l1_size = 0
        h[40..48].copy_from_slice(&0u64.to_be_bytes()); // l1_table_offset
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
            buf, [0u8; 512],
            "ZERO_PLAIN cluster (L2 entry=1) must read as all zeros"
        );
    }

    // The Tier-1 differential validation against `qemu-img convert` output and
    // the real CirrOS corpus lives in `core/tests/real_images.rs` and
    // `core/tests/corpus.rs` — env-gated oracle tests that skip cleanly when the
    // tool / large image is absent. Those tests are the correctness path; per the
    // deterministic-coverage-fixtures discipline they must NOT drive the coverage
    // gate. The synthetic byte-buffer tests below cover the same production paths
    // (compressed clusters, unallocated/zero clusters, seek variants, L1-size
    // guard) from committed bytes alone, so the coverage number holds on a fresh
    // clone with no external tool.

    // ── Synthetic coverage fixtures (committed bytes, no external tool) ────────

    /// Deflate-compress `plain` with a raw (headerless) deflate stream, matching
    /// what a QCOW2 compressed cluster stores.
    fn raw_deflate(plain: &[u8]) -> Vec<u8> {
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(plain).unwrap();
        enc.finish().unwrap()
    }

    /// Build a minimal QCOW2 (512-byte clusters) whose single data cluster is a
    /// compressed (raw-deflate) stream, so reads exercise the decompression path.
    ///
    /// Layout: 0=header, 1=L1, 2=refcount(unused), 3=L2, 4=compressed data.
    fn compressed_qcow2(plain: &[u8]) -> Vec<u8> {
        use testutil::{CLUSTER_BITS, CLUSTER_SIZE};
        let cs = CLUSTER_SIZE as u64;
        let l1_off = cs;
        let l2_off = cs * 3;
        let data_off = cs * 4;

        let compressed = raw_deflate(plain);
        let nb_sectors = compressed.len().div_ceil(512).max(1) as u64;

        let mut img = vec![0u8; data_off as usize];
        // Header.
        img[0..4].copy_from_slice(&crate::header::MAGIC.to_be_bytes());
        img[4..8].copy_from_slice(&2u32.to_be_bytes());
        img[20..24].copy_from_slice(&CLUSTER_BITS.to_be_bytes());
        img[24..32].copy_from_slice(&cs.to_be_bytes()); // disk_size = one cluster
        img[36..40].copy_from_slice(&1u32.to_be_bytes()); // l1_size = 1
        img[40..48].copy_from_slice(&l1_off.to_be_bytes());
        // L1[0] → L2 table.
        img[l1_off as usize..l1_off as usize + 8].copy_from_slice(&l2_off.to_be_bytes());
        // L2[0] → compressed descriptor: bit 62 set; low (63 - cluster_bits) bits
        // hold the file byte offset; next (cluster_bits - 1) bits hold
        // (nb_sectors - 1).
        let split = 63u32 - CLUSTER_BITS;
        let desc = (1u64 << 62) | ((nb_sectors - 1) << split) | data_off;
        img[l2_off as usize..l2_off as usize + 8].copy_from_slice(&desc.to_be_bytes());
        // Append the compressed stream.
        img.extend_from_slice(&compressed);
        img
    }

    #[test]
    fn compressed_cluster_decompresses_to_original_bytes() {
        // A pattern that both compresses well and shrinks below one cluster, so
        // the decompressor's short-output resize-to-cluster path also runs.
        let mut plain = vec![0u8; testutil::CLUSTER_SIZE];
        for (i, b) in plain.iter_mut().enumerate() {
            *b = ((i / 8) % 251) as u8;
        }
        let img = compressed_qcow2(&plain);
        let mut reader =
            Qcow2Reader::open_reader(Box::new(std::io::Cursor::new(img))).expect("open");
        let mut got = vec![0u8; testutil::CLUSTER_SIZE];
        reader
            .read_exact(&mut got)
            .expect("read compressed cluster");
        assert_eq!(got, plain, "compressed cluster must decode to the original");
    }

    #[test]
    fn short_compressed_stream_resizes_to_full_cluster() {
        // A deflate stream whose decompressed length is SHORTER than one cluster
        // drives the `out.len() < cluster_size` resize-with-zeros branch: the
        // read must still return a full, zero-padded cluster.
        let half = testutil::CLUSTER_SIZE / 2;
        let plain: Vec<u8> = (0..half).map(|i| (i % 253) as u8).collect();
        let img = compressed_qcow2(&plain);
        let mut reader =
            Qcow2Reader::open_reader(Box::new(std::io::Cursor::new(img))).expect("open");
        let mut got = vec![0xFFu8; testutil::CLUSTER_SIZE];
        reader.read_exact(&mut got).expect("read");
        let mut want = vec![0u8; testutil::CLUSTER_SIZE];
        want[..half].copy_from_slice(&plain);
        assert_eq!(
            got, want,
            "short deflate output is zero-padded to a cluster"
        );
    }

    #[test]
    fn corrupt_compressed_stream_errors_not_panics() {
        // A compressed descriptor pointing at non-deflate bytes must surface an
        // InvalidData error, never panic.
        let mut img = compressed_qcow2(&[0xAB; 64]);
        // Clobber the compressed stream (everything past the data cluster start).
        let data_off = testutil::CLUSTER_SIZE * 4;
        for b in &mut img[data_off..] {
            *b = 0xFF;
        }
        let mut reader =
            Qcow2Reader::open_reader(Box::new(std::io::Cursor::new(img))).expect("open");
        let mut buf = vec![0u8; testutil::CLUSTER_SIZE];
        assert!(
            reader.read_exact(&mut buf).is_err(),
            "corrupt deflate stream must error, not panic"
        );
    }

    #[test]
    fn unallocated_cluster_reads_as_zeros() {
        // L2[0] = 0 (unallocated) — a read must yield zeros, exercising the
        // Unallocated arm reached via an all-zero L2 entry with a set L1.
        let img = test_qcow2(&[0xAB; 512]);
        let mut patched = img.clone();
        // Zero L2[0] at offset 1536 (L2_OFFSET) so cluster_offset resolves to 0.
        patched[1536..1544].copy_from_slice(&0u64.to_be_bytes());
        let mut reader = Qcow2Reader::open(write_tmp(&patched).path()).expect("open");
        let mut buf = [0xFFu8; 512];
        reader.read_exact(&mut buf).expect("read");
        assert_eq!(buf, [0u8; 512], "unallocated cluster reads as zeros");
    }

    #[test]
    fn unset_l1_entry_reads_as_zeros() {
        // L1[0] = 0 — the whole L2 table is absent, so cluster_ref_for returns
        // Unallocated at the L1 stage (the `l2_table_offset == 0` arm).
        let img = test_qcow2(&[0xAB; 512]);
        let mut patched = img.clone();
        // Zero L1[0] at offset 512 (L1_OFFSET).
        patched[512..520].copy_from_slice(&0u64.to_be_bytes());
        let mut reader = Qcow2Reader::open(write_tmp(&patched).path()).expect("open");
        let mut buf = [0xFFu8; 512];
        reader.read_exact(&mut buf).expect("read");
        assert_eq!(buf, [0u8; 512], "unset L1 entry reads as zeros");
    }

    #[test]
    fn seek_from_current_and_end_and_reject_negative() {
        let img = test_qcow2(&[0u8; 512]);
        let mut reader = Qcow2Reader::open(write_tmp(&img).path()).expect("open");
        // SeekFrom::Current advances relative to the current position.
        assert_eq!(reader.seek(SeekFrom::Current(10)).unwrap(), 10);
        assert_eq!(reader.seek(SeekFrom::Current(5)).unwrap(), 15);
        // SeekFrom::End is relative to the virtual disk size.
        assert_eq!(
            reader.seek(SeekFrom::End(-4)).unwrap(),
            testutil::CLUSTER_SIZE as u64 - 4
        );
        assert_eq!(
            reader.seek(SeekFrom::End(0)).unwrap(),
            testutil::CLUSTER_SIZE as u64
        );
        // A seek before the start is rejected (InvalidInput), never a panic.
        assert!(reader.seek(SeekFrom::Current(-1000)).is_err());
        assert!(reader.seek(SeekFrom::Start(0)).is_ok());
        assert!(reader.seek(SeekFrom::End(-100_000)).is_err());
    }

    #[test]
    fn l1_size_over_cap_is_rejected() {
        // l1_size above MAX_L1_ENTRIES (1 << 20) must error, not allocate.
        let mut h = qcow2_header_bytes(9);
        h[36..40].copy_from_slice(&((1u32 << 20) + 1).to_be_bytes()); // l1_size
        assert!(matches!(
            Qcow2Reader::open(write_tmp(&h).path()),
            Err(Qcow2Error::L1TableTooLarge(_))
        ));
    }
}
