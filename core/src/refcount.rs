//! QCOW2 refcount-based orphan detection (QEMU block format spec §5).
//!
//! A *forensically interesting* condition is a cluster that is still reachable
//! through the active L1/L2 mapping yet has a host **refcount of 0**: the
//! allocation metadata says the cluster is in use, but the refcount table says
//! it is free. This "allocated-but-unreferenced" state is a candidate for
//! orphaned or deleted guest data left behind by an inconsistent image.
//!
//! Parsing is **panic-free and bounded**: table/block walks are capped, every
//! offset is checked, and a crafted image degrades to a best-effort count
//! rather than panicking or allocating without bound.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::{Qcow2Error, Result};

/// Safety cap on the number of L1 entries we will walk.
const MAX_L1_ENTRIES: usize = 1 << 20;
/// Safety cap on the number of data clusters we will check refcounts for, so a
/// crafted huge image cannot drive unbounded work. ~16M clusters is generous
/// for forensic triage of real images.
const MAX_CLUSTERS_SCANNED: u64 = 16 << 20;

/// Summary of the refcount metadata and the orphan scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Qcow2RefcountReport {
    /// `refcount_bits = 1 << refcount_order` (v2 is always order 4 → 16 bits).
    pub refcount_order: u32,
    /// File offset of the refcount table.
    pub refcount_table_offset: u64,
    /// Number of clusters occupied by the refcount table.
    pub refcount_table_clusters: u32,
    /// Number of data clusters reachable through the active L1/L2 mapping that
    /// were examined.
    pub allocated_clusters: u64,
    /// Of those, how many had a host refcount of 0 (allocated-but-unreferenced).
    pub orphan_clusters: u64,
}

fn be_u32(data: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    if let Some(s) = data.get(off..off + 4) {
        b.copy_from_slice(s);
    }
    u32::from_be_bytes(b)
}

fn be_u64(data: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    if let Some(s) = data.get(off..off + 8) {
        b.copy_from_slice(s);
    }
    u64::from_be_bytes(b)
}

/// Read `n` big-endian u64 values starting at `offset`. Returns an empty vec on
/// any I/O failure (caller treats a missing table as "no allocations").
fn read_u64_table(file: &mut File, offset: u64, n: usize) -> Vec<u64> {
    if n == 0 || offset == 0 {
        return Vec::new();
    }
    if file.seek(SeekFrom::Start(offset)).is_err() {
        return Vec::new();
    }
    let mut buf = vec![0u8; n * 8];
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) | Err(_) => break,
            Ok(k) => filled += k,
        }
    }
    buf[..filled]
        .chunks_exact(8)
        .map(|c| {
            let mut a = [0u8; 8];
            a.copy_from_slice(c);
            u64::from_be_bytes(a)
        })
        .collect()
}

/// Look up the host refcount for cluster index `cluster_idx`.
///
/// Returns `None` when the refcount cannot be resolved (block absent or
/// out-of-range), which the caller treats as "not provably orphaned" — we only
/// count a definite refcount of 0, never guess.
fn refcount_of(
    file: &mut File,
    refcount_table: &[u64],
    cluster_idx: u64,
    refcount_bits: u32,
    cluster_size: u64,
) -> Option<u64> {
    let refcounts_per_block = (cluster_size * 8) / u64::from(refcount_bits);
    if refcounts_per_block == 0 {
        return None;
    }
    let table_idx = (cluster_idx / refcounts_per_block) as usize;
    let block_idx = cluster_idx % refcounts_per_block;

    let entry = *refcount_table.get(table_idx)?;
    // Mask off the reserved low bits to get the block's cluster-aligned offset.
    let block_offset = entry & !(cluster_size - 1);
    if block_offset == 0 {
        // No refcount block allocated for this range ⇒ refcount 0.
        return Some(0);
    }

    // Bit offset of this entry within the block.
    let bit_off = block_idx * u64::from(refcount_bits);
    let byte_off = block_offset + (bit_off / 8);

    match refcount_bits {
        8 => {
            let mut b = [0u8; 1];
            read_at(file, byte_off, &mut b)?;
            Some(u64::from(b[0]))
        }
        16 => {
            let mut b = [0u8; 2];
            read_at(file, byte_off, &mut b)?;
            Some(u64::from(u16::from_be_bytes(b)))
        }
        32 => {
            let mut b = [0u8; 4];
            read_at(file, byte_off, &mut b)?;
            Some(u64::from(u32::from_be_bytes(b)))
        }
        64 => {
            let mut b = [0u8; 8];
            read_at(file, byte_off, &mut b)?;
            Some(u64::from_be_bytes(b))
        }
        // Sub-byte widths (1, 2, 4 bits): extract the relevant bits from one byte.
        bits @ (1 | 2 | 4) => {
            let mut b = [0u8; 1];
            read_at(file, byte_off, &mut b)?;
            let within = (bit_off % 8) as u32;
            let mask = (1u64 << bits) - 1;
            // QCOW2 packs sub-byte refcounts MSB-first within each byte.
            let shift = 8 - within - bits;
            Some((u64::from(b[0]) >> shift) & mask)
        }
        _ => None,
    }
}

/// Read exactly `buf.len()` bytes at absolute `offset`. Returns `None` on any
/// seek/read failure (treated as unresolved, never as a false orphan).
fn read_at(file: &mut File, offset: u64, buf: &mut [u8]) -> Option<()> {
    file.seek(SeekFrom::Start(offset)).ok()?;
    file.read_exact(buf).ok()?;
    Some(())
}

/// Best-effort refcount/orphan report for the QCOW2 image at `path`.
///
/// Walks the active L1→L2 mapping to collect allocated data-cluster host
/// offsets, then resolves each one's refcount through the refcount table. A
/// cluster whose refcount is provably 0 is counted as an orphan. Unresolvable
/// refcounts are conservatively skipped — never reported as orphans.
pub fn refcount_report(path: &Path) -> Result<Qcow2RefcountReport> {
    let mut file = File::open(path)?;

    let mut hdr = [0u8; 104];
    let n = file.read(&mut hdr)?;
    let hdr = &hdr[..n];
    if hdr.len() < crate::header::MIN_HEADER_SIZE {
        return Err(Qcow2Error::FileTooSmall);
    }
    if be_u32(hdr, 0) != crate::header::MAGIC {
        return Err(Qcow2Error::BadMagic);
    }
    let version = be_u32(hdr, 4);
    if !(2..=3).contains(&version) {
        return Err(Qcow2Error::UnsupportedVersion(version));
    }

    let cluster_bits = be_u32(hdr, 20);
    if !(9..=20).contains(&cluster_bits) {
        return Err(Qcow2Error::ClusterBitsOutOfRange(cluster_bits));
    }
    let cluster_size = 1u64 << cluster_bits;

    let l1_size = be_u32(hdr, 36) as usize;
    let l1_table_offset = be_u64(hdr, 40);
    let refcount_table_offset = be_u64(hdr, 48);
    let refcount_table_clusters = be_u32(hdr, 56);

    // refcount_order: v3 field at offset 96, else the v2-mandated default of 4.
    let refcount_order = if version == 3 && hdr.len() >= 100 {
        be_u32(hdr, 96)
    } else {
        4
    };
    // Guard against a crafted order that would overflow the shift / divide.
    if refcount_order > 6 {
        return Ok(Qcow2RefcountReport {
            refcount_order,
            refcount_table_offset,
            refcount_table_clusters,
            allocated_clusters: 0,
            orphan_clusters: 0,
        });
    }
    let refcount_bits = 1u32 << refcount_order;

    // Load the refcount table (an array of u64 block pointers).
    let rt_entries = (u64::from(refcount_table_clusters) * cluster_size / 8) as usize;
    let rt_entries = rt_entries.min(MAX_L1_ENTRIES);
    let refcount_table = read_u64_table(&mut file, refcount_table_offset, rt_entries);

    // Load the active L1 table.
    let l1_entries = l1_size.min(MAX_L1_ENTRIES);
    let l1_table = read_u64_table(&mut file, l1_table_offset, l1_entries);

    let l2_entries_per_table = cluster_size / 8;

    let mut allocated_clusters: u64 = 0;
    let mut orphan_clusters: u64 = 0;

    'outer: for &l1_entry in &l1_table {
        let l2_offset = l1_entry & 0x00ff_ffff_ffff_fe00;
        if l2_offset == 0 {
            continue;
        }
        let l2 = read_u64_table(&mut file, l2_offset, l2_entries_per_table as usize);
        for &l2_entry in &l2 {
            // Compressed clusters (bit 62) use a packed descriptor — skip them
            // for the orphan scan; their host offset is not cluster-aligned.
            if l2_entry & (1 << 62) != 0 {
                continue;
            }
            // ZERO flag (bit 0) clusters carry no real host data.
            if l2_entry & 1 != 0 {
                continue;
            }
            let host_offset = l2_entry & 0x00ff_ffff_ffff_fe00;
            if host_offset == 0 {
                continue; // unallocated
            }
            allocated_clusters += 1;
            if allocated_clusters > MAX_CLUSTERS_SCANNED {
                break 'outer;
            }
            let cluster_idx = host_offset / cluster_size;
            if let Some(0) = refcount_of(
                &mut file,
                &refcount_table,
                cluster_idx,
                refcount_bits,
                cluster_size,
            ) {
                orphan_clusters += 1;
            }
        }
    }

    Ok(Qcow2RefcountReport {
        refcount_order,
        refcount_table_offset,
        refcount_table_clusters,
        allocated_clusters,
        orphan_clusters,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::Write;

    const CB: u32 = 9; // 512-byte clusters keep the synthetic image tiny
    const CS: u64 = 1 << CB;

    fn write_tmp(data: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(data).unwrap();
        f
    }

    /// Build a minimal v3 QCOW2 with one data cluster whose refcount we control.
    /// Layout (512-byte clusters): 0=header, 1=L1, 2=refcount table,
    /// 3=refcount block, 4=L2, 5=data.
    fn build(refcount_value: u16) -> Vec<u8> {
        let l1_off = CS;
        let rt_off = CS * 2;
        let block_off = CS * 3;
        let l2_off = CS * 4;
        let data_off = CS * 5;

        let mut img = vec![0u8; (CS * 6) as usize];

        // Header.
        img[0..4].copy_from_slice(&crate::header::MAGIC.to_be_bytes());
        img[4..8].copy_from_slice(&3u32.to_be_bytes());
        img[20..24].copy_from_slice(&CB.to_be_bytes());
        img[24..32].copy_from_slice(&CS.to_be_bytes()); // disk_size
        img[36..40].copy_from_slice(&1u32.to_be_bytes()); // l1_size
        img[40..48].copy_from_slice(&l1_off.to_be_bytes());
        img[48..56].copy_from_slice(&rt_off.to_be_bytes());
        img[56..60].copy_from_slice(&1u32.to_be_bytes()); // refcount_table_clusters
        img[96..100].copy_from_slice(&4u32.to_be_bytes()); // refcount_order = 16-bit
        img[100..104].copy_from_slice(&104u32.to_be_bytes()); // header_length

        // L1[0] → L2 table (set COPIED bit 63 like qemu does).
        let l1e = l2_off | (1 << 63);
        img[l1_off as usize..l1_off as usize + 8].copy_from_slice(&l1e.to_be_bytes());

        // Refcount table[0] → refcount block.
        img[rt_off as usize..rt_off as usize + 8].copy_from_slice(&block_off.to_be_bytes());

        // Refcount block: entry for data cluster index (data_off / CS = 5).
        let data_cluster_idx = (data_off / CS) as usize;
        let block_entry = block_off as usize + data_cluster_idx * 2; // 16-bit entries
        img[block_entry..block_entry + 2].copy_from_slice(&refcount_value.to_be_bytes());

        // L2[0] → data cluster (COPIED bit 63).
        let l2e = data_off | (1 << 63);
        img[l2_off as usize..l2_off as usize + 8].copy_from_slice(&l2e.to_be_bytes());

        img
    }

    #[test]
    fn referenced_cluster_is_not_an_orphan() {
        let f = write_tmp(&build(1));
        let r = refcount_report(f.path()).unwrap();
        assert_eq!(r.refcount_order, 4);
        assert_eq!(r.allocated_clusters, 1);
        assert_eq!(r.orphan_clusters, 0);
    }

    #[test]
    fn refcount_zero_cluster_is_flagged_as_orphan() {
        let f = write_tmp(&build(0));
        let r = refcount_report(f.path()).unwrap();
        assert_eq!(r.allocated_clusters, 1);
        assert_eq!(r.orphan_clusters, 1, "refcount-0 allocated cluster is orphaned");
    }

    #[test]
    fn missing_refcount_block_means_orphan() {
        // Zero the refcount table[0] pointer ⇒ no block ⇒ refcount 0.
        let mut img = build(7);
        let rt_off = (CS * 2) as usize;
        img[rt_off..rt_off + 8].copy_from_slice(&0u64.to_be_bytes());
        let f = write_tmp(&img);
        let r = refcount_report(f.path()).unwrap();
        assert_eq!(r.orphan_clusters, 1);
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut img = build(1);
        img[0] = 0;
        let f = write_tmp(&img);
        assert!(matches!(refcount_report(f.path()), Err(Qcow2Error::BadMagic)));
    }

    #[test]
    fn too_small_is_rejected() {
        let f = write_tmp(&[0u8; 8]);
        assert!(matches!(
            refcount_report(f.path()),
            Err(Qcow2Error::FileTooSmall)
        ));
    }

    #[test]
    fn bad_version_is_rejected() {
        let mut img = build(1);
        img[4..8].copy_from_slice(&7u32.to_be_bytes());
        let f = write_tmp(&img);
        assert!(matches!(
            refcount_report(f.path()),
            Err(Qcow2Error::UnsupportedVersion(7))
        ));
    }

    #[test]
    fn bad_cluster_bits_is_rejected() {
        let mut img = build(1);
        img[20..24].copy_from_slice(&30u32.to_be_bytes());
        let f = write_tmp(&img);
        assert!(matches!(
            refcount_report(f.path()),
            Err(Qcow2Error::ClusterBitsOutOfRange(30))
        ));
    }

    #[test]
    fn oversized_refcount_order_is_reported_without_scanning() {
        let mut img = build(1);
        img[96..100].copy_from_slice(&9u32.to_be_bytes()); // order > 6
        let f = write_tmp(&img);
        let r = refcount_report(f.path()).unwrap();
        assert_eq!(r.refcount_order, 9);
        assert_eq!(r.allocated_clusters, 0);
        assert_eq!(r.orphan_clusters, 0);
    }

    #[test]
    fn compressed_and_zero_clusters_are_skipped() {
        let mut img = build(1);
        // Overwrite L2[0] with a compressed-cluster entry (bit 62 set).
        let l2_off = (CS * 4) as usize;
        let comp = (1u64 << 62) | 0x1234;
        img[l2_off..l2_off + 8].copy_from_slice(&comp.to_be_bytes());
        let f = write_tmp(&img);
        let r = refcount_report(f.path()).unwrap();
        assert_eq!(r.allocated_clusters, 0, "compressed cluster is not counted");
    }

    #[test]
    fn zero_flag_cluster_is_skipped() {
        let mut img = build(1);
        let l2_off = (CS * 4) as usize;
        img[l2_off..l2_off + 8].copy_from_slice(&1u64.to_be_bytes()); // ZERO flag
        let f = write_tmp(&img);
        let r = refcount_report(f.path()).unwrap();
        assert_eq!(r.allocated_clusters, 0);
    }

    #[test]
    fn v2_defaults_to_order_four() {
        let mut img = build(1);
        img[4..8].copy_from_slice(&2u32.to_be_bytes()); // version 2
        img[96..100].copy_from_slice(&0u32.to_be_bytes()); // ignored for v2
        let f = write_tmp(&img);
        let r = refcount_report(f.path()).unwrap();
        assert_eq!(r.refcount_order, 4);
    }

    #[test]
    fn open_nonexistent_is_io_error() {
        assert!(refcount_report(Path::new("/tmp/no_such_qcow2_rc.qcow2")).is_err());
    }
}
