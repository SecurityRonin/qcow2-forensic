//! Minimal valid QCOW2 v2 builder for use in tests and downstream crates.
//!
//! Uses cluster_bits = 9 (512-byte clusters) so the test file stays small.

use super::header::MAGIC;

pub const CLUSTER_BITS: u32 = 9;
pub const CLUSTER_SIZE: usize = 1 << CLUSTER_BITS; // 512 bytes

// File layout (each cluster = 512 bytes):
//   Cluster 0 (offset    0): Header
//   Cluster 1 (offset  512): L1 table (1 entry)
//   Cluster 2 (offset 1024): Refcount table (unused by read-only reader)
//   Cluster 3 (offset 1536): L2 table (CLUSTER_SIZE/8 = 64 entries)
//   Cluster 4 (offset 2048): Data cluster
const L1_OFFSET: u64 = 512;
const REFCOUNT_OFFSET: u64 = 1024;
const L2_OFFSET: u64 = 1536;
const DATA_OFFSET: u64 = 2048;

/// Build a minimal valid QCOW2 v2 image containing `sector_data` in cluster 0.
///
/// `sector_data` is zero-padded or truncated to [`CLUSTER_SIZE`].
#[cfg_attr(not(any(test, feature = "test-helpers")), allow(dead_code))]
pub fn test_qcow2(sector_data: &[u8]) -> Vec<u8> {
    // ── Header (padded to one cluster) ────────────────────────────────────────
    let mut hdr = vec![0u8; CLUSTER_SIZE];
    hdr[0..4].copy_from_slice(&MAGIC.to_be_bytes());
    hdr[4..8].copy_from_slice(&2u32.to_be_bytes());                               // version = 2
    hdr[20..24].copy_from_slice(&CLUSTER_BITS.to_be_bytes());
    hdr[24..32].copy_from_slice(&(CLUSTER_SIZE as u64).to_be_bytes());            // disk_size
    hdr[36..40].copy_from_slice(&1u32.to_be_bytes());                             // l1_size = 1
    hdr[40..48].copy_from_slice(&L1_OFFSET.to_be_bytes());
    hdr[48..56].copy_from_slice(&REFCOUNT_OFFSET.to_be_bytes());
    hdr[56..60].copy_from_slice(&1u32.to_be_bytes());                             // refcount_table_clusters = 1

    // ── L1 table ──────────────────────────────────────────────────────────────
    let mut l1 = vec![0u8; CLUSTER_SIZE];
    l1[0..8].copy_from_slice(&L2_OFFSET.to_be_bytes()); // L1[0] → L2 table

    // ── Refcount table (all zeros, not used by reader) ────────────────────────
    let refcount = vec![0u8; CLUSTER_SIZE];

    // ── L2 table (first entry → data cluster, rest unallocated) ──────────────
    let mut l2 = vec![0u8; CLUSTER_SIZE];
    l2[0..8].copy_from_slice(&DATA_OFFSET.to_be_bytes()); // L2[0] → data

    // ── Data cluster ──────────────────────────────────────────────────────────
    let mut data = vec![0u8; CLUSTER_SIZE];
    let n = sector_data.len().min(CLUSTER_SIZE);
    data[..n].copy_from_slice(&sector_data[..n]);

    // ── Assemble ──────────────────────────────────────────────────────────────
    let mut img = Vec::new();
    img.extend_from_slice(&hdr);
    img.extend_from_slice(&l1);
    img.extend_from_slice(&refcount);
    img.extend_from_slice(&l2);
    img.extend_from_slice(&data);
    img
}
