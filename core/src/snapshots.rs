//! QCOW2 internal snapshot table enumeration (QEMU block format spec §6).
//!
//! The header records `nb_snapshots` (offset 60, u32 BE) and `snapshots_offset`
//! (offset 64, u64 BE). The snapshot table is a packed array of
//! `QcowSnapshotHeader` records, each followed by its variable-length extra
//! data, id string, and name string. All fields are big-endian.
//!
//! Parsing is **panic-free and bounded**: counts and string sizes are capped so
//! a crafted image cannot drive unbounded allocation or out-of-range reads.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::{Qcow2Error, Result};

/// Maximum number of snapshots we will enumerate from one image. QEMU itself has
/// no hard cap, but real images carry a handful; this defends against a crafted
/// `nb_snapshots` driving unbounded work.
const MAX_SNAPSHOTS: u32 = 65_536;

/// Maximum id/name string length we will read for a single snapshot. The QCOW2
/// spec does not bound these, but real ids/names are short; cap to defend
/// against a crafted `id_str_size`/`name_size`.
const MAX_STR_LEN: u32 = 65_536;

/// Maximum extra-data length we will skip over for a single snapshot entry.
const MAX_EXTRA_DATA: u32 = 65_536;

/// Fixed portion of a snapshot table entry (QCOW2 spec §6, big-endian):
/// `l1_table_offset` u64, `l1_size` u32, `id_str_size` u16, `name_size` u16,
/// `date_sec` u32, `date_nsec` u32, `vm_clock_nsec` u64, `vm_state_size` u32,
/// `extra_data_size` u32 — 40 bytes total before extra/id/name.
const SNAPSHOT_HEADER_FIXED: usize = 40;

/// One internal snapshot recorded in a QCOW2 image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Qcow2Snapshot {
    /// Unique id string (QEMU assigns "1", "2", … by default).
    pub id: String,
    /// Human-readable snapshot name (e.g. "snap1").
    pub name: String,
    /// Snapshot creation time — seconds since the Unix epoch.
    pub date_unix_secs: u32,
    /// Sub-second portion of the creation time, in nanoseconds.
    pub date_nsecs: u32,
    /// Saved VM state size in bytes (0 = disk-only snapshot).
    pub vm_state_size: u32,
}

/// Read a big-endian `u16` at `off`. Never panics: out-of-range reads yield 0.
fn be_u16(data: &[u8], off: usize) -> u16 {
    let mut b = [0u8; 2];
    if let Some(s) = data.get(off..off + 2) {
        b.copy_from_slice(s);
    }
    u16::from_be_bytes(b)
}

/// Read a big-endian `u32` at `off`. Never panics: out-of-range reads yield 0.
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

/// Enumerate the internal snapshots in the QCOW2 image at `path`.
///
/// Returns an empty vec for images with no snapshots. Malformed snapshot tables
/// degrade gracefully: enumeration stops at the first record that cannot be read
/// in full rather than panicking or erroring out, so a partially-recoverable
/// table still yields the snapshots that parsed cleanly.
pub fn snapshots(path: &Path) -> Result<Vec<Qcow2Snapshot>> {
    let mut file = File::open(path)?;

    // Read the 104-byte header window (covers v2 72-byte + v3 fields).
    let mut hdr = [0u8; 104];
    let n = file.read(&mut hdr)?;
    let hdr = &hdr[..n];
    if hdr.len() < crate::header::MIN_HEADER_SIZE {
        return Err(Qcow2Error::FileTooSmall);
    }
    if be_u32(hdr, 0) != crate::header::MAGIC {
        return Err(Qcow2Error::BadMagic);
    }

    let nb_snapshots = be_u32(hdr, 60).min(MAX_SNAPSHOTS);
    let snapshots_offset = be_u64(hdr, 64);
    if nb_snapshots == 0 || snapshots_offset == 0 {
        return Ok(Vec::new());
    }

    file.seek(SeekFrom::Start(snapshots_offset))?;
    let mut out = Vec::with_capacity(nb_snapshots as usize);

    for _ in 0..nb_snapshots {
        // Read the fixed 40-byte record header. A short read means the table is
        // truncated — stop with what we have rather than fail the whole image.
        let mut fixed = [0u8; SNAPSHOT_HEADER_FIXED];
        if read_full(&mut file, &mut fixed).is_err() {
            break;
        }

        let id_str_size = u32::from(be_u16(&fixed, 12)).min(MAX_STR_LEN);
        let name_size = u32::from(be_u16(&fixed, 14)).min(MAX_STR_LEN);
        let date_unix_secs = be_u32(&fixed, 16);
        let date_nsecs = be_u32(&fixed, 20);
        let vm_state_size = be_u32(&fixed, 32);
        let extra_data_size = be_u32(&fixed, 36).min(MAX_EXTRA_DATA);

        // Skip the extra-data area (we read the canonical 32-bit vm_state_size).
        if extra_data_size > 0 && skip(&mut file, u64::from(extra_data_size)).is_err() {
            break;
        }

        let Some(id) = read_string(&mut file, id_str_size) else {
            break;
        };
        let Some(name) = read_string(&mut file, name_size) else {
            break;
        };

        // The snapshot table is 8-byte aligned between entries (QEMU pads each
        // record up to the next multiple of 8). Align to the next boundary.
        let consumed = SNAPSHOT_HEADER_FIXED
            + extra_data_size as usize
            + id_str_size as usize
            + name_size as usize;
        let pad = (8 - (consumed % 8)) % 8;
        if pad > 0 && skip(&mut file, pad as u64).is_err() {
            // Last entry padding may run into EOF; that is harmless because we
            // already captured this snapshot.
        }

        out.push(Qcow2Snapshot {
            id,
            name,
            date_unix_secs,
            date_nsecs,
            vm_state_size,
        });
    }

    Ok(out)
}

/// Read exactly `buf.len()` bytes, returning `Err` on EOF.
fn read_full(file: &mut File, buf: &mut [u8]) -> std::io::Result<()> {
    file.read_exact(buf)
}

/// Advance the file cursor by `n` bytes, but only within the file. Seeking past
/// EOF is legal at the OS level, so we reject a skip that would land beyond the
/// end — a crafted `extra_data_size`/padding pointing past EOF is truncation,
/// not a valid record, and must not silently yield a bogus empty entry.
fn skip(file: &mut File, n: u64) -> std::io::Result<()> {
    let len = file.metadata()?.len();
    let pos = file.stream_position()?;
    let target = pos.saturating_add(n);
    if target > len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "snapshot record extends past end of file",
        ));
    }
    file.seek(SeekFrom::Start(target))?;
    Ok(())
}

/// Read `len` bytes and decode them as UTF-8 (lossy). Returns `None` on EOF.
fn read_string(file: &mut File, len: u32) -> Option<String> {
    if len == 0 {
        return Some(String::new());
    }
    let mut buf = vec![0u8; len as usize];
    file.read_exact(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(data: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(data).unwrap();
        f
    }

    /// Build a 104-byte v3 header pointing `snapshots_offset` at `snap_off`
    /// with `nb` snapshots.
    fn header(nb: u32, snap_off: u64) -> Vec<u8> {
        let mut h = vec![0u8; 104];
        h[0..4].copy_from_slice(&crate::header::MAGIC.to_be_bytes());
        h[4..8].copy_from_slice(&3u32.to_be_bytes());
        h[20..24].copy_from_slice(&16u32.to_be_bytes()); // cluster_bits
        h[60..64].copy_from_slice(&nb.to_be_bytes());
        h[64..72].copy_from_slice(&snap_off.to_be_bytes());
        h
    }

    /// Encode one snapshot table entry with the given extra-data, id, name.
    fn entry(
        secs: u32,
        nsecs: u32,
        vm_state_size: u32,
        extra: &[u8],
        id: &[u8],
        name: &[u8],
    ) -> Vec<u8> {
        let mut e = vec![0u8; SNAPSHOT_HEADER_FIXED];
        // l1_table_offset (0..8) = 0, l1_size (8..12) = 0
        e[12..14].copy_from_slice(&(id.len() as u16).to_be_bytes());
        e[14..16].copy_from_slice(&(name.len() as u16).to_be_bytes());
        e[16..20].copy_from_slice(&secs.to_be_bytes());
        e[20..24].copy_from_slice(&nsecs.to_be_bytes());
        // vm_clock_nsec (24..32) = 0
        e[32..36].copy_from_slice(&vm_state_size.to_be_bytes());
        e[36..40].copy_from_slice(&(extra.len() as u32).to_be_bytes());
        e.extend_from_slice(extra);
        e.extend_from_slice(id);
        e.extend_from_slice(name);
        // 8-byte align between entries.
        let consumed = SNAPSHOT_HEADER_FIXED + extra.len() + id.len() + name.len();
        let pad = (8 - (consumed % 8)) % 8;
        e.extend(std::iter::repeat_n(0u8, pad));
        e
    }

    #[test]
    fn no_snapshots_returns_empty() {
        let img = header(0, 0);
        let f = write_tmp(&img);
        assert!(snapshots(f.path()).unwrap().is_empty());
    }

    #[test]
    fn nonzero_count_but_zero_offset_returns_empty() {
        let img = header(3, 0);
        let f = write_tmp(&img);
        assert!(snapshots(f.path()).unwrap().is_empty());
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut img = header(0, 0);
        img[0] = 0;
        let f = write_tmp(&img);
        assert!(matches!(snapshots(f.path()), Err(Qcow2Error::BadMagic)));
    }

    #[test]
    fn too_small_is_rejected() {
        let f = write_tmp(&[0u8; 8]);
        assert!(matches!(snapshots(f.path()), Err(Qcow2Error::FileTooSmall)));
    }

    #[test]
    fn open_nonexistent_is_io_error() {
        assert!(snapshots(Path::new("/tmp/no_such_qcow2_snaps.qcow2")).is_err());
    }

    #[test]
    fn parses_two_entries_with_extra_data() {
        // Table starts one cluster (65536) in.
        let snap_off = 65_536u64;
        let mut img = header(2, snap_off);
        img.resize(snap_off as usize, 0);
        // First entry: 16-byte extra data (v3 vm_state_size + virtual_disk_size).
        let extra1 = {
            let mut x = vec![0u8; 16];
            x[0..8].copy_from_slice(&4096u64.to_be_bytes());
            x
        };
        img.extend(entry(1_700_000_000, 123, 4096, &extra1, b"1", b"alpha"));
        img.extend(entry(1_700_000_050, 0, 0, &[], b"2", b"beta-name"));
        let f = write_tmp(&img);

        let snaps = snapshots(f.path()).unwrap();
        assert_eq!(snaps.len(), 2);
        assert_eq!(snaps[0].id, "1");
        assert_eq!(snaps[0].name, "alpha");
        assert_eq!(snaps[0].date_unix_secs, 1_700_000_000);
        assert_eq!(snaps[0].date_nsecs, 123);
        assert_eq!(snaps[0].vm_state_size, 4096);
        assert_eq!(snaps[1].id, "2");
        assert_eq!(snaps[1].name, "beta-name");
        assert_eq!(snaps[1].date_unix_secs, 1_700_000_050);
        assert_eq!(snaps[1].vm_state_size, 0);
    }

    #[test]
    fn truncated_table_stops_gracefully() {
        // Declares 3 snapshots but the file ends mid-second-entry.
        let snap_off = 512u64;
        let mut img = header(3, snap_off);
        img.resize(snap_off as usize, 0);
        img.extend(entry(1_700_000_000, 0, 0, &[], b"1", b"only"));
        // Append a partial fixed header for the "second" entry (too short).
        img.extend_from_slice(&[0u8; 10]);
        let f = write_tmp(&img);

        let snaps = snapshots(f.path()).unwrap();
        assert_eq!(snaps.len(), 1, "should recover the one fully-parsed entry");
        assert_eq!(snaps[0].name, "only");
    }

    #[test]
    fn count_is_capped_to_max_snapshots() {
        // A crafted huge count must not drive unbounded work; with no table data
        // the loop stops at the first truncated read.
        let snap_off = 512u64;
        let mut img = header(u32::MAX, snap_off);
        img.resize(snap_off as usize, 0);
        let f = write_tmp(&img);
        assert!(snapshots(f.path()).unwrap().is_empty());
    }

    #[test]
    fn oversized_string_sizes_are_capped() {
        // id_str_size / name_size at u16::MAX exceed MAX_STR_LEN's effect but the
        // read simply hits EOF and the entry is skipped — no panic, no OOM.
        let snap_off = 512u64;
        let mut img = header(1, snap_off);
        img.resize(snap_off as usize, 0);
        let mut e = vec![0u8; SNAPSHOT_HEADER_FIXED];
        e[12..14].copy_from_slice(&u16::MAX.to_be_bytes());
        e[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
        img.extend(e);
        let f = write_tmp(&img);
        assert!(snapshots(f.path()).unwrap().is_empty());
    }

    #[test]
    fn extra_data_runs_off_end_stops_gracefully() {
        let snap_off = 512u64;
        let mut img = header(1, snap_off);
        img.resize(snap_off as usize, 0);
        let mut e = vec![0u8; SNAPSHOT_HEADER_FIXED];
        // Declare extra_data_size larger than remaining file.
        e[36..40].copy_from_slice(&1000u32.to_be_bytes());
        img.extend(e);
        let f = write_tmp(&img);
        assert!(snapshots(f.path()).unwrap().is_empty());
    }
}
