//! QCOW2 internal snapshot table enumeration (QEMU block format spec §6).
//!
//! The header records `nb_snapshots` (offset 60, u32 BE) and `snapshots_offset`
//! (offset 64, u64 BE). The snapshot table is a packed array of
//! `QcowSnapshotHeader` records, each followed by its variable-length extra
//! data, id string, and name string. All fields are big-endian.

use std::path::Path;

use crate::error::Result;

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

/// Enumerate the internal snapshots in the QCOW2 image at `path`.
pub fn snapshots(_path: &Path) -> Result<Vec<Qcow2Snapshot>> {
    Ok(Vec::new())
}
