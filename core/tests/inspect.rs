//! Lenient forensic header inspection — exposes facts the strict reader rejects
//! (backing files, encryption, v3 incompatible-feature bits, snapshots) so an
//! analyzer can audit images it cannot decode.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use qcow2::{inspect, Qcow2Info};
use std::io::Write;

fn write_tmp(data: &[u8]) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(data).unwrap();
    f
}

fn v3_header(mutate: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut h = vec![0u8; 104];
    h[0..4].copy_from_slice(&0x5146_49fb_u32.to_be_bytes()); // magic
    h[4..8].copy_from_slice(&3u32.to_be_bytes()); // version 3
    h[20..24].copy_from_slice(&16u32.to_be_bytes()); // cluster_bits = 16
    h[24..32].copy_from_slice(&(1u64 << 20).to_be_bytes()); // disk_size = 1 MiB
    h[60..64].copy_from_slice(&0u32.to_be_bytes()); // nb_snapshots
    h[100..104].copy_from_slice(&104u32.to_be_bytes()); // header_length
    mutate(&mut h);
    h
}

#[test]
fn inspect_reports_clean_image() {
    let clean = write_tmp(&v3_header(|_| {}));
    let info: Qcow2Info = inspect(clean.path()).unwrap();
    assert_eq!(info.version, 3);
    assert!(!info.has_backing_file);
    assert_eq!(info.encryption_method, 0);
    assert_eq!(info.snapshot_count, 0);
    assert_eq!(info.incompatible_features, 0);
    assert_eq!(info.virtual_disk_size, 1 << 20);
}

#[test]
fn inspect_reports_backing_encryption_snapshots_and_feature_bits() {
    let img = write_tmp(&v3_header(|h| {
        h[8..16].copy_from_slice(&200u64.to_be_bytes()); // backing_file_offset != 0
        h[32..36].copy_from_slice(&1u32.to_be_bytes()); // encryption = AES
        h[60..64].copy_from_slice(&3u32.to_be_bytes()); // nb_snapshots = 3
        h[72..80].copy_from_slice(&0b11u64.to_be_bytes()); // dirty + corrupt bits
    }));
    let info = inspect(img.path()).unwrap();
    assert!(info.has_backing_file);
    assert_eq!(info.encryption_method, 1);
    assert_eq!(info.snapshot_count, 3);
    assert_eq!(info.incompatible_features & 0b11, 0b11);
}

#[test]
fn inspect_rejects_non_qcow2() {
    let junk = write_tmp(b"not a qcow2 image");
    assert!(inspect(junk.path()).is_err());
}
