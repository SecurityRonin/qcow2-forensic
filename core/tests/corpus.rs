use forensic_testgate::gated_file;
use qcow2::Qcow2Reader;
use std::io::{Read, Seek, SeekFrom};

const DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data");

#[test]
fn corpus_sparse_qcow2_opens_and_has_nonzero_size() {
    let Some(path) = gated_file("CORPUS_DIR", "sparse.qcow2") else {
        return;
    };
    let reader = Qcow2Reader::open(&path).expect("open sparse.qcow2");
    assert!(
        reader.virtual_disk_size() > 0,
        "virtual_disk_size must be > 0"
    );
}

#[test]
fn corpus_sparse_qcow2_read_is_stable() {
    let Some(path) = gated_file("CORPUS_DIR", "sparse.qcow2") else {
        return;
    };
    let mut reader = Qcow2Reader::open(&path).expect("open");
    let mut buf = [0u8; 512];
    reader.seek(SeekFrom::Start(0)).expect("seek");
    reader.read_exact(&mut buf).expect("read sector 0");
    assert_eq!(
        buf, [0u8; 512],
        "sector 0 of an empty sparse QCOW2 must be all zeros"
    );
}

/// CirrOS 0.6.3 — an independent real-world QCOW2 produced by the CirrOS build system.
/// Committed to tests/data/ so this test runs in all CI jobs without `CORPUS_DIR`.
#[test]
fn cirros_committed_opens_and_has_correct_mbr() {
    let path = std::path::Path::new(DATA_DIR).join("cirros-0.6.3-x86_64-disk.img");
    // Not gated on anything: this fixture is committed, so its absence is a broken
    // checkout rather than a skip.
    assert!(
        path.exists(),
        "committed fixture missing: {}",
        path.display()
    );
    let mut reader = Qcow2Reader::open(&path).expect("open committed CirrOS");
    assert!(
        reader.virtual_disk_size() > 0,
        "CirrOS virtual_disk_size must be > 0"
    );
    let mut mbr = [0u8; 512];
    reader.seek(SeekFrom::Start(0)).expect("seek");
    reader.read_exact(&mut mbr).expect("read MBR");
    assert_eq!(mbr[510], 0x55, "CirrOS MBR byte 510 must be 0x55");
    assert_eq!(mbr[511], 0xAA, "CirrOS MBR byte 511 must be 0xAA");
}

/// CirrOS via `CORPUS_DIR` — kept for CI corpus job backward-compatibility.
#[test]
fn corpus_cirros_opens_and_has_nonzero_size() {
    let Some(path) = gated_file("CORPUS_DIR", "cirros-0.6.3-x86_64-disk.img") else {
        return;
    };
    let mut reader = Qcow2Reader::open(&path).expect("open cirros");
    assert!(
        reader.virtual_disk_size() > 0,
        "CirrOS virtual_disk_size must be > 0"
    );
    let mut mbr = [0u8; 512];
    reader.seek(SeekFrom::Start(0)).expect("seek");
    reader.read_exact(&mut mbr).expect("read MBR");
    assert_eq!(mbr[510], 0x55, "MBR boot signature byte 510 must be 0x55");
    assert_eq!(mbr[511], 0xAA, "MBR boot signature byte 511 must be 0xAA");
}
