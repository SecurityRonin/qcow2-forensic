use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use qcow2::Qcow2Reader;

fn corpus_dir() -> Option<PathBuf> {
    std::env::var("CORPUS_DIR").ok().map(PathBuf::from)
}

#[test]
fn corpus_sparse_qcow2_opens_and_has_nonzero_size() {
    let Some(dir) = corpus_dir() else { return };
    let path = dir.join("sparse.qcow2");
    if !path.exists() {
        return;
    }
    let reader = Qcow2Reader::open(&path).expect("open sparse.qcow2");
    assert!(reader.virtual_disk_size() > 0, "virtual_disk_size must be > 0");
}

#[test]
fn corpus_sparse_qcow2_read_is_stable() {
    let Some(dir) = corpus_dir() else { return };
    let path = dir.join("sparse.qcow2");
    if !path.exists() {
        return;
    }
    let mut reader = Qcow2Reader::open(&path).expect("open");
    let mut buf = [0u8; 512];
    reader.seek(SeekFrom::Start(0)).expect("seek");
    reader.read_exact(&mut buf).expect("read sector 0");
    assert_eq!(buf, [0u8; 512], "sector 0 of an empty sparse QCOW2 must be all zeros");
}

/// CirrOS 0.6.3 — an independent real-world QCOW2 produced by the CirrOS build system.
/// This test verifies that an image from a completely separate toolchain parses correctly.
#[test]
fn corpus_cirros_opens_and_has_nonzero_size() {
    let Some(dir) = corpus_dir() else { return };
    let path = dir.join("cirros-0.6.3-x86_64-disk.img");
    if !path.exists() {
        return;
    }
    let mut reader = Qcow2Reader::open(&path).expect("open cirros");
    assert!(reader.virtual_disk_size() > 0, "CirrOS virtual_disk_size must be > 0");

    // MBR sector: CirrOS has a real partition table.
    let mut mbr = [0u8; 512];
    reader.seek(SeekFrom::Start(0)).expect("seek");
    reader.read_exact(&mut mbr).expect("read MBR");
    assert_eq!(mbr[510], 0x55, "MBR boot signature byte 510 must be 0x55");
    assert_eq!(mbr[511], 0xAA, "MBR boot signature byte 511 must be 0xAA");
}
