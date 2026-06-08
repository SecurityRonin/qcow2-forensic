//! Doer-checker validation: `inspect()` against REAL qemu-img-produced images
//! and the real CirrOS corpus. Gated on qemu-img presence — skips silently
//! where it is unavailable (e.g. minimal CI) rather than failing.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

const QEMU_IMG: &str = "/opt/homebrew/bin/qemu-img";

fn have_qemu() -> bool {
    Path::new(QEMU_IMG).exists()
}

fn qemu(args: &[&str]) -> bool {
    Command::new(QEMU_IMG)
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn p(d: &tempfile::TempDir, name: &str) -> PathBuf {
    d.path().join(name)
}

#[test]
fn inspect_detects_backing_file_on_real_overlay() {
    if !have_qemu() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let base = p(&dir, "base.qcow2");
    let overlay = p(&dir, "overlay.qcow2");
    assert!(qemu(&["create", "-f", "qcow2", base.to_str().unwrap(), "10M"]));
    assert!(qemu(&[
        "create", "-f", "qcow2", "-b",
        base.to_str().unwrap(), "-F", "qcow2",
        overlay.to_str().unwrap()
    ]));

    assert!(
        qcow2::inspect(&overlay).unwrap().has_backing_file,
        "overlay must report a backing file"
    );
    assert!(
        !qcow2::inspect(&base).unwrap().has_backing_file,
        "base must not report a backing file"
    );
}

#[test]
fn inspect_detects_internal_snapshot_on_real_image() {
    if !have_qemu() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let img = p(&dir, "snap.qcow2");
    assert!(qemu(&["create", "-f", "qcow2", img.to_str().unwrap(), "10M"]));
    assert!(qemu(&["snapshot", "-c", "snap1", img.to_str().unwrap()]));

    let info = qcow2::inspect(&img).unwrap();
    assert!(
        info.snapshot_count >= 1,
        "expected >= 1 internal snapshot, got {}",
        info.snapshot_count
    );
}

#[test]
fn inspect_detects_encryption_on_real_luks_image() {
    if !have_qemu() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let img = p(&dir, "enc.qcow2");
    // Some qemu builds lack LUKS support — skip if creation fails.
    if !qemu(&[
        "create", "-f", "qcow2",
        "--object", "secret,id=sec,data=hunter2",
        "-o", "encrypt.format=luks,encrypt.key-secret=sec",
        img.to_str().unwrap(), "10M",
    ]) {
        return;
    }
    assert_ne!(
        qcow2::inspect(&img).unwrap().encryption_method,
        0,
        "a LUKS-encrypted image must report a non-zero encryption method"
    );
}

#[test]
fn inspect_reads_real_cirros_corpus_as_clean() {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/cirros-0.6.3-x86_64-disk.img");
    if !corpus.exists() {
        return;
    }
    let info = qcow2::inspect(&corpus).unwrap();
    assert!(info.version == 2 || info.version == 3, "real qcow2 version");
    assert!(!info.has_backing_file, "standalone cirros image — no backing file");
    assert_eq!(info.encryption_method, 0, "cirros is not encrypted");
    assert!(info.virtual_disk_size > 0);
}
