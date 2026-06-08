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
fn refcount_report_on_real_clean_image_finds_no_orphans() {
    if !have_qemu() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let raw = p(&dir, "src.raw");
    let img = p(&dir, "data.qcow2");
    // A 4 MiB image with real content so several data clusters are allocated.
    let data: Vec<u8> = (0..(4usize << 20)).map(|i| (i ^ (i >> 7)) as u8).collect();
    std::fs::write(&raw, &data).unwrap();
    assert!(qemu(&[
        "convert", "-O", "qcow2", raw.to_str().unwrap(), img.to_str().unwrap()
    ]));

    let r = qcow2::refcount_report(&img).unwrap();
    // qemu defaults to 16-bit refcounts (order 4) and a non-empty refcount table.
    assert_eq!(r.refcount_order, 4, "qemu default refcount_order is 4");
    assert_ne!(r.refcount_table_offset, 0, "refcount table must be located");
    assert!(r.allocated_clusters > 0, "image has allocated data clusters");
    assert_eq!(
        r.orphan_clusters, 0,
        "a freshly-converted clean image must have no orphaned clusters"
    );
}

#[test]
fn inspect_reports_qcow1_version_distinctly_on_real_image() {
    if !have_qemu() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let img = p(&dir, "legacy.qcow");
    // Some qemu builds drop the legacy qcow (v1) writer — skip if unavailable.
    if !qemu(&["create", "-f", "qcow", img.to_str().unwrap(), "10M"]) {
        return;
    }
    let info = qcow2::inspect(&img).unwrap();
    assert_eq!(info.version, 1, "a real qcow (v1) image must report version 1");
}

#[test]
fn inspect_extracts_backing_file_name_and_format_on_real_overlay() {
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

    let info = qcow2::inspect(&overlay).unwrap();
    let backing = info.backing_file.expect("overlay must expose a backing filename");
    assert!(
        backing.contains("base.qcow2"),
        "backing filename should reference base.qcow2, got {backing:?}"
    );
    assert_eq!(
        info.backing_format.as_deref(),
        Some("qcow2"),
        "backing format should be the qcow2 recorded via -F"
    );

    // The standalone base image has neither.
    let base_info = qcow2::inspect(&base).unwrap();
    assert!(base_info.backing_file.is_none());
    assert!(base_info.backing_format.is_none());
}

#[test]
fn snapshots_enumerates_named_snapshot_on_real_image() {
    if !have_qemu() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let img = p(&dir, "snaps.qcow2");
    assert!(qemu(&["create", "-f", "qcow2", img.to_str().unwrap(), "10M"]));
    assert!(qemu(&["snapshot", "-c", "alpha", img.to_str().unwrap()]));
    assert!(qemu(&["snapshot", "-c", "beta", img.to_str().unwrap()]));

    let snaps = qcow2::snapshots(&img).unwrap();
    let names: Vec<&str> = snaps.iter().map(|s| s.name.as_str()).collect();
    assert!(names.contains(&"alpha"), "expected snapshot 'alpha', got {names:?}");
    assert!(names.contains(&"beta"), "expected snapshot 'beta', got {names:?}");
    // Every real snapshot carries a non-empty id and a plausible recent timestamp.
    for s in &snaps {
        assert!(!s.id.is_empty(), "snapshot id must not be empty");
        assert!(s.date_unix_secs > 1_500_000_000, "snapshot date looks wrong: {}", s.date_unix_secs);
    }
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
