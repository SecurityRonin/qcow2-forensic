//! Doer-checker validation: `audit_path()` against REAL qemu-img-produced
//! images. Gated on qemu-img presence — skips silently where it is unavailable
//! (e.g. minimal CI) rather than failing.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

use qcow2_forensic::{audit_path, Qcow2Anomaly};

/// Resolve a usable `qemu-img`, or `None` (the differential then skips).
///
/// `PATH` is probed first, so any install location works — including ones a
/// fixed list cannot anticipate: another package manager's prefix, or a
/// hand-built install. The absolute
/// candidates are the fallback for a stripped `PATH`: Homebrew on Apple silicon
/// and Intel, then `/usr/bin`, where the Linux CI runner's `qemu-utils` package
/// lands it. `QEMU_IMG_BIN` overrides both.
///
/// The hardcoded Homebrew path this replaces resolved only on a macOS-arm64 dev
/// machine, so these audits skipped silently on the Linux CI runner despite CI
/// installing `qemu-utils` for exactly these tests. `qcow2-core`'s sibling
/// differential carries the same resolver.
fn qemu_img_bin() -> Option<String> {
    if let Ok(explicit) = std::env::var("QEMU_IMG_BIN") {
        return usable(&explicit);
    }
    [
        "qemu-img",
        "/opt/homebrew/bin/qemu-img",
        "/usr/local/bin/qemu-img",
        "/usr/bin/qemu-img",
    ]
    .into_iter()
    .find_map(usable)
}

/// A candidate counts only if it actually executes: a successful `--version`
/// proves both that the name resolved and that the binary runs on this host,
/// which a bare `Path::exists()` check does not.
fn usable(candidate: &str) -> Option<String> {
    Command::new(candidate)
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|_| candidate.to_string())
}

fn have_qemu() -> bool {
    qemu_img_bin().is_some()
}

fn qemu(args: &[&str]) -> bool {
    let Some(bin) = qemu_img_bin() else {
        return false;
    };
    Command::new(bin)
        .args(args)
        .status()
        .is_ok_and(|s| s.success())
}

#[test]
fn audit_path_names_the_backing_file_on_real_overlay() {
    if !have_qemu() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base.qcow2");
    let overlay = dir.path().join("overlay.qcow2");
    assert!(qemu(&[
        "create",
        "-f",
        "qcow2",
        base.to_str().unwrap(),
        "10M"
    ]));
    assert!(qemu(&[
        "create",
        "-f",
        "qcow2",
        "-b",
        base.to_str().unwrap(),
        "-F",
        "qcow2",
        overlay.to_str().unwrap()
    ]));

    let anomalies = audit_path(&overlay).unwrap();
    let bf = anomalies
        .iter()
        .find_map(|a| match a {
            Qcow2Anomaly::BackingFile { name, .. } => Some(name.clone()),
            _ => None,
        })
        .expect("backing-file finding");
    assert_eq!(
        bf.as_deref().map(|n| n.contains("base.qcow2")),
        Some(true),
        "audit_path must name the backing file, got {bf:?}"
    );
}

#[test]
fn audit_path_surfaces_per_snapshot_findings_on_real_image() {
    if !have_qemu() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("snaps.qcow2");
    assert!(qemu(&[
        "create",
        "-f",
        "qcow2",
        img.to_str().unwrap(),
        "10M"
    ]));
    assert!(qemu(&["snapshot", "-c", "alpha", img.to_str().unwrap()]));
    assert!(qemu(&["snapshot", "-c", "beta", img.to_str().unwrap()]));

    let anomalies = audit_path(&img).unwrap();
    let snap_findings: Vec<&Qcow2Anomaly> = anomalies
        .iter()
        .filter(|a| matches!(a, Qcow2Anomaly::Snapshot { .. }))
        .collect();
    assert_eq!(
        snap_findings.len(),
        2,
        "expected one per-snapshot finding for each of alpha, beta"
    );

    let names: Vec<String> = snap_findings
        .iter()
        .filter_map(|a| match a {
            Qcow2Anomaly::Snapshot { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect();
    assert!(names.contains(&"alpha".to_string()), "got {names:?}");
    assert!(names.contains(&"beta".to_string()), "got {names:?}");
}
