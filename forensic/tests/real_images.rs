//! Doer-checker validation: `audit_path()` against REAL qemu-img-produced
//! images. Gated on qemu-img presence — skips silently where it is unavailable
//! (e.g. minimal CI) rather than failing.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::Command;

use qcow2_forensic::{audit_path, Qcow2Anomaly};

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

#[test]
fn audit_path_surfaces_per_snapshot_findings_on_real_image() {
    if !have_qemu() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("snaps.qcow2");
    assert!(qemu(&["create", "-f", "qcow2", img.to_str().unwrap(), "10M"]));
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
