//! QCOW2 forensic auditor: header-level anomalies graded onto the shared
//! forensicnomicon report model.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use forensicnomicon::report::{Observation, Source};
use qcow2::Qcow2Info;
use qcow2_forensic::{audit, Qcow2Anomaly, Severity};

fn src() -> Source {
    Source {
        analyzer: "qcow2-forensic".to_string(),
        scope: "image".to_string(),
        version: None,
    }
}

fn info(mutate: impl FnOnce(&mut Qcow2Info)) -> Qcow2Info {
    let mut i = Qcow2Info {
        version: 3,
        cluster_bits: 16,
        virtual_disk_size: 1 << 20,
        l1_size: 1,
        has_backing_file: false,
        encryption_method: 0,
        snapshot_count: 0,
        incompatible_features: 0,
        backing_file: None,
        backing_format: None,
    };
    mutate(&mut i);
    i
}

#[test]
fn clean_image_has_no_anomalies() {
    assert!(audit(&info(|_| {})).is_empty());
}

#[test]
fn backing_file_is_flagged() {
    let anomalies = audit(&info(|i| i.has_backing_file = true));
    assert_eq!(anomalies.len(), 1);
    assert!(matches!(anomalies[0], Qcow2Anomaly::BackingFile { .. }));
    let f = anomalies[0].to_finding(src());
    assert_eq!(f.code, "QCOW2-BACKING-FILE");
    assert!(f.severity.is_some());
}

#[test]
fn encryption_snapshots_and_feature_bits_are_flagged() {
    let anomalies = audit(&info(|i| {
        i.encryption_method = 2; // LUKS
        i.snapshot_count = 2;
        i.incompatible_features = 0b11; // dirty + corrupt
    }));
    let codes: Vec<&str> = anomalies.iter().map(Observation::code).collect();
    assert!(codes.contains(&"QCOW2-ENCRYPTED"));
    assert!(codes.contains(&"QCOW2-INTERNAL-SNAPSHOTS"));
    assert!(codes.contains(&"QCOW2-DIRTY"));
    assert!(codes.contains(&"QCOW2-CORRUPT"));

    // The corrupt bit is the most severe.
    let corrupt = anomalies
        .iter()
        .find(|a| Observation::code(*a) == "QCOW2-CORRUPT")
        .expect("corrupt anomaly present");
    assert_eq!(corrupt.severity(), Severity::High);
}
