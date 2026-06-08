//! Forensic anomaly auditor for QCOW2 images.
//!
//! Reads QCOW2 header facts via [`qcow2::inspect`] and grades them into
//! severity-ranked findings on the shared [`forensicnomicon::report`] model.
//! Each finding is an *observation* ("consistent with …"); the examiner draws
//! the conclusions.

// Production code is panic-free (enforced by the workspace lints); tests opt out.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::path::Path;

pub use forensicnomicon::report::Severity;
pub use qcow2::{Qcow2Error, Qcow2Info};

// v3 incompatible-feature bits (QCOW2 spec §4).
const FEAT_DIRTY: u64 = 1 << 0;
const FEAT_CORRUPT: u64 = 1 << 1;
const FEAT_EXTERNAL_DATA: u64 = 1 << 2;

/// A QCOW2 image-level forensic anomaly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Qcow2Anomaly {
    /// The image references a backing file — it is an overlay/differential and
    /// alone does not contain the full guest data.
    BackingFile,
    /// The image is encrypted; its contents cannot be read without the key.
    Encrypted {
        /// Encryption method byte (1 = AES, 2 = LUKS).
        method: u32,
    },
    /// The image carries internal snapshots — additional captured guest states.
    InternalSnapshots {
        /// Number of snapshots.
        count: u32,
    },
    /// The dirty bit is set — the image was not closed cleanly (in use/crash).
    Dirty,
    /// The corrupt bit is set — QEMU flagged the image as corrupt.
    Corrupt,
    /// The image stores guest data in an external data file (not self-contained).
    ExternalDataFile,
}

impl Qcow2Anomaly {
    /// Severity — the single source of truth for this kind.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            Qcow2Anomaly::Corrupt => Severity::High,
            Qcow2Anomaly::BackingFile
            | Qcow2Anomaly::Encrypted { .. }
            | Qcow2Anomaly::ExternalDataFile => Severity::Medium,
            Qcow2Anomaly::InternalSnapshots { .. } | Qcow2Anomaly::Dirty => Severity::Low,
        }
    }

    /// Stable machine-readable code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Qcow2Anomaly::BackingFile => "QCOW2-BACKING-FILE",
            Qcow2Anomaly::Encrypted { .. } => "QCOW2-ENCRYPTED",
            Qcow2Anomaly::InternalSnapshots { .. } => "QCOW2-INTERNAL-SNAPSHOTS",
            Qcow2Anomaly::Dirty => "QCOW2-DIRTY",
            Qcow2Anomaly::Corrupt => "QCOW2-CORRUPT",
            Qcow2Anomaly::ExternalDataFile => "QCOW2-EXTERNAL-DATA",
        }
    }

    /// Human-readable, "consistent with" note.
    #[must_use]
    pub fn note(&self) -> String {
        match self {
            Qcow2Anomaly::BackingFile => "image references a backing file — it is an overlay and does not alone contain the full guest data".to_string(),
            Qcow2Anomaly::Encrypted { method } => format!("image is encrypted (method {method}) — contents are inaccessible without the key"),
            Qcow2Anomaly::InternalSnapshots { count } => format!("image carries {count} internal snapshot(s) — additional captured guest states to examine"),
            Qcow2Anomaly::Dirty => "the dirty bit is set — consistent with the image not having been closed cleanly (in use or crashed)".to_string(),
            Qcow2Anomaly::Corrupt => "the corrupt bit is set — QEMU flagged the image as corrupt".to_string(),
            Qcow2Anomaly::ExternalDataFile => "image stores guest data in an external data file — the data is not self-contained".to_string(),
        }
    }
}

impl forensicnomicon::report::Observation for Qcow2Anomaly {
    fn severity(&self) -> Option<Severity> {
        Some(self.severity())
    }
    fn code(&self) -> &'static str {
        self.code()
    }
    fn note(&self) -> String {
        self.note()
    }
    fn evidence(&self) -> Vec<forensicnomicon::report::Evidence> {
        use forensicnomicon::report::{Evidence, Location};
        let (field, value) = match self {
            Qcow2Anomaly::BackingFile => ("backing_file_offset", "present".to_string()),
            Qcow2Anomaly::Encrypted { method } => ("crypt_method", method.to_string()),
            Qcow2Anomaly::InternalSnapshots { count } => ("nb_snapshots", count.to_string()),
            Qcow2Anomaly::Dirty => ("incompatible_features", "dirty".to_string()),
            Qcow2Anomaly::Corrupt => ("incompatible_features", "corrupt".to_string()),
            Qcow2Anomaly::ExternalDataFile => ("incompatible_features", "external-data".to_string()),
        };
        vec![Evidence {
            field: field.to_string(),
            value,
            location: Some(Location::Field("QCOW2 header".to_string())),
        }]
    }
}

/// Audit parsed QCOW2 header facts for forensic anomalies.
#[must_use]
pub fn audit(info: &Qcow2Info) -> Vec<Qcow2Anomaly> {
    let mut out = Vec::new();
    if info.has_backing_file {
        out.push(Qcow2Anomaly::BackingFile);
    }
    if info.encryption_method != 0 {
        out.push(Qcow2Anomaly::Encrypted {
            method: info.encryption_method,
        });
    }
    if info.snapshot_count > 0 {
        out.push(Qcow2Anomaly::InternalSnapshots {
            count: info.snapshot_count,
        });
    }
    if info.incompatible_features & FEAT_DIRTY != 0 {
        out.push(Qcow2Anomaly::Dirty);
    }
    if info.incompatible_features & FEAT_CORRUPT != 0 {
        out.push(Qcow2Anomaly::Corrupt);
    }
    if info.incompatible_features & FEAT_EXTERNAL_DATA != 0 {
        out.push(Qcow2Anomaly::ExternalDataFile);
    }
    out
}

/// Inspect and audit a QCOW2 image at `path` in one step. Malformed input
/// surfaces as an error rather than silent emptiness.
pub fn audit_path(path: &Path) -> Result<Vec<Qcow2Anomaly>, Qcow2Error> {
    Ok(audit(&qcow2::inspect(path)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensicnomicon::report::{Observation, Source};
    use std::io::Write;

    fn info() -> Qcow2Info {
        Qcow2Info {
            version: 3,
            cluster_bits: 16,
            virtual_disk_size: 1 << 20,
            l1_size: 1,
            has_backing_file: false,
            encryption_method: 0,
            snapshot_count: 0,
            incompatible_features: 0,
        }
    }

    fn all_anomalies() -> Vec<Qcow2Anomaly> {
        let mut i = info();
        i.has_backing_file = true;
        i.encryption_method = 1;
        i.snapshot_count = 4;
        i.incompatible_features = FEAT_DIRTY | FEAT_CORRUPT | FEAT_EXTERNAL_DATA;
        audit(&i)
    }

    #[test]
    fn clean_image_has_no_anomalies() {
        assert!(audit(&info()).is_empty());
    }

    #[test]
    fn every_anomaly_kind_is_emitted_and_round_trips_to_a_finding() {
        let anomalies = all_anomalies();
        let codes: Vec<&str> = anomalies.iter().map(Observation::code).collect();
        for expected in [
            "QCOW2-BACKING-FILE",
            "QCOW2-ENCRYPTED",
            "QCOW2-INTERNAL-SNAPSHOTS",
            "QCOW2-DIRTY",
            "QCOW2-CORRUPT",
            "QCOW2-EXTERNAL-DATA",
        ] {
            assert!(codes.contains(&expected), "missing {expected}");
        }
        let src = Source {
            analyzer: "qcow2-forensic".to_string(),
            scope: "image".to_string(),
            version: None,
        };
        for a in &anomalies {
            let f = a.to_finding(src.clone());
            assert!(f.code.starts_with("QCOW2-"));
            assert!(f.severity.is_some());
            assert!(!f.note.is_empty());
            assert!(!f.evidence.is_empty());
        }
    }

    #[test]
    fn severities_are_graded() {
        let mut i = info();
        i.incompatible_features = FEAT_CORRUPT | FEAT_DIRTY;
        let a = audit(&i);
        let corrupt = a.iter().find(|x| x.code() == "QCOW2-CORRUPT").unwrap();
        let dirty = a.iter().find(|x| x.code() == "QCOW2-DIRTY").unwrap();
        assert_eq!(corrupt.severity(), Severity::High);
        assert_eq!(dirty.severity(), Severity::Low);
    }

    #[test]
    fn audit_path_inspects_a_real_header_then_audits() {
        let mut h = vec![0u8; 72];
        h[0..4].copy_from_slice(&0x5146_49fb_u32.to_be_bytes());
        h[4..8].copy_from_slice(&2u32.to_be_bytes());
        h[8..16].copy_from_slice(&512u64.to_be_bytes()); // backing_file_offset
        h[20..24].copy_from_slice(&16u32.to_be_bytes()); // cluster_bits
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&h).unwrap();
        let anomalies = audit_path(f.path()).unwrap();
        assert!(anomalies.contains(&Qcow2Anomaly::BackingFile));
    }

    #[test]
    fn audit_path_propagates_errors_on_non_qcow2() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"definitely not a qcow2 image header").unwrap();
        assert!(audit_path(f.path()).is_err());
    }
}
