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
pub use qcow2::{Qcow2Error, Qcow2Info, Qcow2RefcountReport, Qcow2Snapshot};

// v3 incompatible-feature bits (QCOW2 spec §4).
const FEAT_DIRTY: u64 = 1 << 0;
const FEAT_CORRUPT: u64 = 1 << 1;
const FEAT_EXTERNAL_DATA: u64 = 1 << 2;

/// A QCOW2 image-level forensic anomaly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Qcow2Anomaly {
    /// The image references a backing file — it is an overlay/differential and
    /// alone does not contain the full guest data.
    BackingFile {
        /// The referenced backing filename, when it could be extracted.
        name: Option<String>,
        /// The backing-file format (e.g. "qcow2", "raw"), when recorded.
        format: Option<String>,
    },
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
    /// A single named internal snapshot — a captured guest state at a point in
    /// time, worth examining as additional recoverable evidence.
    Snapshot {
        /// Snapshot name (e.g. "snap1").
        name: String,
        /// Creation time — seconds since the Unix epoch.
        date_unix_secs: u32,
    },
    /// The dirty bit is set — the image was not closed cleanly (in use/crash).
    Dirty,
    /// The corrupt bit is set — QEMU flagged the image as corrupt.
    Corrupt,
    /// The image stores guest data in an external data file (not self-contained).
    ExternalDataFile,
    /// Clusters reachable through the active L1/L2 mapping have a host refcount
    /// of 0 — allocated-but-unreferenced data, a candidate for orphaned or
    /// deleted guest content.
    OrphanClusters {
        /// Number of allocated-but-unreferenced clusters detected.
        count: u64,
        /// Total allocated data clusters examined (context for the count).
        allocated: u64,
    },
    /// The image uses the legacy QCOW1 (v1) format — an obsolete container
    /// predating QCOW2's refcounts, snapshots, and feature bits.
    LegacyQcow1,
}

impl Qcow2Anomaly {
    /// Severity — the single source of truth for this kind.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            Qcow2Anomaly::Corrupt => Severity::High,
            Qcow2Anomaly::BackingFile { .. }
            | Qcow2Anomaly::Encrypted { .. }
            | Qcow2Anomaly::OrphanClusters { .. }
            | Qcow2Anomaly::ExternalDataFile => Severity::Medium,
            Qcow2Anomaly::InternalSnapshots { .. }
            | Qcow2Anomaly::Snapshot { .. }
            | Qcow2Anomaly::LegacyQcow1
            | Qcow2Anomaly::Dirty => Severity::Low,
        }
    }

    /// Stable machine-readable code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Qcow2Anomaly::BackingFile { .. } => "QCOW2-BACKING-FILE",
            Qcow2Anomaly::Encrypted { .. } => "QCOW2-ENCRYPTED",
            Qcow2Anomaly::InternalSnapshots { .. } => "QCOW2-INTERNAL-SNAPSHOTS",
            Qcow2Anomaly::Snapshot { .. } => "QCOW2-SNAPSHOT",
            Qcow2Anomaly::Dirty => "QCOW2-DIRTY",
            Qcow2Anomaly::Corrupt => "QCOW2-CORRUPT",
            Qcow2Anomaly::ExternalDataFile => "QCOW2-EXTERNAL-DATA",
            Qcow2Anomaly::OrphanClusters { .. } => "QCOW2-ORPHAN-CLUSTERS",
            Qcow2Anomaly::LegacyQcow1 => "QCOW2-QCOW1",
        }
    }

    /// Human-readable, "consistent with" note.
    #[must_use]
    pub fn note(&self) -> String {
        match self {
            Qcow2Anomaly::BackingFile { name, format } => match (name, format) {
                (Some(n), Some(f)) => format!("image references backing file `{n}` (format {f}) — it is an overlay and does not alone contain the full guest data"),
                (Some(n), None) => format!("image references backing file `{n}` — it is an overlay and does not alone contain the full guest data"),
                (None, _) => "image references a backing file — it is an overlay and does not alone contain the full guest data".to_string(),
            },
            Qcow2Anomaly::Encrypted { method } => format!("image is encrypted (method {method}) — contents are inaccessible without the key"),
            Qcow2Anomaly::InternalSnapshots { count } => format!("image carries {count} internal snapshot(s) — additional captured guest states to examine"),
            Qcow2Anomaly::Snapshot { name, date_unix_secs } => format!("internal snapshot `{name}` captured at unix time {date_unix_secs} — a recoverable point-in-time guest state to examine"),
            Qcow2Anomaly::Dirty => "the dirty bit is set — consistent with the image not having been closed cleanly (in use or crashed)".to_string(),
            Qcow2Anomaly::Corrupt => "the corrupt bit is set — QEMU flagged the image as corrupt".to_string(),
            Qcow2Anomaly::ExternalDataFile => "image stores guest data in an external data file — the data is not self-contained".to_string(),
            Qcow2Anomaly::OrphanClusters { count, allocated } => format!("{count} of {allocated} allocated cluster(s) are reachable through L1/L2 yet have a host refcount of 0 — consistent with orphaned or deleted guest data left in the image"),
            Qcow2Anomaly::LegacyQcow1 => "image uses the legacy QCOW1 (version 1) format — an obsolete container predating QCOW2's refcounts, snapshots, and feature bits".to_string(),
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
        // A single named snapshot's evidence lives in the snapshot table and
        // carries both the name and its capture timestamp; every other anomaly
        // is a single header field.
        let header = |field: &str, value: String| Evidence {
            field: field.to_string(),
            value,
            location: Some(Location::Field("QCOW2 header".to_string())),
        };
        match self {
            Qcow2Anomaly::Snapshot {
                name,
                date_unix_secs,
            } => {
                let loc = || Some(Location::Field("QCOW2 snapshot table".to_string()));
                vec![
                    Evidence {
                        field: "snapshot_name".to_string(),
                        value: name.clone(),
                        location: loc(),
                    },
                    Evidence {
                        field: "date_unix_secs".to_string(),
                        value: date_unix_secs.to_string(),
                        location: loc(),
                    },
                ]
            }
            Qcow2Anomaly::BackingFile { name, format } => {
                let mut ev = vec![header(
                    "backing_file",
                    name.clone().unwrap_or_else(|| "present".to_string()),
                )];
                if let Some(f) = format {
                    ev.push(header("backing_format", f.clone()));
                }
                ev
            }
            Qcow2Anomaly::Encrypted { method } => vec![header("crypt_method", method.to_string())],
            Qcow2Anomaly::InternalSnapshots { count } => {
                vec![header("nb_snapshots", count.to_string())]
            }
            Qcow2Anomaly::Dirty => vec![header("incompatible_features", "dirty".to_string())],
            Qcow2Anomaly::Corrupt => vec![header("incompatible_features", "corrupt".to_string())],
            Qcow2Anomaly::ExternalDataFile => {
                vec![header("incompatible_features", "external-data".to_string())]
            }
            Qcow2Anomaly::OrphanClusters { count, allocated } => {
                let loc = || Some(Location::Field("QCOW2 refcount table".to_string()));
                vec![
                    Evidence {
                        field: "orphan_clusters".to_string(),
                        value: count.to_string(),
                        location: loc(),
                    },
                    Evidence {
                        field: "allocated_clusters".to_string(),
                        value: allocated.to_string(),
                        location: loc(),
                    },
                ]
            }
            Qcow2Anomaly::LegacyQcow1 => vec![header("version", "1".to_string())],
        }
    }
}

/// Audit parsed QCOW2 header facts for forensic anomalies.
#[must_use]
pub fn audit(info: &Qcow2Info) -> Vec<Qcow2Anomaly> {
    let mut out = Vec::new();
    if info.version == 1 {
        out.push(Qcow2Anomaly::LegacyQcow1);
    }
    if info.has_backing_file {
        out.push(Qcow2Anomaly::BackingFile {
            name: info.backing_file.clone(),
            format: info.backing_format.clone(),
        });
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

/// Audit an enumerated snapshot list, emitting one `QCOW2-SNAPSHOT` finding per
/// snapshot with its name and creation timestamp.
#[must_use]
pub fn audit_snapshots(snapshots: &[Qcow2Snapshot]) -> Vec<Qcow2Anomaly> {
    snapshots
        .iter()
        .map(|s| Qcow2Anomaly::Snapshot {
            name: s.name.clone(),
            date_unix_secs: s.date_unix_secs,
        })
        .collect()
}

/// Audit a refcount/orphan report, emitting a single `QCOW2-ORPHAN-CLUSTERS`
/// finding when clusters reachable through L1/L2 have a host refcount of 0.
#[must_use]
pub fn audit_orphans(report: &Qcow2RefcountReport) -> Option<Qcow2Anomaly> {
    if report.orphan_clusters == 0 {
        return None;
    }
    Some(Qcow2Anomaly::OrphanClusters {
        count: report.orphan_clusters,
        allocated: report.allocated_clusters,
    })
}

/// Inspect and audit a QCOW2 image at `path` in one step. Surfaces the header-
/// level anomalies, one per-snapshot finding, and an orphan-cluster finding when
/// allocated-but-unreferenced clusters are present. Malformed input surfaces as
/// an error rather than silent emptiness.
pub fn audit_path(path: &Path) -> Result<Vec<Qcow2Anomaly>, Qcow2Error> {
    let mut out = audit(&qcow2::inspect(path)?);
    out.extend(audit_snapshots(&qcow2::snapshots(path)?));
    out.extend(audit_orphans(&qcow2::refcount_report(path)?));
    Ok(out)
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
            backing_file: None,
            backing_format: None,
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
    fn backing_file_finding_names_the_referenced_image() {
        let mut i = info();
        i.has_backing_file = true;
        i.backing_file = Some("base.qcow2".to_string());
        i.backing_format = Some("qcow2".to_string());
        let out = audit(&i);
        let bf = out
            .iter()
            .find(|a| a.code() == "QCOW2-BACKING-FILE")
            .expect("backing-file finding");
        assert!(bf.note().contains("base.qcow2"), "note: {}", bf.note());
        let mut joined = String::new();
        for e in &bf.evidence() {
            joined.push_str(&e.field);
            joined.push('=');
            joined.push_str(&e.value);
            joined.push(';');
        }
        assert!(joined.contains("base.qcow2"), "evidence name: {joined}");
        assert!(joined.contains("qcow2"), "evidence format: {joined}");
    }

    #[test]
    fn backing_file_without_name_still_emits_a_generic_finding() {
        let mut i = info();
        i.has_backing_file = true; // present but name not captured
        let out = audit(&i);
        assert!(out.iter().any(|a| a.code() == "QCOW2-BACKING-FILE"));
    }

    #[test]
    fn backing_file_name_without_format_is_noted() {
        let mut i = info();
        i.has_backing_file = true;
        i.backing_file = Some("base.qcow2".to_string());
        i.backing_format = None; // name known, format not recorded
        let out = audit(&i);
        let bf = out
            .iter()
            .find(|a| a.code() == "QCOW2-BACKING-FILE")
            .unwrap();
        assert!(bf.note().contains("base.qcow2"));
        assert!(
            !bf.note().contains("format "),
            "no format clause when absent: {}",
            bf.note()
        );
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

    fn report(allocated: u64, orphans: u64) -> Qcow2RefcountReport {
        Qcow2RefcountReport {
            refcount_order: 4,
            refcount_table_offset: 65_536,
            refcount_table_clusters: 1,
            allocated_clusters: allocated,
            orphan_clusters: orphans,
        }
    }

    #[test]
    fn no_orphans_yields_no_finding() {
        assert!(audit_orphans(&report(100, 0)).is_none());
    }

    #[test]
    fn qcow1_version_is_flagged() {
        let mut i = info();
        i.version = 1;
        let out = audit(&i);
        let a = out
            .iter()
            .find(|a| a.code() == "QCOW2-QCOW1")
            .expect("v1 finding");
        assert_eq!(a.severity(), Severity::Low);
        assert!(a.note().to_lowercase().contains("version 1") || a.note().contains("QCOW1"));
        assert!(!a.evidence().is_empty());
    }

    #[test]
    fn qcow2_and_qcow3_are_not_flagged_as_v1() {
        for v in [2u32, 3] {
            let mut i = info();
            i.version = v;
            assert!(audit(&i).iter().all(|a| a.code() != "QCOW2-QCOW1"));
        }
    }

    #[test]
    fn orphans_yield_a_medium_finding_with_the_count() {
        let a = audit_orphans(&report(100, 7)).expect("orphan finding");
        assert_eq!(a.code(), "QCOW2-ORPHAN-CLUSTERS");
        assert_eq!(a.severity(), Severity::Medium);
        assert!(
            a.note().contains('7'),
            "note must carry the count: {}",
            a.note()
        );
        let mut joined = String::new();
        for e in &a.evidence() {
            joined.push_str(&e.field);
            joined.push('=');
            joined.push_str(&e.value);
            joined.push(';');
        }
        assert!(
            joined.contains('7'),
            "evidence must carry the count: {joined}"
        );
    }

    #[test]
    fn orphan_anomaly_round_trips_to_a_finding() {
        let src = Source {
            analyzer: "qcow2-forensic".to_string(),
            scope: "image".to_string(),
            version: None,
        };
        let a = audit_orphans(&report(10, 3)).unwrap();
        let f = a.to_finding(src);
        assert_eq!(f.code, "QCOW2-ORPHAN-CLUSTERS");
        assert_eq!(f.severity, Some(Severity::Medium));
        assert!(!f.evidence.is_empty());
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
        assert!(anomalies
            .iter()
            .any(|a| matches!(a, Qcow2Anomaly::BackingFile { .. })));
    }

    #[test]
    fn audit_path_propagates_errors_on_non_qcow2() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"definitely not a qcow2 image header").unwrap();
        assert!(audit_path(f.path()).is_err());
    }

    fn snap(name: &str, secs: u32) -> Qcow2Snapshot {
        Qcow2Snapshot {
            id: "1".to_string(),
            name: name.to_string(),
            date_unix_secs: secs,
            date_nsecs: 0,
            vm_state_size: 0,
        }
    }

    #[test]
    fn audit_snapshots_emits_one_finding_per_snapshot() {
        let snaps = vec![snap("alpha", 1_700_000_000), snap("beta", 1_700_000_050)];
        let out = audit_snapshots(&snaps);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|a| a.code() == "QCOW2-SNAPSHOT"));
    }

    #[test]
    fn audit_snapshots_empty_yields_nothing() {
        assert!(audit_snapshots(&[]).is_empty());
    }

    #[test]
    fn snapshot_finding_carries_name_and_timestamp_in_evidence() {
        let out = audit_snapshots(&[snap("alpha", 1_700_000_000)]);
        let a = &out[0];
        assert_eq!(a.code(), "QCOW2-SNAPSHOT");
        assert!(a.severity() == Severity::Low || a.severity() == Severity::Info);
        assert!(
            a.note().contains("alpha"),
            "note must name the snapshot: {}",
            a.note()
        );
        let ev = a.evidence();
        let mut joined = String::new();
        for e in &ev {
            joined.push_str(&e.field);
            joined.push('=');
            joined.push_str(&e.value);
            joined.push(';');
        }
        assert!(
            joined.contains("alpha"),
            "evidence must carry the name: {joined}"
        );
        assert!(
            joined.contains("1700000000"),
            "evidence must carry the timestamp: {joined}"
        );
    }

    #[test]
    fn snapshot_anomaly_round_trips_to_a_finding() {
        let src = Source {
            analyzer: "qcow2-forensic".to_string(),
            scope: "image".to_string(),
            version: None,
        };
        let out = audit_snapshots(&[snap("alpha", 1_700_000_000)]);
        let f = out[0].to_finding(src);
        assert_eq!(f.code, "QCOW2-SNAPSHOT");
        assert!(f.severity.is_some());
        assert!(!f.note.is_empty());
        assert!(!f.evidence.is_empty());
    }
}
