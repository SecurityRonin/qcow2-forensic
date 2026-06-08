//! Fuzz target: full inspect+audit pipeline on arbitrary bytes.
//! Invariant: never panics; produces a (possibly empty) anomaly list or Err.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Write as _;

fuzz_target!(|data: &[u8]| {
    let mut f = tempfile::NamedTempFile::new().expect("tempfile");
    f.write_all(data).expect("write");
    let _ = qcow2_forensic::audit_path(f.path());
});
