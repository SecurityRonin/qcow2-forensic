//! Fuzz target: lenient forensic header inspection on arbitrary bytes.
//! Invariant: never panics.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Write as _;

fuzz_target!(|data: &[u8]| {
    let mut f = tempfile::NamedTempFile::new().expect("tempfile");
    f.write_all(data).expect("write");
    let _ = qcow2::inspect(f.path());
});
