//! Fuzz target: feed arbitrary bytes to Qcow2Reader::open.
//!
//! Invariant: must not panic; may return Ok or Err.
//!
//! Run with:
//!   cargo +nightly fuzz run fuzz_open
//!
//! Corpus seeds in fuzz/corpus/fuzz_open/ (add real QCOW2 files here for coverage).
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Write as _;

fuzz_target!(|data: &[u8]| {
    let mut f = tempfile::NamedTempFile::new().expect("tempfile");
    f.write_all(data).expect("write");
    let _ = qcow2::Qcow2Reader::open(f.path());
});
