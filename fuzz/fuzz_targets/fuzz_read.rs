//! Fuzz target: open arbitrary bytes as QCOW2 and read the whole virtual stream.
//! Invariant: never panics; reads return Ok/Err but never out-of-bounds.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::{Read as _, Write as _};

fuzz_target!(|data: &[u8]| {
    let mut f = tempfile::NamedTempFile::new().expect("tempfile");
    f.write_all(data).expect("write");
    if let Ok(mut r) = qcow2::Qcow2Reader::open(f.path()) {
        let mut sink = vec![0u8; 4096];
        // Bounded read loop — stop after a fixed budget to keep the target fast.
        for _ in 0..256 {
            match r.read(&mut sink) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    }
});
