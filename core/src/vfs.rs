//! `forensic-vfs` integration: a decoded QCOW2 as an [`ImageSource`].
//!
//! A decoded QCOW2 is a read-only, randomly-addressable byte stream — the
//! `ImageSource` contract. [`Qcow2Reader`] resolves a virtual offset through the
//! L1→L2 cluster tables via a `Read + Seek` cursor (the read advances an
//! internal position, so it needs `&mut self`). It is therefore wrapped here:
//! [`Qcow2Source`] holds the reader behind a poison-recovering `Mutex` and serves
//! `read_at` by seeking then reading under the lock. Reads serialize through the
//! mutex. Behind the `vfs` feature.

use std::io::{Read, Seek, SeekFrom};
use std::sync::{Mutex, PoisonError};

use forensic_vfs::{ImageSource, VfsError, VfsResult};

use crate::Qcow2Reader;

/// A decoded [`Qcow2Reader`] presented as a read-only [`ImageSource`].
///
/// Construction records the virtual disk size once; `read_at` locks the reader,
/// seeks, and fills the buffer. Because a QCOW2 read advances an internal cursor
/// (`&mut self`), reads **serialize through the mutex** — correct and
/// `Send + Sync`, at the cost of no intra-source read parallelism. The lock is
/// poison-recovering, so one panicking reader does not wedge the source.
pub struct Qcow2Source {
    inner: Mutex<Qcow2Reader>,
    len: u64,
}

impl Qcow2Source {
    /// Wrap an open [`Qcow2Reader`], recording its virtual disk size as the
    /// source length.
    pub fn new(reader: Qcow2Reader) -> Self {
        let len = reader.virtual_disk_size();
        Self {
            inner: Mutex::new(reader),
            len,
        }
    }
}

impl ImageSource for Qcow2Source {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let io_err = |op: &'static str| move |source: std::io::Error| VfsError::Io { op, source };
        let avail = self.len.saturating_sub(offset);
        if avail == 0 {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(avail) as usize;
        let mut guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        guard
            .seek(SeekFrom::Start(offset))
            .map_err(io_err("qcow2::seek"))?;
        let mut total = 0;
        while total < want {
            match guard
                .read(&mut buf[total..want])
                .map_err(io_err("qcow2::read"))?
            {
                0 => break,
                n => total += n,
            }
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::Arc;

    use forensic_vfs::ImageSource;

    use super::Qcow2Source;
    use crate::Qcow2Reader;

    /// A synthetic QCOW2 whose first cluster begins with a known marker, driven
    /// purely through the `ImageSource` API.
    #[test]
    fn qcow2_reader_is_an_image_source() {
        let mut sector = vec![0u8; crate::testutil::CLUSTER_SIZE];
        sector[..8].copy_from_slice(b"QCOWMRK!");
        let image = crate::testutil::test_qcow2(&sector);
        let reader = Qcow2Reader::open_reader(Box::new(Cursor::new(image))).expect("open qcow2");
        let expected_len = reader.virtual_disk_size();

        // The load-bearing claim: a Qcow2Reader composes as a dyn ImageSource.
        let src: Arc<dyn ImageSource> = Arc::new(Qcow2Source::new(reader));
        assert_eq!(src.len(), expected_len);
        assert!(!src.is_empty());

        // Positioned read of the first bytes returns the known marker.
        let mut buf = [0u8; 8];
        let n = src.read_at(0, &mut buf).expect("read_at");
        assert_eq!(n, 8);
        assert_eq!(&buf, b"QCOWMRK!");

        // A read starting at EOF yields 0 (ImageSource short-read contract).
        let mut eof = [0u8; 16];
        assert_eq!(src.read_at(expected_len, &mut eof).expect("eof read"), 0);
    }
}
