//! `forensic-vfs` integration: a decoded QCOW2 as an [`ImageSource`].
//!
//! A decoded QCOW2 is a read-only, randomly-addressable byte stream — the
//! `ImageSource` contract. [`Qcow2Reader`] resolves a virtual offset through the
//! L1→L2 cluster tables via a `Read + Seek` cursor (the read advances an
//! internal position, so it needs `&mut self`). It is therefore wrapped here:
//! [`Qcow2Source`] holds the reader behind a poison-recovering `Mutex` and serves
//! `read_at` by seeking then reading under the lock. Reads serialize through the
//! mutex. Behind the `vfs` feature.

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
