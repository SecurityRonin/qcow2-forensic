use thiserror::Error;

pub type Result<T> = std::result::Result<T, Qcow2Error>;

#[derive(Debug, Error)]
pub enum Qcow2Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("not a QCOW2 file: bad magic number")]
    BadMagic,
    #[error("unsupported QCOW2 version: {0}")]
    UnsupportedVersion(u32),
    #[error("encrypted QCOW2 images are not supported")]
    EncryptedNotSupported,
    #[error("QCOW2 images with a backing file are not supported")]
    BackingFileNotSupported,
    #[error("compressed cluster encountered; decompression is not supported")]
    CompressedCluster,
    #[error("unsupported QCOW2 incompatible feature flag(s): 0x{0:016x}")]
    UnsupportedIncompatibleFeatures(u64),
    #[error("QCOW2 file too small")]
    FileTooSmall,
}
