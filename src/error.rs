//! One error type for the whole crate.

use std::fmt;
use std::io;
use std::path::PathBuf;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    /// The bytes are not an archive this crate knows.
    NotAnArchive,
    /// A header failed its checksum or its structure is impossible.
    Corrupt(&'static str),
    /// The archive ended before a header or a data area did.
    Truncated,
    /// The next volume of a multi-volume set is not on disk.
    MissingVolume(PathBuf),
    /// The set has more volumes, but this volume's name doesn't say what the next one is called.
    UnnamedVolume(PathBuf),
    /// A feature the archive uses that this build cannot handle yet.
    Unsupported(String),
    /// The archive or a file in it is encrypted.
    Encrypted,
    /// Extracted data does not match the checksum stored for it.
    BadChecksum(String),
    /// A stored name would write outside the destination.
    UnsafePath(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::NotAnArchive => f.write_str("not a supported archive"),
            Error::Corrupt(what) => write!(f, "corrupt archive: {what}"),
            Error::Truncated => f.write_str("archive is truncated"),
            Error::MissingVolume(p) => write!(f, "missing volume {}", p.display()),
            Error::UnnamedVolume(p) => {
                write!(f, "{} says more volumes follow, but its name has no volume number to find them by", p.display())
            }
            Error::Unsupported(what) => write!(f, "unsupported: {what}"),
            Error::Encrypted => f.write_str("encrypted (passwords are not supported yet)"),
            Error::BadChecksum(name) => write!(f, "checksum error in {name}"),
            Error::UnsafePath(name) => write!(f, "unsafe path refused: {name}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::UnexpectedEof { Error::Truncated } else { Error::Io(e) }
    }
}
