// Copyright (C) 2026 xbmc4lyfe
// SPDX-License-Identifier: RPL-1.5
//
// Unless explicitly acquired and licensed from Licensor under another license,
// the contents of this file are subject to the Reciprocal Public License
// ("RPL") Version 1.5, or subsequent versions as allowed by the RPL, and You
// may not copy or use this file in either source code or executable form,
// except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS"
// basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR
// HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT LIMITATION, ANY
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, QUIET
// ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing
// rights and limitations under the RPL.

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
