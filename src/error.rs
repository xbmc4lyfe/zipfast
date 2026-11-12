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

/// The password evidence available for this encryption context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RarPasswordEvidence {
    NotEncrypted,
    VerifierMatched,
    VerifierUnavailable(RarVerifierUnavailable),
}

/// Why the encryption record could not verify a password independently.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RarVerifierUnavailable {
    Absent,
    CheckChecksumMismatch,
}

/// The encryption or integrity context of a RAR failure.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum RarScope {
    Header { volume: PathBuf },
    Member { index: Option<u64> },
}

/// Checks and framing violations found while reading a RAR archive.
#[derive(Debug)]
#[non_exhaustive]
pub enum RarIntegrityReason {
    HeaderCrc,
    HeaderFraming(&'static str),
    MalformedEncryptionRecord,
    Decoder(&'static str),
    FinalChecks { crc32: bool, blake2sp: bool },
    PackedPiece { crc32: bool, blake2sp: bool, keyed: bool },
    DecodedSize { expected: u64, actual: u64 },
    TruncatedHeader,
    TruncatedData,
    IncompleteCipherBlock,
    MissingSplitContinuation,
    ChangedContinuationEncoding,
    DeclaredHashUnavailable,
    InvalidDictionary { requested: u64 },
}

#[derive(Debug)]
#[non_exhaustive]
pub enum RarUnsupported {
    ArchiveVersion(u8),
    CompressionAlgorithm { algorithm: u8, method: u8 },
    EncryptionVersion(u64),
    Redirection { kind: u64 },
    NameEncoding,
    Decoder(String),
}

#[derive(Debug)]
#[non_exhaustive]
pub enum RarResource {
    KdfExponent,
    DictionarySize,
    DictionaryAllocation,
    Counter,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum RarPolicyReason {
    UnsafePath,
    ProtectedInput,
    Symlink,
    Directory,
    ParentIsFile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum IoOperation {
    Open,
    Metadata,
    CreateDirectory,
    CreateFile,
    Read,
    Write,
    Seek,
    Publish,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum RarInternal {
    WorkerStopped,
    WorkerPanic,
    Invariant(&'static str),
}

/// Owned failure details from a RAR-only bulk run.
#[derive(Debug)]
#[non_exhaustive]
pub enum RarFailure {
    PasswordRequired { scope: RarScope },
    WrongPassword { scope: RarScope },
    Integrity { scope: RarScope, reason: RarIntegrityReason, password: RarPasswordEvidence },
    EncryptedIntegrity { scope: RarScope, reason: RarIntegrityReason, verifier: RarVerifierUnavailable },
    Unsupported(RarUnsupported),
    Limit { resource: RarResource, requested: Option<u64>, allowed: Option<u64> },
    SolidHistoryUnavailable { predecessor: Option<u64>, cause: Option<std::sync::Arc<RarFailure>> },
    Input { operation: IoOperation, path: Option<PathBuf>, offset: Option<u64>, source: io::Error },
    Output { operation: IoOperation, path: Option<PathBuf>, offset: Option<u64>, source: io::Error },
    Policy { reason: RarPolicyReason, path: PathBuf },
    MissingVolume { path: PathBuf },
    UnnamedVolume { path: PathBuf },
    NotRar,
    Internal(RarInternal),
}

impl fmt::Display for RarFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PasswordRequired { scope } => write!(f, "password required for {scope:?}"),
            Self::WrongPassword { scope } => write!(f, "password rejected for {scope:?}"),
            Self::Integrity { scope, reason, .. } => write!(f, "RAR integrity failure in {scope:?} ({reason:?})"),
            Self::EncryptedIntegrity { scope, reason, .. } => {
                write!(f, "RAR integrity failure or wrong password in {scope:?} ({reason:?})")
            }
            Self::Unsupported(reason) => write!(f, "unsupported RAR feature ({reason:?})"),
            Self::Limit { resource, requested, allowed } => {
                write!(f, "RAR limit ({resource:?}, requested {requested:?}, allowed {allowed:?})")
            }
            Self::SolidHistoryUnavailable { predecessor, .. } => {
                write!(f, "RAR solid history unavailable (predecessor {predecessor:?})")
            }
            Self::Input { operation, path, source, .. } | Self::Output { operation, path, source, .. } => {
                write!(f, "{operation:?}")?;
                if let Some(path) = path {
                    write!(f, " {}", path.display())?;
                }
                write!(f, ": {source}")
            }
            Self::Policy { reason, path } => write!(f, "RAR path blocked ({reason:?}): {}", path.display()),
            Self::MissingVolume { path } => write!(f, "missing volume {}", path.display()),
            Self::UnnamedVolume { path } => write!(f, "cannot determine the next volume after {}", path.display()),
            Self::NotRar => f.write_str("not a RAR archive"),
            Self::Internal(reason) => write!(f, "RAR internal failure ({reason:?})"),
        }
    }
}

impl std::error::Error for RarFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Input { source, .. } | Self::Output { source, .. } => Some(source),
            Self::SolidHistoryUnavailable { cause: Some(cause), .. } => Some(cause.as_ref()),
            _ => None,
        }
    }
}

impl RarFailure {
    pub(crate) fn integrity(
        scope: RarScope,
        reason: RarIntegrityReason,
        password: RarPasswordEvidence,
        plaintext_dependent: bool,
    ) -> Self {
        match password {
            RarPasswordEvidence::VerifierUnavailable(verifier) if plaintext_dependent => {
                Self::EncryptedIntegrity { scope, reason, verifier }
            }
            _ => Self::Integrity { scope, reason, password },
        }
    }

    pub(crate) fn crypt(error: crate::crypto::Rar5CryptError, scope: RarScope) -> Self {
        use crate::crypto::Rar5CryptError;
        match error {
            Rar5CryptError::Malformed => Self::integrity(
                scope,
                RarIntegrityReason::MalformedEncryptionRecord,
                RarPasswordEvidence::NotEncrypted,
                false,
            ),
            Rar5CryptError::UnsupportedVersion(version) => {
                Self::Unsupported(RarUnsupported::EncryptionVersion(version))
            }
            Rar5CryptError::KdfLimit(kdf) => {
                Self::Limit { resource: RarResource::KdfExponent, requested: Some(u64::from(kdf)), allowed: Some(24) }
            }
            Rar5CryptError::WrongPassword => Self::WrongPassword { scope },
        }
    }
}

/// An owned failure and its legacy projection. Transport errors stay owned by the detailed failure.
#[derive(Debug)]
pub(crate) struct RarFault {
    pub(crate) failure: Box<RarFailure>,
    legacy: Option<Error>,
    preserve_eof: bool,
}

pub(crate) type RarResult<T> = std::result::Result<T, RarFault>;

impl RarFault {
    pub(crate) fn new(failure: RarFailure, legacy: Error) -> Self {
        Self { failure: Box::new(failure), legacy: Some(legacy), preserve_eof: false }
    }

    pub(crate) fn input(operation: IoOperation, path: Option<PathBuf>, offset: Option<u64>, source: io::Error) -> Self {
        Self {
            failure: Box::new(RarFailure::Input { operation, path, offset, source }),
            legacy: None,
            preserve_eof: false,
        }
    }

    pub(crate) fn output(
        operation: IoOperation,
        path: Option<PathBuf>,
        offset: Option<u64>,
        source: io::Error,
        preserve_eof: bool,
    ) -> Self {
        Self { failure: Box::new(RarFailure::Output { operation, path, offset, source }), legacy: None, preserve_eof }
    }

    pub(crate) fn into_parts(self) -> (Box<RarFailure>, Error) {
        (self.failure, self.legacy.expect("structural failures have a legacy projection"))
    }

    pub(crate) fn into_legacy(self) -> Error {
        if let Some(legacy) = self.legacy {
            return legacy;
        }
        match *self.failure {
            RarFailure::Input { source, .. } | RarFailure::Output { source, .. } => {
                if self.preserve_eof {
                    Error::Io(source)
                } else {
                    source.into()
                }
            }
            _ => unreachable!("missing legacy RAR error projection"),
        }
    }
}
