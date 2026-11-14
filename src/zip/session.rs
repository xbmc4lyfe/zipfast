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

//! ZIP archives, read from PKWARE's published APPNOTE: the end of central directory record (and its ZIP64 form),

//! ZIP metadata and selected reads bound to one checked file and directory parse.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use zip_container::{CENTRAL_HEADER_LEN, CentralRecord, LimitKind};

use super::read::io::SourceCheckError;
use super::read::{
    CheckedSourceFault, EncryptedReadContext, IoStage, SourceInvalidationCode, ZipReadError, ZipReadResult,
};
use super::{
    AesFields, BUF, CentralHeader, CentralLocation, Directory, DirectoryDeclaration, DirectoryError, DirectoryParser,
    EndRecord, ExtraMtime, FLAG_UTF8, HOST_UNIX, Limits, Profile, ReadDescription, ResolvedFields, Usage, Zip64End,
    Zip64Locator, check_cancel, check_selection, decode_invalid_name, directory_error, extraction_unix_mode, is_dir,
    is_link, project_aes, project_mtime, read_directory, read_entry,
};
use crate::error::{Error, Result};
use crate::extract::Cancellation;
use crate::path::sanitize;

// This separately bounds the bytes needed when the decoded name cannot share
// the raw name or selected Unicode path allocation. It is a component budget.
const DECODED_NAME_BYTES: usize = 128 << 20;

/// Result of opening a ZIP session, checking its identity, or reading an entry.
pub type SessionResult<T> = std::result::Result<T, SessionError>;

/// Why the source can no longer be used by a session.
#[derive(Clone, Debug)]
pub enum SourceChange {
    /// The handle, the path, or both no longer match the original file stamp.
    StampMismatch,
    /// The required source identity or change information could not be obtained.
    Unverifiable(Arc<io::Error>),
}

impl fmt::Display for SourceChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StampMismatch => f.write_str("file identity or modification stamp changed"),
            Self::Unverifiable(error) => write!(f, "cannot verify ZIP source: {error}"),
        }
    }
}

impl std::error::Error for SourceChange {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::StampMismatch => None,
            Self::Unverifiable(error) => Some(error.as_ref()),
        }
    }
}

impl From<io::Error> for SourceChange {
    fn from(error: io::Error) -> Self {
        Self::Unverifiable(Arc::new(error))
    }
}

/// Errors from opening a session or reading its entries.
#[derive(Debug)]
#[non_exhaustive]
pub enum SessionError {
    /// The source changed or could not be verified. Reopen to obtain fresh metadata and IDs.
    SourceChanged {
        change: SourceChange,
        /// The original parse, decoder, cancellation or sink error, if one occurred.
        context: Option<Error>,
    },
    /// The platform has no supported file identity policy for sessions.
    UnsupportedIdentity,
    /// This entry ID belongs to a different metadata snapshot.
    ForeignEntryId,
    /// An ordinary archive, filesystem, cancellation or sink error.
    Archive(Error),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceChanged { change, context } => {
                write!(f, "ZIP source changed: {change}")?;
                if let Some(error) = context {
                    write!(f, " (operation error: {error})")?;
                }
                Ok(())
            }
            Self::UnsupportedIdentity => f.write_str("ZIP read sessions require a supported Unix file identity"),
            Self::ForeignEntryId => f.write_str("ZIP entry ID belongs to another read session"),
            Self::Archive(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SourceChanged { change, .. } => Some(change),
            Self::Archive(Error::Io(error)) => Some(error),
            Self::Archive(error) => Some(error),
            _ => None,
        }
    }
}

impl From<Error> for SessionError {
    fn from(error: Error) -> Self {
        Self::Archive(error)
    }
}

/// Retains one source file and the immutable metadata from its central directory.
///
/// Unix sessions compare handle and path identity, length, mtime and ctime
/// before and after parsing or decoding. These are optimistic checks.
/// Filesystem timestamp precision limits detection, and a writer may change
/// the source after the final check or change and restore the observed state
/// between checks.
/// Callers should stage sink bytes and publish them only after a successful
/// read and a final caller cancellation check.
pub struct ReadSession {
    pub(super) file: File,
    pub(super) source: SourceBinding,
    pub(super) metadata: Arc<Metadata>,
    pub(super) checked_identity: u64,
    dispatch_bytes: u64,
}

impl ReadSession {
    /// Opens a regular file and parses the central directory once.
    ///
    /// Shared parser limits bound the directory to 128 MiB and one million
    /// entries, and cumulative source fetches to 129 MiB. Additional decoded
    /// name bytes are limited separately to 128 MiB. Fixed records and buffer
    /// storage also contribute to process memory.
    ///
    /// Returns [`SessionError::UnsupportedIdentity`] on non-Unix platforms.
    pub fn open(path: &Path) -> SessionResult<Self> {
        Self::open_cancelable(path, &Cancellation::default())
    }

    /// Opens a session with cooperative cancellation between bounded reads and records.
    pub fn open_cancelable(path: &Path, cancel: &Cancellation) -> SessionResult<Self> {
        if !cfg!(unix) {
            return Err(SessionError::UnsupportedIdentity);
        }
        check_cancel(Some(cancel))?;
        let path = absolute_spelling(path).map_err(Error::from)?;
        check_cancel(Some(cancel))?;
        let file = open_file(&path).map_err(Error::from)?;
        let source = SourceBinding::capture(&file, path)?;
        Self::parse(file, source, 0, cancel)
    }

    fn parse(
        mut file: File,
        mut source: SourceBinding,
        dispatch_bytes: u64,
        cancel: &Cancellation,
    ) -> SessionResult<Self> {
        let len = source.stamp.len;
        let parsed = (|| {
            check_cancel(Some(cancel))?;
            let mut limits = Limits::default();
            limits.fetched_bytes = limits
                .fetched_bytes
                .checked_sub(dispatch_bytes)
                .filter(|&remaining| remaining > 0)
                .ok_or_else(|| directory_error(DirectoryError::Limit(LimitKind::FetchedBytes)))?;
            let parser = DirectoryParser::with_name_crc32(len, Profile::Zipfast, limits, crate::crc32::hash)
                .map_err(directory_error)?;
            #[cfg(all(test, unix))]
            let file = &mut tests::ObservedFile { file: &mut file, position: 0, event: tests::Event::DirectoryRead };
            #[cfg(not(all(test, unix)))]
            let file = &mut file;
            let directory = read_directory(file, len, parser, Some(cancel))?;
            Metadata::from_directory(directory, cancel)
        })();
        let metadata = source.finish_checked(&file, parsed)?;
        check_cancel(Some(cancel))?;
        Ok(Self {
            file,
            source,
            metadata: Arc::new(metadata),
            dispatch_bytes,
            checked_identity: super::read::projected_identity()
                .map_err(|_| Error::Corrupt("ZIP identity counter exhausted"))?,
        })
    }

    /// Source bytes fetched by format dispatch before ZIP directory parsing.
    ///
    /// These bytes and [`Metadata::parser_usage()`] share the same 129 MiB
    /// cumulative fetch limit. Repeated reads count each time. Sessions opened
    /// directly with [`Self::open`] or [`Self::open_cancelable`] report zero.
    pub fn dispatch_bytes(&self) -> u64 {
        self.dispatch_bytes
    }

    /// Shares the snapshot. It remains readable as historical metadata after invalidation or drop.
    pub fn metadata(&self) -> Arc<Metadata> {
        Arc::clone(&self.metadata)
    }

    /// Admits the actual output descriptor against this original checked owner.
    #[cfg(unix)]
    #[allow(clippy::result_large_err)]
    pub fn admit_output_fd(
        &mut self,
        fd: std::os::fd::BorrowedFd<'_>,
        context: &mut EncryptedReadContext,
    ) -> ZipReadResult<()> {
        if !context.has_action_plan() {
            return Err(super::ReadFault::InvalidPlan.into());
        }
        self.check_source_checked(context)?;
        context.admit_output_descriptor(self.checked_identity, self.source.stamp, fd)
    }

    /// Checks the original source without allocating an error wrapper.
    /// The first observation is moved out; subsequent checks return a Copy invalidation code.
    #[allow(clippy::result_large_err)] // Fixed inline terminal evidence must survive allocation refusal.
    pub fn check_source_checked(&mut self, context: &mut EncryptedReadContext) -> ZipReadResult<()> {
        context.verify_identity(self.checked_identity)?;
        if let Some(fault) = self.source.previous_invalidation() {
            return Err(ZipReadError::from(fault).with_usage(context.usage(), context.run_usage()));
        }
        context
            .source_group(self.source.stamp)
            .map_err(|fault| ZipReadError::from(fault).with_usage(context.usage(), context.run_usage()))?;
        self.source
            .verify_checked(&self.file, context)
            .map_err(|fault| ZipReadError::from(fault).with_usage(context.usage(), context.run_usage()))?;
        context.successful_source_observation(self.checked_identity, self.source.stamp)?;
        Ok(())
    }

    /// Checks that the retained handle and original path still identify the opened version.
    /// A failed check invalidates this session permanently.
    pub fn check_source(&mut self) -> SessionResult<()> {
        self.source.finish_checked(&self.file, Ok(()))
    }

    /// Selects a regular file, checks its path and limits, and borrows the session exclusively.
    ///
    /// `max_bytes` applies independently to packed and decoded size.
    pub fn select(
        &mut self,
        id: &EntryId,
        max_bytes: u64,
        cancel: Cancellation,
    ) -> SessionResult<SelectedZipEntry<'_>> {
        let ordinal = self.metadata.ordinal(id)?;
        self.check_source()?;
        check_cancel(Some(&cancel))?;
        let entry = self.metadata.view(ordinal);
        check_selection(entry.is_dir(), entry.is_link(), entry.packed_size(), entry.size(), max_bytes)?;
        let relative_path = sanitize(entry.name(), entry.creator_host() != HOST_UNIX)?;
        Ok(SelectedZipEntry { session: self, ordinal, relative_path, cancel, max_bytes })
    }
}

/// The retained data file and original ZIP identity attempt for format inspection.
pub(crate) struct InspectionSource {
    file: File,
    source: SessionResult<SourceBinding>,
    dispatch_bytes: u64,
}

impl InspectionSource {
    pub(crate) fn open(path: &Path, cancel: &Cancellation) -> SessionResult<Self> {
        check_cancel(Some(cancel))?;
        let path = absolute_spelling(path).map_err(Error::from)?;
        check_cancel(Some(cancel))?;
        let file = open_file(&path).map_err(Error::from)?;
        // Only ZIP dispatch needs a verified identity. Keep this attempt even
        // if it fails so the other formats can use their existing readers.
        let source =
            if cfg!(unix) { SourceBinding::capture(&file, path) } else { Err(SessionError::UnsupportedIdentity) };
        Ok(Self { file, source, dispatch_bytes: 0 })
    }

    pub(crate) fn probe_prefix(&mut self, max_len: u64, cancel: &Cancellation) -> Result<Vec<u8>> {
        check_cancel(Some(cancel))?;
        let len = self.file.metadata()?.len().min(max_len) as usize;
        let mut bytes = vec![0; len];
        if len > 0 {
            self.file.seek(SeekFrom::Start(0))?;
        }
        if self.read_probe(&mut bytes, cancel)? != len {
            return Err(Error::Truncated);
        }
        Ok(bytes)
    }

    pub(crate) fn read_probe(&mut self, bytes: &mut [u8], cancel: &Cancellation) -> Result<usize> {
        const CHUNK_BYTES: usize = 64 << 10;
        let mut done = 0;
        while done < bytes.len() {
            check_cancel(Some(cancel))?;
            let end = bytes.len().min(done + CHUNK_BYTES);
            let read = match self.file.read(&mut bytes[done..end]) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
            #[cfg(all(test, unix))]
            tests::observe(tests::Event::ProbeRead(done as u64..(done + read) as u64));
            done += read;
            // The two bounded probes total at most 1024 + 1 MiB + 8 bytes.
            self.dispatch_bytes += read as u64;
        }
        check_cancel(Some(cancel))?;
        Ok(done)
    }

    pub(crate) fn into_zip(self, cancel: &Cancellation) -> SessionResult<ReadSession> {
        let Self { file, source, dispatch_bytes } = self;
        let mut source = source?;
        source.finish_checked(&file, check_cancel(Some(cancel)))?;
        ReadSession::parse(file, source, dispatch_bytes, cancel)
    }
}

#[derive(Debug)]
struct SessionIdentity {
    // Keep identity as an allocated, non-zero-sized type.
    _private: u8,
}

/// An opaque reference to one central-directory ordinal in one snapshot.
#[derive(Clone, Debug)]
pub struct EntryId {
    identity: EntryIdentity,
    pub(super) ordinal: usize,
}

#[derive(Clone, Debug)]
enum EntryIdentity {
    Canonical(Arc<SessionIdentity>),
    Projected(u64),
}
impl EntryId {
    pub(super) fn projected(identity: u64, ordinal: usize) -> Self {
        Self { identity: EntryIdentity::Projected(identity), ordinal }
    }
    pub(super) fn is_projected(&self, identity: u64) -> bool {
        matches!(self.identity, EntryIdentity::Projected(id) if id == identity)
    }
}

/// The immutable ZIP directory and archive envelope from a successfully opened session.
pub struct Metadata {
    identity: Arc<SessionIdentity>,
    envelope: Directory,
    entries: Vec<CanonicalEntry>,
}

impl Metadata {
    fn from_directory(envelope: Directory, cancel: &Cancellation) -> Result<Self> {
        Self::from_directory_accounted(envelope, cancel).map(|(metadata, _, _)| metadata)
    }

    pub(super) const RECORD_BYTES: usize = std::mem::size_of::<CanonicalEntry>();

    pub(super) fn from_directory_accounted(mut envelope: Directory, cancel: &Cancellation) -> Result<(Self, u64, u64)> {
        let mut entries = Vec::new();
        entries.try_reserve_exact(envelope.entries.len()).map_err(|_| directory_error(DirectoryError::Allocation))?;
        let mut decoded_names = DecodedNameBudget(DECODED_NAME_BYTES);
        for record in std::mem::take(&mut envelope.entries) {
            check_cancel(Some(cancel))?;
            let entry =
                CanonicalEntry::from_record(record, |len| decoded_names.charge(len)).map_err(directory_error)?;
            entries.push(entry);
        }
        let capacity = entries.capacity() as u64 * Self::RECORD_BYTES as u64;
        let decoded = (DECODED_NAME_BYTES - decoded_names.0) as u64;
        Ok((Self { identity: Arc::new(SessionIdentity { _private: 0 }), envelope, entries }, capacity, decoded))
    }

    /// Number of central records, including duplicates.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the archive has zero central records.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns an ID for an ordinal in central order.
    pub fn entry_id(&self, ordinal: usize) -> Option<EntryId> {
        (ordinal < self.len())
            .then(|| EntryId { identity: EntryIdentity::Canonical(Arc::clone(&self.identity)), ordinal })
    }

    pub(super) fn ordinal(&self, id: &EntryId) -> SessionResult<usize> {
        if !matches!(&id.identity, EntryIdentity::Canonical(identity) if Arc::ptr_eq(identity, &self.identity))
            || id.ordinal >= self.len()
        {
            return Err(SessionError::ForeignEntryId);
        }
        Ok(id.ordinal)
    }

    /// Looks up an entry from this snapshot.
    pub fn entry(&self, id: &EntryId) -> SessionResult<EntryMetadata<'_>> {
        Ok(self.view(self.ordinal(id)?))
    }

    /// Borrows every entry in central order.
    pub fn entries(&self) -> impl ExactSizeIterator<Item = EntryMetadata<'_>> + DoubleEndedIterator + '_ {
        self.entries.iter().map(|entry| EntryMetadata { entry, prefix_shift: self.prefix_shift() })
    }

    pub(super) fn view(&self, ordinal: usize) -> EntryMetadata<'_> {
        EntryMetadata { entry: &self.entries[ordinal], prefix_shift: self.prefix_shift() }
    }

    /// Length of the opened source.
    pub fn source_len(&self) -> u64 {
        self.envelope.archive_len
    }

    /// Adjustment from stored ZIP-relative offsets to physical offsets.
    pub fn prefix_shift(&self) -> u64 {
        self.envelope.prefix_shift
    }

    /// Raw archive comment bytes.
    pub fn raw_comment(&self) -> &[u8] {
        &self.envelope.raw_comment
    }

    /// Physical range of the archive comment in the opened source.
    pub fn comment_range(&self) -> Range<u64> {
        self.envelope.comment_range.clone()
    }

    /// Original classic end record and its source range.
    pub fn end_record(&self) -> &EndRecord {
        &self.envelope.end_record
    }

    /// ZIP64 locator considered by the parser.
    pub fn zip64_locator(&self) -> Option<&Zip64Locator> {
        self.envelope.zip64_locator.as_ref()
    }

    /// Selected ZIP64 end record.
    pub fn zip64_end(&self) -> Option<&Zip64End> {
        self.envelope.zip64_end.as_ref()
    }

    /// Effective directory count, size and offset as stored.
    pub fn declaration(&self) -> DirectoryDeclaration {
        self.envelope.declaration
    }

    /// Declared directory range at the selected physical start.
    pub fn directory_range(&self) -> Range<u64> {
        self.envelope.directory_range.clone()
    }

    /// Physical range of available bytes in the parsed central records.
    pub fn observed_range(&self) -> Range<u64> {
        self.envelope.observed_range.clone()
    }

    /// Parsed extent including any unavailable declared comment suffix.
    pub fn logical_range(&self) -> Range<u64> {
        self.envelope.logical_range.clone()
    }

    /// Shared parser work, source fetch and raw metadata charges.
    pub fn parser_usage(&self) -> Usage {
        self.envelope.usage
    }
}

struct DecodedNameBudget(usize);

impl DecodedNameBudget {
    fn charge(&mut self, len: usize) -> std::result::Result<(), DirectoryError> {
        self.0 = self.0.checked_sub(len).ok_or(DirectoryError::Limit(LimitKind::NameBytes))?;
        Ok(())
    }
}

struct CanonicalEntry {
    header: CentralHeader,
    resolved: ResolvedFields,
    source: CentralLocation,
    name: CanonicalName,
    raw_comment: Box<[u8]>,
    raw_aes: Option<AesFields>,
    raw_mtime_override: Option<ExtraMtime>,
    modified: Option<(i64, u32)>,
}

// When raw_name is absent, the display String owns the raw name bytes.
// When has_unicode_path is true and raw_unicode_path is absent, the display
// String owns the selected Unicode path bytes. Other cases keep the raw bytes.
struct CanonicalName {
    display: String,
    raw_name: Option<Box<[u8]>>,
    raw_unicode_path: Option<Box<[u8]>>,
    has_unicode_path: bool,
}

impl CanonicalEntry {
    fn from_record(
        record: CentralRecord,
        charge: impl FnOnce(usize) -> std::result::Result<(), DirectoryError>,
    ) -> std::result::Result<Self, DirectoryError> {
        let CentralRecord { header, resolved, source, raw_name, raw_comment, known } = record;
        let (mtime, nanos) = project_mtime(header, known.mtime_override);
        let name = match known.unicode_path {
            Some(path) => match String::from_utf8(path.into_vec()) {
                Ok(display) => {
                    CanonicalName { display, raw_name: Some(raw_name), raw_unicode_path: None, has_unicode_path: true }
                }
                Err(invalid) => CanonicalName {
                    display: decode_invalid_name(invalid.as_bytes(), true, charge)?,
                    raw_name: Some(raw_name),
                    raw_unicode_path: Some(invalid.into_bytes().into_boxed_slice()),
                    has_unicode_path: true,
                },
            },
            None => match String::from_utf8(raw_name.into_vec()) {
                Ok(display) => {
                    CanonicalName { display, raw_name: None, raw_unicode_path: None, has_unicode_path: false }
                }
                Err(invalid) => CanonicalName {
                    display: decode_invalid_name(invalid.as_bytes(), header.flags & FLAG_UTF8 != 0, charge)?,
                    raw_name: Some(invalid.into_bytes().into_boxed_slice()),
                    raw_unicode_path: None,
                    has_unicode_path: false,
                },
            },
        };
        Ok(Self {
            header,
            resolved,
            source,
            name,
            raw_comment,
            raw_aes: known.aes,
            raw_mtime_override: known.mtime_override,
            modified: mtime.map(|seconds| (seconds, nanos)),
        })
    }
}

/// A borrowed view of one entry's raw metadata and its ZIP listing projections.
#[derive(Clone, Copy)]
pub struct EntryMetadata<'a> {
    entry: &'a CanonicalEntry,
    prefix_shift: u64,
}

impl<'a> EntryMetadata<'a> {
    /// Name interpreted with zipfast's Unicode-extra, UTF-8 and CP437 rules.
    pub fn name(self) -> &'a str {
        &self.entry.name.display
    }

    /// Raw central name bytes, including invalid UTF-8.
    pub fn raw_name(self) -> &'a [u8] {
        self.entry.name.raw_name.as_deref().unwrap_or_else(|| self.name().as_bytes())
    }

    /// Path bytes from the selected Unicode extra, if any.
    pub fn raw_unicode_path(self) -> Option<&'a [u8]> {
        self.entry
            .name
            .has_unicode_path
            .then(|| self.entry.name.raw_unicode_path.as_deref().unwrap_or_else(|| self.name().as_bytes()))
    }

    /// Available raw central comment.
    pub fn raw_comment(self) -> &'a [u8] {
        &self.entry.raw_comment
    }

    /// Original fixed central header, including raw DOS timestamps, attributes and sentinels.
    pub fn header(self) -> CentralHeader {
        self.entry.header
    }

    /// Resolved ZIP64 fields and the flags marking any remaining sentinels.
    pub fn resolved(self) -> ResolvedFields {
        self.entry.resolved
    }

    /// Record, name, extra and comment ranges in the opened source.
    ///
    /// These ranges describe the snapshot, even after the source has changed.
    pub fn source(self) -> CentralLocation {
        self.entry.source
    }

    /// Physical range of the fixed central header.
    pub fn fixed_header_range(self) -> Range<u64> {
        let start = self.source().raw_range().start;
        start..start + CENTRAL_HEADER_LEN as u64
    }

    /// Stored local-header offset after ZIP64 resolution and before relocation.
    pub fn stored_local_header_offset(self) -> u64 {
        self.entry.resolved.local_header_offset
    }

    /// Physical local-header offset in the opened file after prefix adjustment.
    pub fn physical_local_header_offset(self) -> u64 {
        // The strict parser validates this addition and bounds before admitting each record.
        self.stored_local_header_offset() + self.prefix_shift
    }

    /// Declared decoded size.
    pub fn size(self) -> u64 {
        self.entry.resolved.unpacked_size
    }

    /// Declared packed size.
    pub fn packed_size(self) -> u64 {
        self.entry.resolved.packed_size
    }

    /// Original CRC field, including for directories.
    pub fn raw_crc32(self) -> u32 {
        self.entry.header.crc32
    }

    /// CRC as shown in the generic zipfast listing.
    pub fn listing_crc32(self) -> Option<u32> {
        (!self.is_dir()).then_some(self.raw_crc32())
    }

    /// Method as shown in the generic zipfast listing.
    pub fn listing_method(self) -> u8 {
        self.entry.header.method.min(255) as u8
    }

    /// Creator host byte.
    pub fn creator_host(self) -> u8 {
        (self.entry.header.version_made_by >> 8) as u8
    }

    /// Creator version byte.
    pub fn creator_version(self) -> u8 {
        self.entry.header.version_made_by as u8
    }

    /// Unix mode used by root ZIP extraction, if present.
    pub fn extraction_unix_mode(self) -> Option<u32> {
        extraction_unix_mode(self.creator_host(), self.entry.header.external_attributes)
    }

    /// Unix mode as shown in ZIP format details, including host 19 and zero modes.
    pub fn display_unix_mode(self) -> Option<u32> {
        matches!(self.creator_host(), HOST_UNIX | 19).then_some(self.entry.header.external_attributes >> 16)
    }

    /// Whether zipfast treats the entry as a directory.
    pub fn is_dir(self) -> bool {
        is_dir(self.name(), self.creator_host(), self.entry.header.external_attributes)
    }

    /// Whether zipfast treats the entry as a Unix symlink.
    pub fn is_link(self) -> bool {
        is_link(self.creator_host(), self.entry.header.external_attributes)
    }

    /// ZIP entries are independently decodable.
    pub fn is_solid(self) -> bool {
        false
    }

    /// Whether the root decoder treats the entry as encrypted.
    pub fn encrypted(self) -> bool {
        self.read_description().encrypted()
    }

    /// The method used by the root decoder after applying the selected AES metadata.
    pub fn effective_method(self) -> u16 {
        self.read_description().effective_method()
    }

    /// Human-readable name for the raw method tag, including the AES wrapper tag.
    pub fn compression_name(self) -> &'static str {
        match self.entry.header.method {
            0 => "Stored",
            1 => "Shrunk",
            6 => "Imploded",
            8 => "Deflate",
            9 => "Deflate64",
            12 => "Bzip2",
            14 => "LZMA",
            93 => "Zstd",
            95 => "XZ",
            96 => "Jpeg",
            97 => "WavPack",
            98 => "PPMd",
            99 => "AES",
            _ => "Unknown",
        }
    }

    /// Selected raw AES metadata, including any unsupported strength byte.
    pub fn raw_aes_fields(self) -> Option<AesFields> {
        self.entry.raw_aes
    }

    /// AES strength, vendor version and underlying method accepted by the root decoder.
    pub fn aes_info(self) -> Option<(u8, u16, u16)> {
        project_aes(self.entry.raw_aes)
    }

    /// Selected raw NTFS or extended Unix modification time.
    pub fn raw_mtime_override(self) -> Option<ExtraMtime> {
        self.entry.raw_mtime_override
    }

    /// Modification time interpreted by zipfast as Unix seconds and nanoseconds.
    pub fn modified(self) -> Option<(i64, u32)> {
        self.entry.modified
    }

    pub(super) fn read_description(self) -> ReadDescription<'a> {
        ReadDescription {
            name: self.name(),
            flags: self.entry.header.flags,
            method: self.entry.header.method,
            crc32: self.raw_crc32(),
            packed: self.packed_size(),
            size: self.size(),
            local_at: self.physical_local_header_offset(),
            aes_info: self.aes_info(),
        }
    }
}

/// A checked regular-file selection, holding an exclusive borrow of its session.
pub struct SelectedZipEntry<'a> {
    session: &'a mut ReadSession,
    ordinal: usize,
    relative_path: PathBuf,
    cancel: Cancellation,
    max_bytes: u64,
}

impl SelectedZipEntry<'_> {
    /// Borrows this original selected record and its original sanitized path.
    #[allow(clippy::result_large_err)]
    pub fn stage_entry(&mut self) -> ZipReadResult<super::ZipStageEntry<'_>> {
        let metadata = self.session.metadata.view(self.ordinal);
        if metadata.is_dir() || metadata.is_link() || !super::supported(metadata.effective_method()) {
            return Err(super::ReadFault::InvalidPlan.into());
        }
        if let Some(fault) = self.session.source.previous_invalidation() {
            return Err(fault.into());
        }
        Ok(super::ZipStageEntry::original(
            &self.session.file,
            &mut self.session.source,
            self.session.checked_identity,
            self.ordinal,
            metadata.read_description(),
            metadata.creator_host() != 3,
            metadata.extraction_unix_mode(),
            metadata.modified(),
            Some(&self.relative_path),
        ))
    }
    /// Borrows the selected metadata for output staging.
    pub fn metadata(&self) -> EntryMetadata<'_> {
        self.session.metadata.view(self.ordinal)
    }

    /// Returns the root-decoded name.
    pub fn name(&self) -> &str {
        self.metadata().name()
    }

    /// Returns the checked extraction path relative to the output directory.
    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    /// Returns the root extraction mode.
    pub fn unix_mode(&self) -> Option<u32> {
        self.metadata().extraction_unix_mode()
    }

    /// Returns the root interpretation of the modification time.
    pub fn modified(&self) -> Option<(i64, u32)> {
        self.metadata().modified()
    }

    /// Streams this original selection under its bound single-use action.
    #[allow(clippy::result_large_err)]
    pub fn read_with_context(
        self,
        password: Option<&str>,
        context: &mut EncryptedReadContext,
        mut sink: impl FnMut(&[u8]) -> super::read::ZipSinkResult<()>,
    ) -> ZipReadResult<()> {
        let Self { session, ordinal, cancel, max_bytes, .. } = self;
        let e = session.metadata.view(ordinal).read_description();
        super::read::checked_read(
            &mut session.file,
            &mut session.source,
            session.checked_identity,
            ordinal,
            e,
            password,
            max_bytes,
            &cancel,
            context,
            &mut sink,
        )
    }

    /// Decodes and verifies the complete entry. Every sink byte is provisional
    /// until this returns success. Caller output publication is a separate step.
    ///
    /// Cancellation is cooperative, including across codec and crypto calls.
    pub fn read(self, password: Option<&str>, mut sink: impl FnMut(&[u8]) -> Result<()>) -> SessionResult<()> {
        let Self { session, ordinal, cancel, .. } = self;
        let mut buffer = vec![0; BUF];
        session.check_source()?;
        let entry = session.metadata.view(ordinal).read_description();
        let file = &mut session.file;
        #[cfg(all(test, unix))]
        let file = &mut tests::ObservedFile { file, position: 0, event: tests::Event::PayloadRead };
        let decoded =
            read_entry(file, session.source.stamp.len, &entry, password, &mut buffer, &mut sink, Some(&cancel));
        #[cfg(all(test, unix))]
        tests::observe(tests::Event::AfterDecoder);
        session.source.finish_checked(&session.file, decoded)?;
        check_cancel(Some(&cancel))?;
        Ok(())
    }
}

pub(super) struct SourceBinding {
    pub(super) path: PathBuf,
    pub(super) stamp: SourceStamp,
    invalid: Option<SourceChange>,
    checked_invalid: Option<(SourceInvalidationCode, Option<i32>)>,
}

impl SourceBinding {
    pub(super) fn from_checked(path: PathBuf, stamp: SourceStamp) -> Self {
        Self { path, stamp, invalid: None, checked_invalid: None }
    }
    fn capture(file: &File, path: PathBuf) -> SessionResult<Self> {
        let stamp = SourceStamp::capture(file, &path)
            .map_err(|change| SessionError::SourceChanged { change, context: None })?;
        Ok(Self { path, stamp, invalid: None, checked_invalid: None })
    }

    fn finish_checked<T>(&mut self, file: &File, attempt: Result<T>) -> SessionResult<T> {
        match self.verify(file) {
            Ok(()) => attempt.map_err(SessionError::from),
            Err(change) => Err(SessionError::SourceChanged { change, context: attempt.err() }),
        }
    }

    pub(super) fn previous_invalidation(&self) -> Option<CheckedSourceFault> {
        if let Some((code, raw_os_error)) = self.checked_invalid {
            return Some(CheckedSourceFault::PreviouslyInvalidated { code, raw_os_error });
        }
        // Inspect the preexisting legacy owner by borrow; do not clone its Arc.
        if let Some(change) = &self.invalid {
            let (code, raw_os_error) = match change {
                SourceChange::StampMismatch => (SourceInvalidationCode::StampMismatch, None),
                SourceChange::Unverifiable(error) => (SourceInvalidationCode::LegacyUnavailable, error.raw_os_error()),
            };
            return Some(CheckedSourceFault::PreviouslyInvalidated { code, raw_os_error });
        }
        None
    }
    /// A current namespace observation after ownership of the original File ended.
    /// This deliberately performs no held-descriptor observation and never refreshes the stamp.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(super) fn verify_retired_path(
        &mut self,
        mut stat: impl FnMut(
            IoStage,
            &mut dyn FnMut() -> io::Result<SourceStamp>,
        ) -> std::result::Result<SourceStamp, SourceCheckError>,
    ) -> std::result::Result<(), SourceCheckError> {
        if let Some(fault) = self.previous_invalidation() {
            return Err(SourceCheckError::Source(fault));
        }
        let result = stat(IoStage::SourcePath, &mut || SourceStamp::stat_path(&self.path)).and_then(|stamp| {
            if stamp == self.stamp { Ok(()) } else { Err(SourceCheckError::Source(CheckedSourceFault::StampMismatch)) }
        });
        if let Err(SourceCheckError::Source(fault)) = &result {
            self.checked_invalid = Some(fault.invalidation());
        }
        result
    }
    pub(super) fn verify_checked(
        &mut self,
        file: &File,
        context: &mut EncryptedReadContext,
    ) -> std::result::Result<(), SourceCheckError> {
        self.verify_with(file, |stage, call| context.source_stat(stage, call))
    }
    pub(super) fn verify_with(
        &mut self,
        file: &File,
        stat: impl FnMut(
            IoStage,
            &mut dyn FnMut() -> io::Result<SourceStamp>,
        ) -> std::result::Result<SourceStamp, SourceCheckError>,
    ) -> std::result::Result<(), SourceCheckError> {
        if let Some(fault) = self.previous_invalidation() {
            return Err(SourceCheckError::Source(fault));
        }
        let result = SourceStamp::capture_checked(file, &self.path, stat).and_then(|stamp| {
            if stamp == self.stamp { Ok(()) } else { Err(SourceCheckError::Source(CheckedSourceFault::StampMismatch)) }
        });
        if let Err(SourceCheckError::Source(fault)) = &result {
            self.checked_invalid = Some(fault.invalidation());
        }
        result
    }

    pub(super) fn verify(&mut self, file: &File) -> std::result::Result<(), SourceChange> {
        if let Some(change) = &self.invalid {
            return Err(change.clone());
        }
        if let Some((code, os_error)) = self.checked_invalid {
            // Only the old API adapts to its historical allocated/cloneable representation.
            return Err(match code {
                SourceInvalidationCode::StampMismatch => SourceChange::StampMismatch,
                _ => SourceChange::from(
                    os_error.map(io::Error::from_raw_os_error).unwrap_or_else(|| io::ErrorKind::Other.into()),
                ),
            });
        }
        let verified = SourceStamp::capture(file, &self.path)
            .and_then(|stamp| if stamp == self.stamp { Ok(()) } else { Err(SourceChange::StampMismatch) });
        if let Err(change) = &verified {
            self.invalid = Some(change.clone());
        }
        verified
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SourceStamp {
    regular: bool,
    pub(super) len: u64,
    pub(super) dev: u64,
    pub(super) ino: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl SourceStamp {
    pub(super) fn capture_checked(
        file: &File,
        path: &Path,
        mut stat: impl FnMut(IoStage, &mut dyn FnMut() -> io::Result<Self>) -> std::result::Result<Self, SourceCheckError>,
    ) -> std::result::Result<Self, SourceCheckError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let (before, resolved, after) = (
            stat(IoStage::SourceHandle, &mut || Self::stat_handle(file))?,
            stat(IoStage::SourcePath, &mut || Self::stat_path(path))?,
            stat(IoStage::SourceHandle, &mut || Self::stat_handle(file))?,
        );
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let (before, resolved, after) = (
            stat(IoStage::SourceHandle, &mut || Self::from_metadata_checked(file.metadata()?))?,
            stat(IoStage::SourcePath, &mut || Self::from_metadata_checked(fs::metadata(path)?))?,
            stat(IoStage::SourceHandle, &mut || Self::from_metadata_checked(file.metadata()?))?,
        );
        if before != resolved || before != after {
            return Err(SourceCheckError::Source(CheckedSourceFault::StampMismatch));
        }
        Ok(before)
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn stat_handle(file: &File) -> io::Result<Self> {
        use std::os::fd::AsRawFd;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: descriptor is borrowed and live, stat is a writable output of
        // exactly the required layout. One syscall; EINTR returns to the budget.
        if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Self::from_stat(unsafe { stat.assume_init() })
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn stat_path(path: &Path) -> io::Result<Self> {
        use std::os::unix::ffi::OsStrExt;
        let bytes = path.as_os_str().as_bytes();
        // Match the kernel pathname limit without a temporary CString allocation.
        let mut terminated = [0u8; libc::PATH_MAX as usize];
        if bytes.len() >= terminated.len() {
            return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
        }
        if bytes.contains(&0) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        terminated[..bytes.len()].copy_from_slice(bytes);
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: pathname has a trailing NUL and no interior NUL; output has
        // exact stat layout. Follow symlinks exactly as legacy fs::metadata does.
        if unsafe { libc::stat(terminated.as_ptr().cast(), stat.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Self::from_stat(unsafe { stat.assume_init() })
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    // stat inode/device widths vary with the Unix ABI; preserve MetadataExt casts.
    #[allow(clippy::unnecessary_cast)]
    fn from_stat(stat: libc::stat) -> io::Result<Self> {
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(Self {
            regular: true,
            len: u64::try_from(stat.st_size).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?,
            dev: stat.st_dev as u64,
            ino: stat.st_ino as u64,
            mtime: (stat.st_mtime, stat.st_mtime_nsec),
            ctime: (stat.st_ctime, stat.st_ctime_nsec),
        })
    }
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
    fn from_metadata_checked(metadata: fs::Metadata) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let file_type = metadata.file_type();
        if !file_type.is_file() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(Self {
            regular: true,
            len: metadata.len(),
            dev: metadata.dev(),
            ino: metadata.ino(),
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
    #[cfg(not(unix))]
    fn from_metadata_checked(_: fs::Metadata) -> io::Result<Self> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn capture(file: &File, path: &Path) -> std::result::Result<Self, SourceChange> {
        let before = Self::from_metadata(file.metadata()?)?;
        let resolved = Self::from_metadata(fs::metadata(path)?)?;
        let after = Self::from_metadata(file.metadata()?)?;
        if before != resolved || before != after {
            return Err(SourceChange::StampMismatch);
        }
        Ok(before)
    }

    #[cfg(unix)]
    fn from_metadata(metadata: fs::Metadata) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;

        let file_type = metadata.file_type();
        if !file_type.is_file() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "ZIP source is not a regular file"));
        }
        Ok(Self {
            regular: true,
            len: metadata.len(),
            dev: metadata.dev(),
            ino: metadata.ino(),
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }

    #[cfg(not(unix))]
    fn from_metadata(_: fs::Metadata) -> io::Result<Self> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "Unix source identity unavailable"))
    }
}

fn absolute_spelling(path: &Path) -> io::Result<PathBuf> {
    // Keep symlink and parent components in the original absolute spelling.
    if path.is_absolute() { Ok(path.to_path_buf()) } else { Ok(std::env::current_dir()?.join(path)) }
}

fn open_file(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;

        // Opening a FIFO for a file-type check must not block waiting for a writer.
        fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(path)?
    };
    #[cfg(not(unix))]
    let file = File::open(path)?;
    #[cfg(all(test, unix))]
    tests::observe(tests::Event::Opened);
    Ok(file)
}

#[cfg(all(test, unix))]
mod tests;
