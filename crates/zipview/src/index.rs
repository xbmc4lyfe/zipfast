// zipview -- read-only ZIP container reader
// Copyright (C) 2026 zipview contributors
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

//! Archives that are not in memory, read a byte range at a time.
//!
//! [`ZipIndexOpener`] follows the same steps as [`crate::ZipReader::new`], but asks
//! for each piece of the archive it needs instead of indexing a slice. The
//! tests hold the two to the same entries, comment and errors on every
//! fixture, every truncation of one and every single-byte corruption.

use super::{
    Listing, MAX_INFLATED_SIZE, PasswordCheck, Result, ZipEntry, ZipReadError, directory_error,
    local_password_check, parse_error, parse_local_header, read_local_entry,
};
use std::borrow::Cow;
use std::ops::Range;
use zip_container::{DirectoryParser, LOCAL_HEADER_LEN, Limits, Profile, local_layout};

/// The longest span [`ZipIndex::entry_range`] asks for: the largest entry
/// [`MAX_INFLATED_SIZE`] lets through, stored or deflated, with its headers.
const MAX_ENTRY_SPAN: u64 = MAX_INFLATED_SIZE + MAX_INFLATED_SIZE / 1024 + 128 * 1024;

/// The bytes a password check reads after the local header: an AES-256 salt
/// and verifier (18), which covers ZipCrypto's 12-byte header too.
const PASSWORD_CHECK_LEN: u64 = 16 + 2;

/// The directory of a ZIP archive that isn't in memory: a file too big to
/// load, or one read over a network a range at a time.
///
/// Opening reads the end of the archive and, when the directory lies outside
/// that range, probes and fetches its records. Reading an entry fetches only
/// that entry's bytes. Nothing else of the archive is read or
/// held. [`ZipIndex::open`] and [`ZipIndex::fetch_entry`] take a blocking
/// `read(offset, buf)`; [`ZipIndexOpener`], [`ZipIndex::entry_range`] and
/// [`ZipIndex::read_entry`] do the same work one read at a time, for callers
/// whose reads are asynchronous or need checking first.
///
/// ```
/// # fn main() -> std::io::Result<()> {
/// # let archive: Vec<u8> = vec![0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
/// // Any source of byte ranges: a file read by offset, HTTP range requests...
/// let read = |offset: u64, buf: &mut [u8]| -> std::io::Result<()> {
///     let start = offset as usize;
///     buf.copy_from_slice(&archive[start..start + buf.len()]);
///     Ok(())
/// };
/// let index = zipview::ZipIndex::open(archive.len() as u64, read)?;
/// for entry in index.entries() {
///     println!("{} ({} bytes)", entry.name(), entry.size());
/// }
/// if let Some(entry) = index.by_name("readme.txt") {
///     let bytes = index.fetch_entry(entry, None, read)?;
/// #   let _ = bytes;
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct ZipIndex {
    len: u64,
    listing: Listing,
}

/// Opens a [`ZipIndex`] one read at a time.
///
/// While [`next_read`](Self::next_read) names a range, read those bytes of
/// the archive however suits (asynchronously, say) and hand them to
/// [`supply`](Self::supply); then [`finish`](Self::finish) gives the index.
/// Each read asks for bytes not yet supplied. The central directory is parsed
/// once, as its pieces arrive, and processed input buffers are released.
/// Supply a contiguous prefix of the current request and keep any read-ahead
/// in your own buffers. Drop the opener to cancel between reads.
///
/// ```
/// use zipview::ZipIndexOpener;
/// # fn main() -> Result<(), zipview::ZipReadError> {
/// # let archive: Vec<u8> = vec![0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
/// let mut opener = ZipIndexOpener::new(archive.len() as u64);
/// while let Some(range) = opener.next_read()? {
///     let bytes = &archive[range.start as usize..range.end as usize]; // or fetch(range).await
///     opener.supply(range.start, bytes)?;
/// }
/// let index = opener.finish()?;
/// # let _ = index;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct ZipIndexOpener {
    len: u64,
    parser: Result<DirectoryParser<ZipEntry>>,
}

impl ZipIndexOpener {
    /// Starts opening an archive of `archive_len` bytes.
    pub fn new(archive_len: u64) -> Self {
        Self {
            len: archive_len,
            parser: DirectoryParser::with_projection(
                archive_len,
                Profile::Zipview,
                Limits::default(),
                ZipEntry::from_reduced_record,
            )
            .map_err(directory_error),
        }
    }

    /// The pending read, or `None` once everything is in. Repeated calls
    /// return the same range until more bytes are supplied. Archive errors
    /// match those from [`crate::ZipReader::new`].
    pub fn next_read(&mut self) -> Result<Option<Range<u64>>> {
        self.parser
            .as_mut()
            .map_err(|error| error.clone())?
            .next_read()
            .map_err(directory_error)
    }

    /// Supplies a contiguous prefix of the range from [`next_read`](Self::next_read).
    ///
    /// An empty in-bounds supply has no effect. A nonempty supply without a
    /// pending request, at the wrong offset, or beyond the request returns
    /// [`ZipReadError::BadOffset`] and leaves the opener's progress intact.
    pub fn supply(&mut self, offset: u64, bytes: &[u8]) -> Result<()> {
        match &mut self.parser {
            Ok(parser) => parser.supply(offset, bytes).map_err(directory_error),
            Err(_) if offset > self.len || !bytes.is_empty() => Err(ZipReadError::BadOffset),
            Err(_) => Ok(()),
        }
    }

    /// The index, once [`next_read`](Self::next_read) has nothing more to
    /// ask for. `Truncated` if it still needs bytes.
    pub fn finish(self) -> Result<ZipIndex> {
        let directory = self.parser?.finish().map_err(directory_error)?;
        Ok(ZipIndex {
            len: self.len,
            listing: Listing::from_directory(directory),
        })
    }
}

impl ZipIndex {
    /// Opens an archive of `archive_len` bytes with a blocking
    /// `read(offset, buf)`, which must fill `buf` from the archive at
    /// `offset`. Each read is at most 16 MiB.
    ///
    /// Errors come back as `E`: whatever `read` returns, or the archive's
    /// [`ZipReadError`] converted (`std::io::Error` converts).
    pub fn open<E: From<ZipReadError>>(
        archive_len: u64,
        mut read: impl FnMut(u64, &mut [u8]) -> std::result::Result<(), E>,
    ) -> std::result::Result<Self, E> {
        let mut opener = ZipIndexOpener::new(archive_len);
        while let Some(range) = opener.next_read()? {
            let start = range.start;
            let buf = read_range(range, &mut read, ZipReadError::BadOffset)?;
            opener.supply(start, &buf)?;
        }
        Ok(opener.finish()?)
    }

    /// The archive's length, as given when opening.
    pub fn archive_len(&self) -> u64 {
        self.len
    }

    /// Number of entries parsed. May be fewer than the archive declared when
    /// its central directory is damaged.
    pub fn len(&self) -> usize {
        self.listing.entries.len()
    }

    /// True when no entries parsed.
    pub fn is_empty(&self) -> bool {
        self.listing.entries.is_empty()
    }

    /// The archive comment, lossily decoded.
    pub fn comment(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.listing.comment)
    }

    /// All parsed entries, in central-directory order.
    pub fn entries(&self) -> &[ZipEntry] {
        &self.listing.entries
    }

    /// The entry at `index` in central-directory order.
    pub fn by_index(&self, index: usize) -> Option<&ZipEntry> {
        self.listing.entries.get(index)
    }

    /// The first entry whose name matches exactly.
    pub fn by_name(&self, name: &str) -> Option<&ZipEntry> {
        self.listing.entries.iter().find(|e| e.name == name)
    }

    /// Whether an entry with this exact name exists.
    pub fn contains(&self, name: &str) -> bool {
        self.by_name(name).is_some()
    }

    /// The first read toward `entry`'s data: its fixed 30-byte local header
    /// (shorter only where the archive ends). Its bytes go to
    /// [`entry_range`](Self::entry_range) or
    /// [`password_check_range`](Self::password_check_range).
    pub fn header_range(&self, entry: &ZipEntry) -> Result<Range<u64>> {
        let start = self.listing.local_start(entry, self.len)?;
        Ok(start..start.saturating_add(LOCAL_HEADER_LEN as u64).min(self.len))
    }

    /// The bytes of `entry` from its local header to the end of its data,
    /// given `header` (the bytes at [`header_range`](Self::header_range)).
    /// Read them and pass them to [`read_entry`](Self::read_entry).
    ///
    /// `EntryTooLarge` for an entry too big to read, before anything else.
    pub fn entry_range(&self, entry: &ZipEntry, header: &[u8]) -> Result<Range<u64>> {
        entry.check_inflated_size()?;
        let start = self.listing.local_start(entry, self.len)?;
        let packed_size = entry.checked_packed_size()?;
        // The preview clips to EOF, including when the local variable
        // fields or payload extend past it. A full read checks the bounds.
        let layout =
            local_layout(parse_local_header(header)?, start, u64::MAX).map_err(parse_error)?;
        let end = layout
            .payload_range(packed_size, u64::MAX)
            .map_err(parse_error)?
            .end
            .min(self.len);
        // A compressed size no entry within the limit could have.
        if end - start > MAX_ENTRY_SPAN {
            return Err(ZipReadError::EntryTooLarge(entry.compressed_size));
        }
        Ok(start..end)
    }

    /// The bytes [`password_check`](Self::password_check) needs for encrypted
    /// `entry`, given `header` (the bytes at
    /// [`header_range`](Self::header_range)): the local header and the first
    /// 18 bytes of data. `None` when it isn't encrypted or the header is
    /// unreadable.
    pub fn password_check_range(&self, entry: &ZipEntry, header: &[u8]) -> Option<Range<u64>> {
        if !entry.is_encrypted() {
            return None;
        }
        let start = self.listing.local_start(entry, self.len).ok()?;
        let layout = local_layout(parse_local_header(header).ok()?, start, u64::MAX).ok()?;
        let end = layout
            .payload_range(PASSWORD_CHECK_LEN, u64::MAX)
            .ok()?
            .end
            .min(self.len);
        Some(start..end)
    }

    /// Decompresses `entry` from `bytes`, the archive's bytes at
    /// [`entry_range`](Self::entry_range).
    pub fn read_entry(&self, entry: &ZipEntry, bytes: &[u8]) -> Result<Vec<u8>> {
        self.read_entry_with_password(entry, bytes, None)
    }

    /// Decompresses `entry` from `bytes` (the archive's bytes at
    /// [`entry_range`](Self::entry_range)), decrypting with `password` when
    /// encrypted.
    pub fn read_entry_with_password(
        &self,
        entry: &ZipEntry,
        bytes: &[u8],
        password: Option<&str>,
    ) -> Result<Vec<u8>> {
        entry.check_inflated_size()?;
        self.listing.local_start(entry, self.len)?;
        read_local_entry(bytes, 0, entry, password)
    }

    /// The [`PasswordCheck`] for `entry` from `bytes`, the archive's bytes at
    /// [`password_check_range`](Self::password_check_range).
    pub fn password_check(&self, entry: &ZipEntry, bytes: &[u8]) -> Option<PasswordCheck> {
        if !entry.is_encrypted() {
            return None;
        }
        self.listing.local_start(entry, self.len).ok()?;
        local_password_check(bytes, entry)
    }

    /// Reads and decompresses `entry` with a blocking `read(offset, buf)`
    /// (see [`open`](Self::open)): two reads, its local header and then the
    /// entry itself, decrypting with `password` when encrypted.
    pub fn fetch_entry<E: From<ZipReadError>>(
        &self,
        entry: &ZipEntry,
        password: Option<&str>,
        mut read: impl FnMut(u64, &mut [u8]) -> std::result::Result<(), E>,
    ) -> std::result::Result<Vec<u8>, E> {
        entry.check_inflated_size()?;
        let header_range = self.header_range(entry)?;
        let too_large = ZipReadError::EntryTooLarge(entry.checked_packed_size()?);
        let header = read_range(header_range, &mut read, too_large.clone())?;
        let range = self.entry_range(entry, &header)?;
        let bytes = read_range(range, &mut read, too_large)?;
        Ok(self.read_entry_with_password(entry, &bytes, password)?)
    }

    /// The [`PasswordCheck`] for `entry` with a blocking `read(offset, buf)`
    /// (see [`open`](Self::open)): `None` without a read when it isn't
    /// encrypted, otherwise two small reads.
    pub fn fetch_password_check<E: From<ZipReadError>>(
        &self,
        entry: &ZipEntry,
        mut read: impl FnMut(u64, &mut [u8]) -> std::result::Result<(), E>,
    ) -> std::result::Result<Option<PasswordCheck>, E> {
        if !entry.is_encrypted() {
            return Ok(None);
        }
        let Ok(range) = self.header_range(entry) else {
            return Ok(None);
        };
        let too_large = ZipReadError::EntryTooLarge(entry.compressed_size);
        let header = read_range(range, &mut read, too_large.clone())?;
        let Some(range) = self.password_check_range(entry, &header) else {
            return Ok(None);
        };
        let bytes = read_range(range, &mut read, too_large)?;
        Ok(self.password_check(entry, &bytes))
    }
}

/// Reads `range` with `read` into a new buffer, failing with `too_large`
/// rather than aborting when the buffer can't be allocated.
fn read_range<E: From<ZipReadError>>(
    range: Range<u64>,
    read: &mut impl FnMut(u64, &mut [u8]) -> std::result::Result<(), E>,
    too_large: ZipReadError,
) -> std::result::Result<Vec<u8>, E> {
    let n = usize::try_from(range.end - range.start).map_err(|_| too_large.clone())?;
    let mut buf = Vec::new();
    buf.try_reserve_exact(n).map_err(|_| too_large)?;
    buf.resize(n, 0);
    read(range.start, &mut buf)?;
    Ok(buf)
}

impl From<ZipReadError> for std::io::Error {
    fn from(e: ZipReadError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CENTRAL_HEADER_SIG, EOCD_SIG, LOCAL_HEADER_SIG, ZipReader};

    /// An archive of `n` empty stored entries named by `name`.
    fn archive(n: usize, name: impl Fn(usize) -> String) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for i in 0..n {
            let name = name(i);
            let offset = out.len() as u32;
            out.extend_from_slice(&LOCAL_HEADER_SIG.to_le_bytes());
            out.extend_from_slice(&[20, 0, 0, 0, 0, 0]); // needed, flags, method
            out.extend_from_slice(&[0; 16]); // time, date, crc, sizes
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&[0, 0]); // extra
            out.extend_from_slice(name.as_bytes());
            central.extend_from_slice(&CENTRAL_HEADER_SIG.to_le_bytes());
            central.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0]); // made by, needed, flags, method
            central.extend_from_slice(&[0; 16]); // time, date, crc, sizes
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&[0; 12]); // extra, comment, disk, attributes
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_offset = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(&EOCD_SIG.to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&(n as u16).to_le_bytes());
        out.extend_from_slice(&(n as u16).to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out
    }

    #[test]
    fn a_big_directory_is_parsed_once_and_not_held_twice() {
        // 60,000 entries with 300-byte names: about 21 MB of directory. Only
        // the first 64 KiB of each read is supplied, so it arrives in over
        // 300 pieces; parsing it again on every one would take minutes.
        let data = archive(60_000, |i| format!("{i:0>300}"));
        let mut opener = ZipIndexOpener::new(data.len() as u64);
        let (mut reads, mut parsed) = (0, 0);
        while let Some(range) = opener.next_read().expect("next read") {
            reads += 1;
            let parser = opener.parser.as_ref().unwrap();
            let entries = parser.usage().owned.entries;
            assert!(entries >= parsed);
            parsed = entries;
            // The tail and one partial record are sufficient, even while a
            // range much larger than either is being supplied in pieces.
            let held = parser.buffer_usage().live_bytes;
            assert!(held < 67_000, "{held} bytes held");
            let end = range.end.min(range.start + 65_536);
            let bytes = &data[range.start as usize..end as usize];
            opener.supply(range.start, bytes).expect("supply");
        }
        assert!(reads > 300, "{reads} reads");
        let index = opener.finish().expect("finish");
        assert_eq!(index.len(), 60_000);
        assert_eq!(index.entries()[59_999].name(), format!("{:0>300}", 59_999));
        let memory = ZipReader::new(&data).expect("parse");
        assert_eq!(
            format!("{:?}", memory.entries()),
            format!("{:?}", index.entries())
        );
    }

    #[test]
    fn finishing_early_is_an_error() {
        let data = archive(3, |i| format!("f{i}"));
        let opener = ZipIndexOpener::new(data.len() as u64);
        assert_eq!(
            opener.finish().map(|i| i.len()),
            Err(ZipReadError::Truncated)
        );
    }
}
