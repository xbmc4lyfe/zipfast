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

use std::ops::Range;

use zip_container::CentralHeader;

use super::*;

const SENTINEL: u64 = u32::MAX as u64;

/// Framing admitted by the rewrite layout pass. The source callback sees only
/// the validated spans or their explicitly listed subranges.
pub(in crate::zip) struct PreparedRaw {
    pub(crate) source_ordinal: usize,
    pub(crate) local: Range<u64>,
    pub(crate) central: Range<u64>,
    pub(crate) extra_at: u64,
    pub(crate) central_header: CentralHeader,
    pub(crate) local_version: u16,
    pub(crate) zip64_extra: Option<(u16, u16)>,
    pub(crate) wide_sizes: bool,
    pub(crate) packed: u64,
    pub(crate) decoded: u64,
}

#[derive(Clone, Copy, Debug)]
pub(in crate::zip) struct RawWritten {
    pub(crate) source_ordinal: usize,
    pub(crate) ordinal: u64,
    pub(crate) local_offset: u64,
    pub(crate) local_len: u64,
    pub(crate) packed: u64,
    pub(crate) decoded: u64,
    pub(crate) method: u16,
    pub(crate) crc: u32,
    pub(crate) proof: Proof,
}

/// Bounded description of the only non-Copy segments. Copy segments are
/// implicit between these sorted replacements or insertions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::zip) struct Proof {
    pub(crate) widened: bool,
    pub(crate) offset64_at: Option<u64>,
    pub(crate) extra_growth: u16,
}

impl PreparedRaw {
    pub(in crate::zip) fn proof(&self, at: u64) -> Result<Proof, WriteError> {
        let already_wide = self.central_header.local_header_offset == u32::MAX;
        let wide = already_wide || at >= SENTINEL;
        let widened = wide && !already_wide;
        let growth = match (widened, self.zip64_extra) {
            (true, Some(_)) => 8,
            (true, None) => 12,
            _ => 0,
        };
        self.central_header
            .extra_len
            .checked_add(growth)
            .ok_or(WriteError::InvalidMetadata("ZIP64 offset does not fit the preserved extra block"))?;
        let extra_end = add(self.extra_at, u64::from(self.central_header.extra_len))?;
        let offset64_at = if !wide {
            None
        } else if let Some((at, size)) = self.zip64_extra {
            // An existing offset and a selected start disk are the only
            // selected values after this position.
            let suffix = 8 * u16::from(already_wide) + 4 * u16::from(self.central_header.disk_start == u16::MAX);
            let before_offset = size.checked_sub(suffix).ok_or(WriteError::Overflow)?;
            Some(add(self.extra_at, u64::from(at) + 4 + u64::from(before_offset))?)
        } else {
            Some(extra_end)
        };
        Ok(Proof { widened, offset64_at, extra_growth: growth })
    }

    pub(in crate::zip) fn output_central_len(&self, proof: Proof) -> Result<u64, WriteError> {
        add(self.central.end - self.central.start, u64::from(proof.extra_growth))
    }
}

/// A ranged source admits positive read progress under the transaction
/// attempt budget. The writer additionally charges its own I/O attempts.
type Source<'a> = dyn FnMut(u64, &mut [u8]) -> io::Result<usize> + 'a;

impl<W: Write + Seek> ZipWriter<W> {
    pub(in crate::zip) fn write_prefix(&mut self, len: u64, source: &mut Source<'_>) -> Result<(), WriteError> {
        self.check_failed()?;
        if self.output.position != 0 || !self.central.is_empty() {
            return Err(WriteError::InvalidMetadata("prefix must precede all archive bytes"));
        }
        self.output.check_tail(End::new(0, 0, len, false, self.comment_len), len)?;
        let result = self.copy_local(0..len, source);
        self.remember_failure(result)
    }

    pub(in crate::zip) fn add_preserved(
        &mut self,
        raw: &PreparedRaw,
        source: &mut Source<'_>,
    ) -> Result<RawWritten, WriteError> {
        self.check_failed()?;
        let at = self.output.position;
        let proof = raw.proof(at)?;
        let wide = raw.wide_sizes || proof.offset64_at.is_some() || raw.central_header.disk_start == u16::MAX;
        let usage = self.output.work.usage;
        let entries = add(usage.entries, 1)?;
        let central = add(self.central.len() as u64, raw.output_central_len(proof)?)?;
        let local_len = raw.local.end - raw.local.start;
        let total_packed = add(usage.packed_bytes, raw.packed)?;
        let total_decoded = add(usage.decoded_bytes, raw.decoded)?;
        let limits = self.output.work.limits;
        bound(entries, limits.entries, Limit::Entries)?;
        bound(central, limits.central_bytes, Limit::CentralBytes)?;
        let end = End::new(entries, central, add(at, local_len)?, self.wide_member || wide, self.comment_len);
        self.output.check_tail(end, local_len)?;
        self.output.work.check_canceled()?;
        self.reserve_central(central)?;

        let result = self.write_preserved(raw, at, proof, source);
        self.remember_failure(result)?;
        self.wide_member |= wide;
        self.output.work.usage.entries = entries;
        self.output.work.usage.packed_bytes = total_packed;
        self.output.work.usage.decoded_bytes = total_decoded;
        Ok(RawWritten {
            source_ordinal: raw.source_ordinal,
            ordinal: entries - 1,
            local_offset: at,
            local_len,
            packed: raw.packed,
            decoded: raw.decoded,
            method: raw.central_header.method,
            crc: raw.central_header.crc32,
            proof,
        })
    }

    fn write_preserved(
        &mut self,
        raw: &PreparedRaw,
        at: u64,
        proof: Proof,
        source: &mut Source<'_>,
    ) -> Result<(), WriteError> {
        if proof.widened && raw.local_version < 45 {
            let start = raw.local.start;
            self.copy_local(start..start + 4, source)?;
            self.output.write(&45_u16.to_le_bytes(), IoStage::LocalHeader)?;
            self.copy_local(start + 6..raw.local.end, source)?;
        } else {
            self.copy_local(raw.local.clone(), source)?;
        }

        let mut cursor = raw.central.start;
        let start = cursor;
        if proof.widened && raw.central_header.version_needed < 45 {
            self.patch_central(&mut cursor, start + 6, 2, &45_u16.to_le_bytes(), source)?;
        }
        if proof.extra_growth != 0 {
            let len = raw.central_header.extra_len + proof.extra_growth;
            self.patch_central(&mut cursor, start + 30, 2, &len.to_le_bytes(), source)?;
        }
        let offset = if proof.offset64_at.is_some() { u32::MAX } else { at as u32 };
        self.patch_central(&mut cursor, start + 42, 4, &offset.to_le_bytes(), source)?;
        if let Some(wide_at) = proof.offset64_at {
            if let Some((extra_at, size)) = raw.zip64_extra {
                if proof.widened {
                    let len_at = raw.extra_at + u64::from(extra_at) + 2;
                    self.patch_central(&mut cursor, len_at, 2, &(size + 8).to_le_bytes(), source)?;
                }
                let replaced = if proof.widened { 0 } else { 8 };
                self.patch_central(&mut cursor, wide_at, replaced, &at.to_le_bytes(), source)?;
            } else {
                let mut extra = [1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0];
                extra[4..].copy_from_slice(&at.to_le_bytes());
                self.patch_central(&mut cursor, wide_at, 0, &extra, source)?;
            }
        }
        self.copy_central(cursor..raw.central.end, source)?;
        self.output.work.check_canceled()
    }

    fn patch_central(
        &mut self,
        cursor: &mut u64,
        at: u64,
        replaced: u64,
        literal: &[u8],
        source: &mut Source<'_>,
    ) -> Result<(), WriteError> {
        self.copy_central(*cursor..at, source)?;
        self.central.extend_from_slice(literal);
        *cursor = add(at, replaced)?;
        Ok(())
    }

    fn copy_local(&mut self, span: Range<u64>, source: &mut Source<'_>) -> Result<(), WriteError> {
        self.copy_span(span, source, |writer, data| writer.output.write(data, IoStage::Payload))
    }

    fn copy_central(&mut self, span: Range<u64>, source: &mut Source<'_>) -> Result<(), WriteError> {
        self.copy_span(span, source, |writer, data| {
            writer.central.extend_from_slice(data);
            Ok(())
        })
    }

    fn copy_span(
        &mut self,
        span: Range<u64>,
        source: &mut Source<'_>,
        mut consume: impl FnMut(&mut Self, &[u8]) -> Result<(), WriteError>,
    ) -> Result<(), WriteError> {
        let mut buffer = [0; BUFFER];
        let mut offset = span.start;
        while offset < span.end {
            let size = (span.end - offset).min(buffer.len() as u64) as usize;
            let count = self.output.work.io(IoStage::SourceRead, || source(offset, &mut buffer[..size]))?;
            if count == 0 || count > size {
                return Err(WriteError::io(IoStage::SourceRead, ErrorKind::UnexpectedEof.into()));
            }
            consume(self, &buffer[..count])?;
            offset += count as u64;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn source(disk: bool) -> (PreparedRaw, Vec<u8>) {
        let mut bytes = vec![0; 30 + 46];
        bytes[..6].copy_from_slice(b"PK\x03\x04\x14\x00");
        bytes[30..38].copy_from_slice(b"PK\x01\x02\x3f\x03\x14\x00");
        let extra_at = bytes.len() as u64;
        if disk {
            bytes[30 + 30..30 + 32].copy_from_slice(&8_u16.to_le_bytes());
            bytes[30 + 34..30 + 36].copy_from_slice(&u16::MAX.to_le_bytes());
            bytes.extend([1, 0, 4, 0, 0, 0, 0, 0]);
        }
        let central_header = CentralHeader::parse(&bytes[30..]).unwrap();
        let raw = PreparedRaw {
            source_ordinal: 0,
            local: 0..30,
            central: 30..bytes.len() as u64,
            extra_at,
            central_header,
            local_version: 20,
            zip64_extra: disk.then_some((0, 4)),
            wide_sizes: false,
            packed: 0,
            decoded: 0,
        };
        (raw, bytes)
    }

    #[test]
    fn offset_sentinel_inserts_before_selected_disk_and_preserves_creator() {
        for at in [u64::from(u32::MAX) - 1, u64::from(u32::MAX), u64::from(u32::MAX) + 1] {
            let (raw, bytes) = source(true);
            let mut writer = ZipWriter::new(Cursor::new(Vec::new()), WriterOptions::default()).unwrap();
            // Position is virtual. Only the actual local and central record
            // bytes use the in-memory sink.
            writer.output.position = at;
            let written = writer
                .add_preserved(&raw, &mut |from, out| {
                    out.copy_from_slice(&bytes[from as usize..from as usize + out.len()]);
                    Ok(out.len())
                })
                .unwrap();
            let wide = at >= u64::from(u32::MAX);
            assert_eq!(written.proof.widened, wide);
            assert_eq!(&writer.central[4..6], &[0x3f, 0x03]);
            if wide {
                assert_eq!(&writer.central[6..8], &[45, 0]);
                assert_eq!(&writer.central[30..32], &[16, 0]);
                assert_eq!(&writer.central[42..46], &[0xff; 4]);
                assert_eq!(&writer.central[46..50], &[1, 0, 12, 0]);
                assert_eq!(&writer.central[50..58], &at.to_le_bytes());
                assert_eq!(&writer.central[58..62], &[0; 4]);
                assert_eq!(&writer.output.sink.get_ref()[4..6], &[45, 0]);
            } else {
                assert_eq!(&writer.central[42..46], &(at as u32).to_le_bytes());
                assert_eq!(&writer.central[46..54], &[1, 0, 4, 0, 0, 0, 0, 0]);
                assert_eq!(&writer.output.sink.get_ref()[4..6], &[20, 0]);
            }
        }
    }

    #[test]
    fn an_offset_growth_overflow_or_full_extra_is_refused_before_source_reads() {
        let (mut raw, _) = source(false);
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()), WriterOptions::default()).unwrap();
        writer.output.position = u64::MAX;
        let error = writer.add_preserved(&raw, &mut |_, _| panic!("preflight must not read")).unwrap_err();
        assert!(matches!(error, WriteError::Overflow));
        writer.output.position = u64::from(u32::MAX);
        raw.central_header.extra_len = u16::MAX;
        let error = writer.add_preserved(&raw, &mut |_, _| panic!("preflight must not read")).unwrap_err();
        assert!(matches!(error, WriteError::InvalidMetadata(_)));
        assert_eq!(writer.usage().entries, 0);
        assert!(writer.failed.is_none());
    }

    #[test]
    fn short_read_poisons_after_raw_member_admission() {
        let (raw, _) = source(false);
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()), WriterOptions::default()).unwrap();
        let error = writer.add_preserved(&raw, &mut |_, _| Ok(0)).unwrap_err();
        assert!(matches!(error, WriteError::Io { stage: IoStage::SourceRead, .. }));
        assert!(matches!(writer.finish(), Err(WriteError::Failed(_))));
    }
}
