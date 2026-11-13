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

//! A bounded per-member recovery proof, separate from ordinary rewrite admission.
//!
//! The recovery transaction owns the held source, strict central snapshot,
//! nonoverlapping physical boundary index and binding checks. This seam neither
//! discovers candidates nor writes or publishes output.

use super::*;
use crate::zip::create::native::verify::{Payload, Reader as PayloadReader};
use crate::zip::create::{CreateLimits, VerificationUsage};
use crate::zip::rewrite::RewriteLimits;

#[derive(Debug)]
pub(in crate::zip) enum RecoveryOutcome {
    Verified(RecoveredMember),
    Omitted(RecoveryIssue),
}

pub(in crate::zip) use crate::zip::recovery::RecoveryIssue;

#[derive(Debug)]
pub(in crate::zip) struct RecoveredMember {
    pub(in crate::zip) framing: Member,
    pub(in crate::zip) descriptor: Option<DescriptorRepair>,
}

/// A signed descriptor replacement proved by exact framing and decoded data.
#[derive(Clone, Copy, Debug)]
pub(in crate::zip) struct DescriptorRepair {
    pub(in crate::zip) offset: u64,
    pub(super) data: [u8; 24],
    pub(super) len: u8,
}

impl DescriptorRepair {
    pub(in crate::zip) fn bytes(&self) -> &[u8] {
        &self.data[..usize::from(self.len)]
    }
}

#[derive(Default)]
pub(in crate::zip) struct RecoveryUsage {
    pub(in crate::zip) layout_read_bytes: u64,
    pub(in crate::zip) payload: VerificationUsage,
}

/// Verify one central-directed candidate on the caller's held source.
/// Member-local corruption is an omission; I/O, limits and cancellation remain
/// terminal. A descriptor patch is returned only after successful payload checks.
/// Callers retain usage across candidates, including failed payloads.
pub(in crate::zip) fn recover_member(
    file: &mut File,
    central: crate::zip::EntryMetadata<'_>,
    boundary: u64,
    limits: RewriteLimits,
    attempts: &Attempts<'_>,
    usage: &mut RecoveryUsage,
) -> Result<RecoveryOutcome> {
    attempts.check_cancel()?;
    if central.encrypted() || !matches!(central.header().method, 0 | 8) {
        return Ok(RecoveryOutcome::Omitted(RecoveryIssue::UnsupportedPayload));
    }
    if central.display_unix_mode().is_some_and(|mode| {
        let kind = mode & 0o170000;
        !matches!(kind, 0 | 0o100000 | 0o040000) || (kind == 0o040000 && !raw_directory(central))
    }) {
        return Ok(RecoveryOutcome::Omitted(RecoveryIssue::UnsupportedEntryKind));
    }
    preflight(central, limits.common, &usage.payload)?;
    let mut buffer = [0; BUFFER];
    let framing = framed_member(
        &mut Reader {
            file,
            attempts,
            bytes: &mut usage.layout_read_bytes,
            max: limits.layout_read_bytes,
            exhausted: ReadLimit::Rewrite(RewriteLimit::LayoutReadBytes),
        },
        central,
        boundary,
        &mut buffer,
        true,
    );
    let (framing, descriptor) = match framing {
        Ok(member) => member,
        Err(RewriteError::UnsupportedLayout(reason)) => {
            return Ok(RecoveryOutcome::Omitted(RecoveryIssue::Framing(reason)));
        }
        Err(error) => return Err(error),
    };
    if !framing.directory {
        let payload = Payload {
            method: central.header().method,
            packed_size: central.packed_size(),
            decoded_size: central.size(),
            crc32: central.raw_crc32(),
        };
        let result = PayloadReader::new(file, limits.common, attempts, &mut usage.payload).check_payload(
            framing.payload_at,
            payload,
            &mut buffer,
        );
        match result {
            Ok(()) => {}
            Err(CreateError::Verification(reason)) => {
                return Ok(RecoveryOutcome::Omitted(RecoveryIssue::Payload(reason)));
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(RecoveryOutcome::Verified(RecoveredMember { framing, descriptor }))
}

fn preflight(central: crate::zip::EntryMetadata<'_>, limits: CreateLimits, usage: &VerificationUsage) -> Result<()> {
    use crate::zip::create::native::limit;
    limit(central.size(), limits.verification_entry_bytes, CreateLimit::VerificationEntryBytes)?;
    limit(
        add(usage.decoded_bytes, central.size())?,
        limits.verification_decoded_bytes,
        CreateLimit::VerificationDecodedBytes,
    )?;
    limit(
        add(usage.read_bytes, central.packed_size())?,
        limits.verification_read_bytes,
        CreateLimit::VerificationReadBytes,
    )?;
    Ok(())
}
