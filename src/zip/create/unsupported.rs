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

use std::convert::Infallible;
use std::fs::File;
use std::path::Path;

use crate::zip::write::EntryOptions;

use super::*;

/// A bounded ordered plan. Native creation is unavailable on this platform.
pub struct CreatePlan(Infallible);

impl CreatePlan {
    /// Returns UnsupportedPlatform before opening a file.
    pub fn new(_destination: &Path, _options: CreateOptions) -> Result<Self> {
        Err(CreateError::UnsupportedPlatform)
    }

    /// Admit a regular path source.
    pub fn add_file(
        &mut self,
        _source: &Path,
        _metadata: EntryOptions<'_>,
        _keys: Option<&CollisionPath>,
    ) -> Result<CreateEntryId> {
        match self.0 {}
    }

    /// Admit and retain a supplied regular file bound to the named path.
    pub fn add_open_file(
        &mut self,
        _source: &Path,
        _file: File,
        _metadata: EntryOptions<'_>,
        _keys: Option<&CollisionPath>,
    ) -> Result<CreateEntryId> {
        match self.0 {}
    }

    /// Admit an explicit metadata-only Stored directory.
    pub fn add_directory(
        &mut self,
        _metadata: EntryOptions<'_>,
        _keys: Option<&CollisionPath>,
    ) -> Result<CreateEntryId> {
        match self.0 {}
    }

    pub fn add_directory_from_path(
        &mut self,
        _: &Path,
        _: EntryOptions<'_>,
        _: Option<&CollisionPath>,
    ) -> Result<CreateEntryId> {
        match self.0 {}
    }

    pub fn add_open_directory(
        &mut self,
        _: &Path,
        _: File,
        _: EntryOptions<'_>,
        _: Option<&CollisionPath>,
    ) -> Result<CreateEntryId> {
        match self.0 {}
    }

    /// Return component accounting.
    pub fn usage(&self) -> CreateUsage {
        match self.0 {}
    }

    /// Write, verify, and publish a new archive.
    #[allow(clippy::result_large_err, reason = "creation failures retain component usage and outcome inline")]
    pub fn publish(self) -> std::result::Result<CreatedArchive, CreateFailure> {
        match self.0 {}
    }

    /// Publishes with write receipts on supported platforms.
    pub fn publish_with_receipts(self) -> CreateReport {
        match self.0 {}
    }
}
