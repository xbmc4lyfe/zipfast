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

use std::{fs::File, path::Path, sync::Arc};

use crate::zip::create::CollisionPath;
use crate::zip::write::EntryOptions;
use crate::zip::{EntryId, Metadata};

use super::*;

/// Rewrite planning is available on qualified Linux and macOS filesystems.
pub struct RewritePlan {
    unavailable: std::convert::Infallible,
}

impl RewritePlan {
    /// Returns the unsupported platform error.
    pub fn open(_: &Path, _: RewriteOptions) -> Result<Self, RewriteError> {
        Err(CreateError::UnsupportedPlatform.into())
    }

    pub fn metadata(&self) -> Arc<Metadata> {
        match self.unavailable {}
    }
    pub fn add_file(
        &mut self,
        _: Placement,
        _: &Path,
        _: EntryOptions<'_>,
        _: Option<&CollisionPath>,
    ) -> Result<(), RewriteError> {
        match self.unavailable {}
    }
    pub fn add_open_file(
        &mut self,
        _: Placement,
        _: &Path,
        _: File,
        _: EntryOptions<'_>,
        _: Option<&CollisionPath>,
    ) -> Result<(), RewriteError> {
        match self.unavailable {}
    }
    pub fn add_directory(
        &mut self,
        _: Placement,
        _: EntryOptions<'_>,
        _: Option<&CollisionPath>,
    ) -> Result<(), RewriteError> {
        match self.unavailable {}
    }
    pub fn remove(&mut self, _: &EntryId) -> Result<(), RewriteError> {
        match self.unavailable {}
    }
    pub fn usage(&self) -> RewriteUsage {
        match self.unavailable {}
    }
    pub fn publish(self) -> Result<RewriteOutcome, RewriteFailure> {
        match self.unavailable {}
    }
    /// Publishes with write receipts on supported platforms.
    pub fn publish_with_receipts(self) -> RewriteReport {
        match self.unavailable {}
    }
}
