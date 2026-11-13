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

use super::*;
use crate::zip::{Metadata, create::CreateError, rewrite::RewriteError};
use std::{fs::File, path::Path, sync::Arc};

/// Recovery is available only on qualified Linux and macOS filesystems.
pub struct RecoveryPlan {
    unavailable: std::convert::Infallible,
}
impl RecoveryPlan {
    pub fn open(_: &Path, _: &Path, _: RecoveryOptions) -> Result<Self, RewriteError> {
        Err(CreateError::UnsupportedPlatform.into())
    }
    pub fn open_with_output_file(_: &Path, _: &Path, _: RecoveryOptions, _: &File) -> Result<Self, RewriteError> {
        Err(CreateError::UnsupportedPlatform.into())
    }
    pub fn check_output_file(&self, _: &File) -> Result<(), RewriteError> {
        match self.unavailable {}
    }
    pub fn metadata(&self) -> Arc<Metadata> {
        match self.unavailable {}
    }
    pub fn usage(&self) -> RewriteUsage {
        match self.unavailable {}
    }
    pub fn recover(self) -> RecoveryReport {
        match self.unavailable {}
    }
}
