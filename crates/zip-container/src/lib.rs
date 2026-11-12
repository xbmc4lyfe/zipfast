// zip-container -- checked ZIP metadata primitives
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

//! Checked ZIP record metadata for callers working with slices or byte windows.
//!
//! Headers and extra-field views expose wire values. Callers choose how to
//! interpret them and which known extras to project into an owned record.
//! Source ranges are absolute half-open byte ranges.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod discovery;
mod error;
mod extras;
mod header;
mod owned;

pub use discovery::{
    BufferUsage, Directory, DirectoryDeclaration, DirectoryError, DirectoryLocation, DirectoryParser, EndDiscovery,
    EndRecord, LimitKind, Limits, Profile, SupplyError, Usage, Zip64End, Zip64Locator, discover_slice, parse_slice,
};
pub use error::{OwnershipError, OwnershipKind, ParseError};
pub use extras::{
    AesFields, AesView, ExtendedMtimeView, Extra, ExtraIter, NtfsMtimeView, UnicodePathView, Zip64FieldIter,
    Zip64Fields, Zip64Value, Zip64View,
};
pub use header::{
    CENTRAL_HEADER_LEN, CentralHeader, CentralLocation, CentralView, LOCAL_HEADER_LEN, LocalHeader, LocalLayout,
    central_layout, local_layout,
};
pub use owned::{
    CentralRecord, ExtraMtime, KnownExtras, KnownExtrasView, OwnershipBudget, OwnershipUsage, ResolvedFields,
};

#[cfg(test)]
mod tests;
