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

#[cfg(unix)]
#[allow(dead_code)] // One shared first-party fixture also models metadata forms used by other suites.
#[path = "../../../../tests/common/zip_parity_fixture.rs"]
mod fixture;

mod core;

#[cfg(unix)]
mod cipher;
#[cfg(unix)]
mod spool;

#[cfg(unix)]
mod codecs;

#[cfg(unix)]
mod projected;

#[cfg(unix)]
mod output;

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod policy;

#[cfg(target_os = "macos")]
mod qualified;
