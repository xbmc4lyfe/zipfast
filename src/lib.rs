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

//! zipfast: a fast, universal archive extractor.
//!
//! RAR 5.0, ZIP, tar and gzip/xz/zstd/bzip2 streams are read from their published layouts. Each format lives in its own module and
//! hands the extractor a stream of entries; the extractor owns paths, overwrite rules and checksums.

#[cfg(test)]
mod test_alloc;

mod batch;
pub mod blake2sp;
pub mod crc32;
pub mod crypto;
pub mod error;
pub mod extract;
mod output;
pub mod path;
pub mod rar5;
pub mod stream;
pub mod tar;
pub mod volume;
pub mod zip;

pub use error::{Error, Result};

mod cli;

#[doc(hidden)]
pub fn cli_main() -> std::process::ExitCode {
    cli::main()
}
