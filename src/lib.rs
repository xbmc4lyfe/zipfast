//! zipfast: a fast, universal archive extractor.
//!
//! RAR 5.0, ZIP, tar and gzip/xz/zstd/bzip2 streams are read from their published layouts. Each format lives in its own module and
//! hands the extractor a stream of entries; the extractor owns paths, overwrite rules and checksums.

mod batch;
pub mod blake2sp;
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
