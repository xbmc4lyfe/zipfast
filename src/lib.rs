//! zipfast: a fast, universal archive extractor.
//!
//! RAR 5.0 and ZIP are read from their published layouts. Each format lives in its own module and
//! hands the extractor a stream of entries; the extractor owns paths, overwrite rules and checksums.

pub mod blake2sp;
pub mod error;
pub mod extract;
pub mod path;
pub mod rar5;
pub mod volume;
pub mod zip;

pub use error::{Error, Result};
