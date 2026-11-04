//! zipfast: a fast, universal archive extractor.
//!
//! The first format is RAR 5.0, read from the published archive layout. Each format lives in its own module and
//! hands the extractor a stream of entries; the extractor owns paths, overwrite rules and checksums.

pub mod error;
pub mod extract;
pub mod path;
pub mod rar5;
pub mod volume;

pub use error::{Error, Result};
