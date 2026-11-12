# zip-container

Checked ZIP record primitives for byte slices and bounded input windows.
The crate exposes fixed central and local headers, absolute source ranges,
ordered borrowed extras, and bounded ownership of selected central metadata.
Callers supply the input and decide how to handle incomplete comments and
malformed extras. They also select ZIP64 values and known extras, decode names,
and interpret timestamps.

`discover_slice` and `EndDiscovery` locate the directory from classic and
ZIP64 end records using bounded slice or caller-supplied range input. They
retain the raw archive comment, source ranges, and the declared and physical
directory positions. The discovery result carries cumulative usage for
continued parsing.

The minimum supported Rust version is 1.87. The crate has zero third-party
dependencies.

The fixed header, layout, extra framing, and ZIP64 and AES field handling
draw on the zipview slice and range readers in this repository. The
Unicode Path and timestamp layouts follow zipfast's extra handling. This
extraction and its tests were developed with AI assistance.

Licensed under the Reciprocal Public License 1.5. Both project attribution
notices appear in [LICENSE](LICENSE).
