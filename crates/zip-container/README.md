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

`parse_slice` and `DirectoryParser` continue discovery into a single streaming
central-directory walk. Complete records borrow the incoming window. A split
record retains only its incomplete fixed fields or body, bounded by the ZIP
record lengths. The parser reuses the discovered tail and first fixed header.
The result owns raw central names and comments, known-extra summaries, the
raw archive comment, and absolute source ranges for the original records.
`usage` includes discovery, and `buffer_usage` reports parser scratch separately
from owned records and the caller's read buffer.

Use `parse_slice_projected` or `DirectoryParser::with_projection` to own a
different output record. The projection receives a fully checked borrowed
record with its resolved fields and selected known extras. It returns an owned
value and should report allocation failure and avoid external side effects.
Entries become available through the completed directory.

The same raw name, selected known-extra, and available comment bytes count
against the metadata and work budgets for either output. In projected mode,
`usage.owned` reports those raw admission charges. The entry limit bounds the
number of values in the output vector. The projection controls each value's
representation and its own variable allocation and work. Cloning a parser
copies its progress and buffers and clones each projected value.

The Zipfast profile requires the declared count and rejects another central
signature immediately after the counted records. It permits noncentral
directory trailers and requires complete record bodies. The Zipview profile
can stop at a noncentral signature, traverse an undersold directory, or retain
a clipped comment within configured limits. It preserves raw extra ranges and
skips the Unicode Path projection used by Zipfast. Zipfast computes IEEE
CRC-32 once per eligible raw name and accepts an optional function pointer
for callers with an existing implementation.

Range supplies must start at the first byte of the current request and may
cover any contiguous prefix. Polling an unchanged request consumes no work.
A bad caller supply leaves progress intact. Drop the parser between requests
to cancel. The directory walk does not read local headers or payloads. Its
physical local-header offset accessor checks start addresses. A later reader
must validate the header and payload extents before access.
