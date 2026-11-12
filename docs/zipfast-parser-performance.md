# Zipfast shared parser verification

At `38ab6f23d1f7ff8de7026d541ca15dea37f90c93`, root `Archive::open`
uses the shared Zipfast profile and the optimized root CRC callback. It
projects borrowed records directly into legacy entries. The public vector,
fields, ordinal reads, streaming codecs and payload verification remain.
The normal source buffer follows bounded parser requests up to 16 MiB;
cancelable opens supply at most 64 KiB between cancellation checks.

## Compatibility and verification

The parity suite passed 28 cases. Newly accepted prefixed extensible ZIP64
and tightened malformed end, AES and excess-count cases have baseline
regressions. Missing-size sentinels, root disk-start exceptions, timestamp
order, CP437/Unicode names, invalid AES strength and error precedence retain
the documented policies. Malformed ZIP64 end and extra errors now share the
`Corrupt("ZIP64 metadata")` diagnostic.

The committed revision passed 326 distinct workspace tests and five
doctests, or 351 test instances including the writer example's duplicate
cases. Formatting, strict Clippy, documentation, Rust 1.87 parser/view tests,
all 11 fuzz seeds and separate dependency graph checks passed. A clean Git
consumer checked legacy fields and selected reads. A locked Git CLI install
listed, tested and extracted a fixture with byte comparison. Neither the
shared parser nor zipview source changed in this adapter.

## Measurements

Original `8e835ae`, Phase 1 `914e005` and the candidate used independent
release consumers with matched flate2 1.1.10/miniz_oxide 0.9.1 and other
codec versions, fat LTO, one codegen unit, and abort on panic. The host was
Apple M4, macOS 27.3 and Rust 1.99.1. Five paired trials per condition
alternated execution order. Values below are file-primed medians; OS caches
were not evicted. Ranges and raw records remain in the benchmark artifacts.

| Fixture | Phase 1 open, ms | Candidate open, ms | Phase 1 peak allocation, MiB | Candidate peak allocation, MiB |
| --- | ---: | ---: | ---: | ---: |
| Short 20k | 0.619 | 0.945 | 3.11 | 3.05 |
| Rich prefixed 20k | 1.832 | 2.654 | 17.15 | 17.09 |
| Short 200k | 5.355 | 8.849 | 30.58 | 30.52 |
| Rich 200k | 20.137 | 21.694 | 170.96 | 73.47 |
| Unicode 200k | 37.942 | 28.224 | 146.17 | 73.47 |

Retained allocations match the legacy projection. Rich-directory process
RSS falls from 176.63 to 80.81 MiB. Bounded input replaces the legacy whole
central-directory allocation, which accounts for the large peak reduction.
Short-directory opening remains 65% slower. Rich opening is 8% slower with
overlapping trial ranges, and Unicode opening takes 26% less time. These
measurements do not isolate each CPU cost in shared walking and projection.
The related [zipview investigation](zipview-parser-performance.md) describes
that path's profiling and remaining tradeoffs.

All 352 timed/allocation invocations and 27 smoke checks passed. The checker
verified every fixture entry's name, physical offset, method, size, flags
and CRC. All three revisions extracted the 257 MiB Deflate member with
SHA-256 `20ea1ca75dca0e865024823841be6e60bced0ae46e003cf53b025ef0024657ab`.
Selected reads verified distinct duplicate ordinals and tiny members beside
large unrelated data.

Highly compressible Deflate streaming with full size/CRC verification took
5,045 versus 5,103 MiB/s, within the paired spread. Peak Rust allocations
were 2,140,666 bytes in each revision. A batch of tiny selected reads added
about 0.66 to 0.72 microseconds per read, including filesystem calls and
checked local layout. This measures legacy `Archive`, not the future
immutable session API. The timed throughput sink discarded verified bytes;
actual filesystem extraction was separately checked once per revision.

The adapter accepts these measured metadata costs while retaining bounded
memory and streaming throughput. Historical builds and downstream pins
remain available. Immutable sessions and final caller measurements have
separate gates; this result does not complete Phase 2.
