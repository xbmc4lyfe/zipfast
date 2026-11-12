# ZIP metadata and selected read sessions

`zip::ReadSession::open` retains one regular file and parses its central
directory once. `metadata()` returns an immutable shared snapshot.
`metadata.entry_id(ordinal)` creates an opaque ID for that exact record,
including duplicates. `session.select(&id, limit, cancellation)` rejects
foreign IDs before source I/O and returns a selected entry with staging
metadata and a consuming `read(password, sink)` method.

The snapshot retains raw names, comments, fixed fields, selected extras,
source ranges and archive geometry separately from root display policy.
Raw and physical offsets have distinct accessors. Directory CRC remains
available even though the legacy listing omits it. Metadata may outlive the
reader; it then describes the version opened, not current path contents.
The old public `Archive.entries` vector cannot alter session records or IDs.

## Source checks and output

The first implementation supports Unix, verified on macOS and Linux.
Other platforms return `UnsupportedIdentity` before opening or publishing
metadata. Legacy archive APIs remain available. The Unix stamp includes
file type, device, inode, length, and nanosecond modification and change
times. Handle/path/handle checks bracket parsing, selection and decoding.
The original absolute path spelling retains symlink components. A FIFO
cannot block regular-file validation.

Detected replacement, modification, disappearance or unverifiable metadata
invalidates the session permanently. Source errors retain an original
parse, decoder or sink error as context. Cancellation, a wrong password or
an integrity error does not invalidate an unchanged source.

Every sink byte is provisional until full payload verification, final
source checks and cancellation checks succeed. The caller must stage output
and publish after success. These are optimistic change checks, not an
immutable filesystem snapshot: timestamp precision, changes restored between
observations, and changes after the final check remain limitations.

Shared parser limits apply, including 128 MiB of directory bytes, one million
entries and 129 MiB of fetched metadata. Additional decoded-name storage has
a separate 128 MiB cap. Fixed records, conversion buffers and allocator
storage also contribute to RSS. Packed and decoded selection limits are
independent; root streaming retains no 256 MiB inflation cap.

## Verification and measured costs

Code `2584c569709ef56f1c7310cbc2034a3cd4307348` passed independent spec
and quality review. All 32 session regressions passed on macOS and Linux,
including same-length writes with restored mtime, path and symlink replacement,
sticky invalidation, FIFO refusal, cancellation, AES/CRC failures and
provisional output. Linux used container-native temporary storage. Local
workspace validation passed 383 all-target test instances and five doctests,
strict Clippy, and Rust 1.87 checks for the unchanged parser/view packages.
Exact Git consumers verified both legacy and new public APIs. Non-Unix
execution was not verified.

Public benchmarks used matched release settings and codec versions on
Apple M4/macOS 27.3 with Rust 1.99.1. Five rotating trials covered both
fresh-process cache-uncontrolled and file-primed conditions; caches were
not evicted. All 306 benchmark invocations and 28 smoke checks passed across
nine fixtures. Each metadata field was compared with independently checked
wire values. A selected 257 MiB stream reproduced the expected SHA-256.

| 200,000-entry fixture | Same-commit Archive open, ms | Session open, ms | Session retained / peak allocation, MiB |
| --- | ---: | ---: | ---: |
| Short names | 9.544 | 15.874 | 44.44 / 78.01 |
| Rich metadata | 21.100 | 29.166 | 110.05 / 143.62 |
| Unicode extras | 23.409 | 31.729 | 120.93 / 154.50 |
| Invalid UTF-8 names | 187.457 | 198.631 | 199.13 / 232.70 |

The rich fixture retains 70,599,334 name/comment bytes and a 224-byte
canonical record per entry. Valid display names reuse raw storage; invalid
names retain both raw bytes and decoded strings. During conversion, the
176-byte raw record slab temporarily coexists with canonical records,
adding about 33.57 MiB for 200,000 entries. This is measured overhead,
not required retained metadata. Legacy Archive keeps fewer fields and has
lower retained memory. Linear scans of wider session records are slower;
ID lookup does not scan names.

Calibrated I/O traces on both large fixtures recorded one open and 65,633
metadata bytes. Each later tiny selection read exactly 30 header bytes and
four payload bytes, with no reopen or unrelated payload scan. Each selection
also made three handle/path/handle checks. This added about 3.3 microseconds
per selection versus same-commit Archive; one standalone check took about
1.1 to 1.2 microseconds. The traces were separate from timed runs.

These costs are accepted for the additive engine API. The separate Prybar comparison below includes its previous two-reader path.
This engine result alone does not establish a caller improvement. Historical
implementations and downstream source snapshots remain available.

## Format-aware inspection

`extract::inspect`, `inspect_with_password` and `inspect_cancelable` return
`Inspection::Zip(ReadSession)` or `Inspection::Other(Vec<Entry>)`. This lets
callers use the snapshot for ZIP and retain their existing non-ZIP listing
path. The password parameter applies to encrypted RAR headers.

At code revision `d9a7b32c314d1bab9b5129f56faba79738745a7d`, dispatch
captures its candidate source baseline before reading the first header.
Ordinary and self-extracting ZIP use that same handle and baseline for the
session. ZIP and TAR/codec headers retain priority. Unknown headers undergo
the existing bounded RAR signature search before ZIP fallback. Once RAR is
recognized, later errors are terminal. This intentionally differs from
legacy listing, which can fall back to a ZIP tail after a later RAR volume
reports `NotAnArchive`. Legacy listing itself is unchanged.

`session.dispatch_bytes()` reports the actual probe charge separately from
`metadata.parser_usage().fetched_bytes`. Both count toward the same 129 MiB
ceiling, including overlapping reads. The exact boundary and one additional
byte were tested. Direct session opening has zero dispatch charge and keeps
its existing full parser budget. Non-ZIP listing errors remain unchanged;
cancellation during those legacy calls is observed on successful return.

Independent review approved the change and reran 134 distinct tests. Local
validation passed 394 all-target test instances, five doctests, strict Clippy,
Rust 1.87 parser/view tests and exact Git consumers. Calibrated traces showed
one open for ordinary ZIP (1,024 probe plus 65,633 parser bytes) and one for
self-extracting ZIP (1,049,608 probe plus 65,633 parser bytes). Genuine RAR
still uses its existing listing reader. These trace results do not replace
the separate caller performance comparison.


## Prybar caller comparison

Prybar code `b3462ee10739d3077532f2e9b5d8ed9e4d58be8e` uses the
inspection API at engine `d9a7b32c314d1bab9b5129f56faba79738745a7d`.
It retains one reader and one immutable snapshot for the explorer. Rows
supply the original ordinal's entry ID; rendering does not lock the reader.
Detected source changes clear the preview and disable new jobs until reopen.
Non-ZIP paths keep their existing selected readers and source guards.

The actual CLI and PTY comparison used baseline Prybar
`d3b8aa32a7c7214919b9c973588a9aa97a6a0e88`, matched default Cargo
release profiles, flate2 1.1.11 and zlib-rs 0.6.8 with runtime detection.
All 500 timed invocations and 144 correctness and instrumentation cases
passed on Apple M4, macOS 27.3 and Rust 1.99.1. These caller builds used
Prybar's release profile, separate from the engine benchmark profile.
Five paired trials per operation and cache condition alternated order.
Caches were not evicted; the table shows file-primed medians.

| Caller operation | Baseline | Candidate |
| --- | ---: | ---: |
| Rich 200k archive inspect | 70.50 ms | 46.25 ms |
| Rich 200k explorer open | 64.63 ms | 51.74 ms |
| Unicode 200k archive inspect | 76.68 ms | 47.27 ms |
| Short 200k archive inspect | 24.19 ms | 27.04 ms |
| Rich 200k browse through extraction: opens | 7 | 1 |
| Rich 200k browse through extraction: bytes read | 476,261,347 | 119,000,136 |
| Rich 200k browse through extraction: peak Rust allocation | 289.37 MiB | 143.63 MiB |
| Rich 200k browse through extraction: peak process RSS | 317.09 MiB | 155.36 MiB |

The short-name fixture remains 12% slower, and its peak Rust allocation
rises from 53.82 to 78.01 MiB. Retained raw metadata and the temporary
record conversion remain costs of the session API. Rich inspection makes
more small reads because cancellation is checked between 64 KiB chunks,
but reads half as many source bytes. Each tiny preview or extraction then
adds only two reads and 36 bytes, without reopening the archive.

Preview and extraction UI completion stayed around 43–47 ms. These times
include the UI's 40 ms worker poll and do not isolate worker latency.
Independent review approved the caller and repeated its 61 tests and PTY
checks, including duplicate payloads, corruption beyond the preview prefix,
replacement, restored-mtime edits, compressed TAR and terminal restoration.
The [Prybar benchmark report](https://github.com/xbmc4lyfe/prybar/blob/5effb7df70e1e8beb93ac5b753bfdfca78289620/docs/zip-session-benchmark.md)
records every fixture, reproduction commands, cache conditions, raw evidence
locations and remaining performance tradeoffs.


The exact caller commit also passed Linux ARM64 formatting, strict Clippy,
all 61 tests, strict documentation, the release-fixture smoke test, the
expanded PTY script, Google Vale, and the existing pinned archive, gzip and
PAR2 differential suite. Cargo-audit 0.23.0 found no advisories among 155
lockfile dependencies using RustSec revision
`fd6f39814c4d3c359fdbe223d0280dec4933f78f`. The lockfile stayed unchanged.
Engine PRs 45–59 merged before the caller PR; all five hosted engine checks
passed on merged main `6d3dfcde42cec8123ad03806dc930bb562f4a369`.
[Prybar PR 4](https://github.com/xbmc4lyfe/prybar/pull/4) stacks on its
existing compatibility branch and carries the caller's separate hosted
checks. These results complete the Phase 2 implementation acceptance;
combined-distribution licensing still gates a binary release.
