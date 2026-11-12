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

These costs are accepted for the additive engine API. The full Prybar
inspect/explorer comparison must include its previous two-reader path;
this engine result alone does not establish a caller improvement or complete
Phase 2. Historical implementations and downstream pins remain available.

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
