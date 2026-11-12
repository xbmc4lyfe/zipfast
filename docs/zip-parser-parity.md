# ZIP parser parity baseline

The fixtures in [zip_parity.rs](../tests/zip_parity.rs) exercise zipfast
`Archive`, zipview `ZipReader`, blocking `ZipIndex`, and incremental
`ZipIndexOpener` against the same bytes. They characterize the readers at
`914e005`. The proposed migration requirements below follow the
[Phase 2 plan](superpowers/plans/2026-11-11-zipview-merge-and-compatibility.md).
The table records the original observations. The current adapter results
follow it.

The [fixture builder](../tests/common/zip_parity_fixture.rs) writes small
little-endian records with explicit raw names, flags, extras and comments.
It records the local header, payload, central header and end record
positions. Most fixtures fit in a few hundred bytes. The maximum-length
archive comment fixture makes the range reader fetch the central directory
separately from the tail, and the incremental reader supplies the tail in
two parts. The range harness records the requested offset and length and
the exact bytes supplied. Selected-entry tests verify the header and
payload ranges and compare the returned bytes.

## Observed behavior and migration requirements

| Fixture | Behavior at the baseline | Required result for the shared parser and adapters |
| --- | --- | --- |
| Central order and duplicate names | All readers enumerate central order, including duplicates, even when the local headers are in a different order. zipview's exact name lookup returns the first central match. zipfast reads by central ordinal. | Retain each central record and its ordinal, preserve first-match lookup, and read the selected record's local payload. Never sort or deduplicate directory entries. |
| UTF-8, legacy names and Unicode path extras | Both accept UTF-8 with or without bit 11 and replace invalid flagged bytes. For unflagged `caf\x82.txt`, zipfast yields `café.txt` and zipview yields `caf�.txt`. zipfast uses the CRC-matching Unicode path extra and ignores the bad-CRC variant. zipview ignores both extras for names. | Retain raw bytes and the UTF-8 flag. Make CRC-gated Unicode paths and CP437 fallback available to zipfast and future callers that need them. Preserve zipview's public name projection and lookup behavior during migration. [APPNOTE §4.6.9 and Appendix D](https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.8.TXT) |
| Archive comments and end-record selection | zipview exposes lossy UTF-8. zipfast exposes no comment and prefers a candidate whose declared comment ends at EOF. With a complete-looking embedded signature and bytes after it, zipview selects the fake record and reports zero entries and an empty comment. Both accept a trailer. zipfast rejects an overlong comment declaration and zipview clamps it to the available bytes. All readers open the empty archive. | Prefer a structurally valid end record whose declared comment ends at EOF. Retain the bounded trailer fallback and preserve the comment byte range. Carry the declared and available lengths for strict and tolerant policies. [APPNOTE §4.3.16 and §§4.4.25–4.4.26](https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.8.TXT) |
| DOS, extended and NTFS timestamps | zipview exposes DOS parts, including malformed nonzero values, and treats all-zero fields as absent. zipfast interprets valid DOS parts as UTC, applies NTFS and extended mtime overrides in extra order, and includes NTFS fractional seconds. | Retain raw DOS words and extras. Preserve zipview's DOS accessor and zipfast's effective UTC timestamp, precision and override order. [APPNOTE §4.4.6 and §4.5.5](https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.8.TXT) |
| Host and external attributes | zipfast reports nonzero mode only for host 3 and uses Unix type bits, DOS directory attributes and a slash suffix. zipview reports mode for hosts 3 and 19, including zero, and uses slash or backslash suffixes. zipfast identifies the Unix symlink. | Keep made-by host and version and all external bits. Preserve each adapter's classification and keep path and symlink policy in zipfast. [APPNOTE §4.4.2 and §4.4.15](https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.8.TXT) |
| AES and encryption flags | Both retain AES strength and method for method 99. zipfast retains the vendor version, counts a valid AES extra alone as encryption, and ignores bits 6 and 13 alone. zipview flags bits 6 and 13 alone and ignores the extra alone. Both ignore strength 4. The conflicting fixture has central AE-2/AES-128/Deflate and local AE-1/AES-256/Stored. zipview lists the central values and probes the password using the local strength. | Retain local and central AES records independently, including vendor version, vendor ID, strength and method. Preserve adapter-specific encryption and password-check decisions during migration. Full AES authentication remains mandatory. Any change to the probe's metadata precedence requires a separate regression. [WinZip AES specification §§II–III](https://www.winzip.com/en/support/aes-encryption/) |
| ZIP64 and prefixed offsets | All readers resolve distinct ZIP64 packed and unpacked sizes and the stored offset on an ordinary archive. With two central records and a ZIP64 count of one, zipfast reports a count mismatch and both zipview paths list only the first record. All readers locate payloads behind the classic prefix. zipfast opens the ZIP64 archive behind the same prefix, while both zipview paths report `BadOffset`. zipfast exposes physical `local_at` and zipview exposes the stored local offset. | Resolve classic and ZIP64 offsets to checked physical positions on both paths, including prefixed ZIP64 end records. Keep the stored offset separately for existing APIs and for rewriting. [APPNOTE §§4.3.14–4.3.16 and §4.5.3](https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.8.TXT) |
| Data descriptor and conflicting local fields | All readers use the local name and extra lengths to locate the compressed payload. Central name, flags, method, sizes and CRC remain the indexed metadata. Changing the local name, flags, method, CRC and sizes leaves the selected bytes intact. The range ends before the descriptor. | Use the bounded local layout for the physical payload start and the central packed size for the span. Preserve both records and their fields. Keep data descriptors outside the payload range, and keep integrity policy with each decoder. [APPNOTE §§4.3.7–4.3.9 and §4.3.12](https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.8.TXT) |
| Bad directory count, truncated fields and split metadata | zipfast rejects low/high counts. zipview returns the declared subset or stops at the first non-central signature. All reject an overlong central name and a local extra extending beyond EOF at payload read. zipfast rejects an overlong central comment and zipview skips the declared length. With a short ZIP64 extra, zipfast rejects the entry and zipview lists it with the packed-size sentinel and rejects payload read. zipfast rejects a nonzero EOCD disk number and zipview lists the entry. | Bound all reads and record extents and distinguish complete records from unavailable fields. Preserve zipfast's strict extraction behavior and zipview's established listing recovery via explicit policy, with the same outcomes for slice and range under the same policy. Treat unfilled ZIP64 sentinels as unresolved for payload reads. Split archives remain unsupported by zipfast. [APPNOTE §§4.3.12–4.3.16 and §4.5.3](https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.8.TXT) |

## Current zipview adapter results

| Fixture or contract | Current behavior |
| --- | --- |
| Embedded EOCD signature | The slice, blocking and incremental readers prefer the structurally valid EOCD with a comment ending at EOF. Trailing and clipped comments remain supported. |
| Prefixed ZIP64 | The three zipview readers relocate the ZIP64 end record and its local offsets, including a prefixed record with extensible data. |
| Directory limits and geometry | An impossible declaration or exhausted metadata budget returns `BadOffset`. The sparse directory-size fixture and the over-limit ZIP64 count fixture stop after the tail. Within the limits, listing retains the tolerant count and clipped central-comment behavior. |
| Unresolved or split addressing | zipview lists the raw offset or sentinel. A local read requiring an unresolved or split address returns `BadOffset`. A full read requiring an unresolved packed size returns `Truncated` without fetching the payload. The bounded password preview still works when its local address is usable. |
| AES extra boundaries | The public helper and entry projection use the first bounded AES extra and ignore a short or overclaimed field. Zipview checks the local extra for a password preview and prefers central AES parameters for a full authenticated read, with a local fallback. |
| Incremental range protocol | A nonempty supply must start at the pending offset and fit within the request. Invalid supply returns `BadOffset` and leaves progress intact. A partial request and the accumulated metadata can be cloned and continued independently. A directory outside the initial tail can require separate signature and fixed-header probes before the remaining directory ranges. |

## Current zipfast adapter results

| Fixture or contract | Current behavior |
| --- | --- |
| Prefixed ZIP64 and end framing | The root reader relocates fixed and extensible ZIP64 end records. It exposes checked physical local offsets. A ZIP64 end record whose declared length fails to reach the locator is corrupt. |
| Central extras | The root reader skips an AES extra whose advertised body exceeds the central extra block. It uses the first complete AES extra and filters invalid strengths. The last CRC-matched Unicode path and the last valid NTFS or extended mtime win in wire order. |
| Directory count and disk metadata | Exact counts remain mandatory, and a noncentral trailer is accepted even for zero entries. A central signature after the declared count is corrupt, including a signature with a clipped header. The central start-disk sentinel `0xffff` retains its legacy exception. Split archive declarations remain unsupported. |
| Missing ZIP64 values | An unresolved local address is corrupt. An absent ZIP64 size extra leaves the classic sentinel visible. A present ZIP64 extra with too few required values is corrupt. |
| Source and metadata bounds | The range driver uses the open file and shared limits, including a 128 MiB directory, 1,000,000 records, a 16 MiB pending request, and 129 MiB of cumulative source bytes. Cancelable opens read and supply chunks of at most 64 KiB. The driver preserves filesystem and cancellation errors. |
| Local layout | Root extraction checks the complete fixed header before the signature and uses its variable lengths and the central packed size for the payload range. A short fixed header or an out-of-range payload returns `Truncated`. |

## Public metadata boundaries

Neither reader exposes raw entry names, raw entry comments, or unknown
extra fields. zipfast has no archive comment accessor, and zipview returns
a lossy archive comment. zipview exposes the AES strength and method but
omits the vendor version. zipfast exposes the host and all external bits,
while zipview exposes the host and version, and projects the external bits
through `unix_mode()`. zipview has no link accessor, and zipfast has no
public local payload-offset accessor. The fixtures retain the bytes and
expected positions for future direct checks of shared records.

The baseline source is available at revision `914e005` in
`src/zip.rs`, `src/crypto.rs`, and `crates/zipview/src/{lib,index}.rs`.
In the current adapter, [ZipReader](../crates/zipview/src/lib.rs) projects the
shared records and [ZipIndexOpener](../crates/zipview/src/index.rs) drives
the same parser over byte ranges. The root [Archive](../src/zip.rs) projects
central records directly into its legacy entries. The shared raw parser
continues to retain metadata and ranges used by the parity fixtures.
