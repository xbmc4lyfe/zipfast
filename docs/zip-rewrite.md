# Staged ZIP rewriting

`zipfast::zip::rewrite::RewritePlan` edits an existing ZIP in place by
publishing a new inode. For a new destination, use [ZIP creation](zip-creation.md).
Select `Replacement::LastWriterWins` when constructing `RewriteOptions`.
The final regular archive is opened without following a final-component
symlink. The plan holds that file and its parent directory through publication.

Use `metadata()` to select a source occurrence by `EntryId`. IDs belong
to one opened plan, and an occurrence accepts one replacement or removal.
Replacements keep the original encoded name and UTF-8 flag. The caller
supplies the new contents, method, timestamps, permissions and comment.
Appends follow admission order after the original central slots. The output
local records follow the resulting central order. Untouched duplicates,
raw names, comments, attributes and well-framed unknown member extras are
preserved. The collision policy checks introduced raw-name conflicts.
Caller keys are applied only to the new and replacement entries that
supply them.

By default, `RewritePlan::open` selects the last valid central modification
time from an extended Unix timestamp or an NTFS timestamp in wire order.
Call `RewritePlan::open_with_central_ut` to compare freshness using only
central extended Unix timestamps. In this mode, `raw_mtime_override()`
returns the modification time from the last complete central UT field
when it contains a usable value. An extra that overruns the block ends
the scan before that field. `modified()` uses the selected UT value or
interprets the DOS fields as UTC. Use `header()` for raw DOS fields
when applying a local time zone. This option only affects the plan's
source metadata projection.

`publish()` first validates the complete source layout, including records
that will be removed. The source must have contiguous disjoint local spans,
a contiguous complete directory and a single supported end chain at EOF.
Both ordinary reader profiles must agree. A second valid anchored end in
the standard EOF tail is an ambiguity. The bounded layout pass checks
local/central metadata, ZIP64 field selection, and a unique data descriptor
at the declared payload boundary. Split archives, unowned interior gaps,
masked or strongly encrypted directories, patching, recognized alignment
extras, directory signatures and unknown ZIP64 end extensions are refused.

An admitted opaque prefix is copied exactly and counted separately.
Recognizable leading archive-extra or orphan local structures are refused.
The rewrite assigns physical output offsets including the prefix.
Application behavior of a relocated executable stub and vendor-specific
semantics of unknown extras are outside the preservation guarantee.

Retained local records, packed payloads, descriptors and central records
are copied in bounded chunks. The only modified retained bytes are central
local-offset fields and the required ZIP64 offset insertion and version
fields. A previous ZIP64 offset remains wide. The output directory and
end records are rebuilt, and the raw archive comment is preserved.
Data-dependent compressed sizes can move later records across the ZIP64
threshold. The writer checks actual relocation and available extra-field
space before admitting each retained record.

The stage verifier rereads the held stage. It checks the output layout,
compares all retained bytes with the held source except the precise
relocation patches, and verifies new Stored and raw Deflate payloads.
`PreserveAndVerifyNew` reports untouched payloads as structural-only.
`Full` additionally checks all retained unencrypted Stored and raw Deflate
payloads with exact framing, lengths and CRC. Unknown codecs and understood
traditional or WinZip AES framing can be retained structurally. Requesting
`Full` with a retained encrypted or otherwise unqualified member fails
before staging. Empty retained directories get a separate structural
verification outcome.

A plan without edits still validates the layout and performs the requested
payload verification on the original inode. It returns `Unchanged`
without creating a stage or changing the inode, mtime or mode.
An explicit replacement always runs even if the caller supplies equal bytes.

Use qualified local APFS on macOS or ext-family/tmpfs on Linux. The parent
and new source namespaces must be under caller control. After verification,
the engine applies ordinary rwx bits to the stage, using the original
archive's rwx bits by default. The replacement does not transfer the old
owner, ACLs, extended attributes or special mode bits. Open readers and
hard links to the old inode continue to see the old archive.

Publication is one same-directory native rename. The final identity
checks catch observed source changes. A competing rename after the last
check can be overwritten. The operation has no compare-and-swap semantics.
Definite failures before commit leave the destination as observed by
external writers and clean only an owned stage. Uncertain rename results
retain recovery information and may leave an owned stage for inspection.
After a successful rename, cleanup, cancellation and directory-sync errors
retain the `Published` outcome and the verified archive. Requested file
and directory synchronization uses the existing counted `fsync` contract.

The source directory, parser scratch, raw metadata, canonical projection,
plan, layout reads, raw copy, retained comparison, stage verification and
decoded verification each have bounded accounting. Ordinary source paths
are opened individually for streaming. Explicit caller files consume the
retained-handle budget. These component limits are independent of the
process's peak resident memory.
