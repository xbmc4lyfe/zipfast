# Seekable ZIP writer

`zipfast::zip::write::ZipWriter` writes Stored and raw Deflate members to
an owned or borrowed `Write + Seek` sink. The sink must start empty at
position zero. Add files and explicit directories in the desired order,
then call `finish` to write the directory and end records, flush, and
recover the sink and accounting summary. The API example is in
[`src/zip/write.rs`](../src/zip/write.rs).

The writer supports exact and unknown input lengths, UTF-8 and raw byte
names, member and archive comments, DOS timestamps, optional signed Unix
mtime, rwx permissions, empty entries, and ZIP64. It keeps duplicate names
in insertion order. Empty regular files use Stored. Nonempty Deflate and
unknown-length inputs use conservative ZIP64 framing; known Stored inputs
use ZIP32 below its sentinel. Equality to a size, offset or count sentinel
requires widening. Any ZIP64 end chain saturates both classic counts and
the classic directory size and offset, while disk fields stay zero.

## Failure and ownership contract

Metadata validation and reservation happen before entry admission. Those
errors leave previous entries usable. An error after admission poisons the
writer and retains its original cause. Later entries and `finish` fail
without writing more bytes. Errors identify length mismatches, component
limits, allocation, overflow, cancellation, codec progress and I/O stage.

`InputLength::Exact(n)` requires exactly `n` bytes and a further EOF probe,
even when `n` is zero. A surplus probe byte is consumed and charged before
the error. Unknown lengths run to actual EOF; a limit is never treated as
EOF. Unknown inputs reserve wide metadata before reading, which can reject
an eventual empty input under very tight limits.

Drop does not finalize or publish anything. A failure can leave a partial
stream, or even complete-looking bytes if final flush or cancellation
fails. Only successful `finish` returns `Finished`. This token means the
writer finished and flushed; it does not mean filesystem publication,
source identity verification or crash durability. A path transaction must
provide those guarantees separately.

Raw names preserve bytes, including NUL and controls. They are format
metadata, not permission to extract or publish a path. In the characterized
raw-name fixture, UnZip truncated the name at NUL and changed an undecodable
byte; 7-Zip rejected the archive. Both shared parser profiles retained the
original raw metadata. Filesystem adapters must apply their own name policy.

## Resource limits

| Component | Default ceiling |
| --- | ---: |
| Entries, including directories | 1,000,000 |
| Serialized central directory | 128 MiB |
| Combined central and archive-comment capacity | 129 MiB |
| Decoded bytes per member | 1 TiB |
| Aggregate source bytes | 2 TiB |
| Physical archive extent | 3 TiB |
| Output bytes, including backpatches | 4 TiB |
| I/O and codec attempts, including retries | 2^32 |

The writer streams through bounded buffers and reserves central storage
fallibly. These component ceilings exclude allocator overhead, codec
allocations and I/O buffers; they are not process RSS limits. Source and
output accounting retain partial work on failure. Member totals count
completed members. Cancellation is checked between calls and codec
iterations; it cannot interrupt arbitrary blocking caller I/O.

## Verification

Code `33d887323c7d8267c81a423404a107c1f4dfcaec` passed independent
specification and quality review. Native macOS validation passed 422
workspace tests and six doctests, formatting, strict Clippy and
warning-denied documentation. Three opt-in tests ran separately: an
impossible metadata reservation, reference-fixture export, and a real
streamed member above 4 GiB. The root reader, parser/view source, manifests
and lockfile were unchanged.

Independent review ran 23 integration and five unit tests, 640 public-API
round trips with Stored and Deflate levels 1/6/9, and 103 sink failure
controls with seven-byte short writes. It checked no further sink calls
after poison and cancellation triggered inside final flush. Both miniz
and the workspace's zlib-rs feature selection were exercised.

Pinned UnZip 6.0 and 7-Zip tested, listed, streamed and extracted the three
small forced-ZIP64 fixtures and the metadata fixture. The large fixture
contained a 4,294,971,392-byte Stored member followed by an entry requiring
an offset-only ZIP64 extra. Both tools and the root reader compared every
payload byte and verified integrity. Tests also cover real entry counts
of 65,534, 65,535 and 65,536, synthetic size/offset boundaries, short and
interrupted writes, exact-size errors, backpatch failures and finalization.
UnZip's warning for a valid empty archive is recorded as expected behavior.

On Apple ARM64 with Rust 1.99.1, the optimized large test process took
2.79 seconds with 3,473,408 bytes peak RSS. A separate isolated miniz
consumer wrote and decoded 1 GiB of Deflate data plus two smaller members
in 1.46 seconds with 4,276,224 bytes peak RSS. The count-boundary process
peaked at 36,110,336 bytes, including its in-memory ZIP and reader index.
These are fixture-specific process observations, not general throughput
or memory guarantees.

The opt-in checks are reproducible with:

```sh
cargo test --locked --lib metadata_allocation_failure_leaves_writer_usable -- --ignored
cargo test --locked --release --test zip_write write_reference_fixtures -- --ignored
cargo test --locked --release --test zip_write streamed_member_crosses_four_gib_and_next_entry_has_offset_only_zip64 -- --ignored
```

Set `ZIPFAST_WRITER_REFERENCE_DIR` to an existing scratch directory to
retain generated ZIPs for external readers. The large check needs disk
space for its archive; full independent extraction needs space for another
large member. Reference source pins and the Linux build are recorded in
[the workspace verification](zipview-workspace.md) and
[Prybar's checked reference builder](https://github.com/xbmc4lyfe/prybar/blob/ab44daa52e1065d81a77fc171703d343606baf92/scripts/build-compatibility-references.sh).

## Forward-only ZIP writer

Use [ZipStreamWriter](../src/zip/write/stream.rs) for an owned or borrowed
sink that implements only Write, such as a pipe or a file opened for
sequential output. Construction validates options without calling the
sink. The caller supplies a fresh logical stream at offset zero. For a
file, truncate it and position it at zero before passing it to the
writer. All recorded offsets and the reported extent are relative to the
first byte emitted by the writer.

The forward writer uses the same metadata, input-length rules and resource
limits. Nonempty files set general-purpose bit 3 and put a signed data
descriptor immediately after the packed payload. The descriptor contains
the CRC32 and final sizes. Known Stored lengths below the ZIP32 size
sentinel use a 16-byte descriptor. Unknown Stored lengths, larger Stored
lengths and nonempty Deflate use ZIP64 local size placeholders and a
24-byte descriptor. A ZIP64 local-header offset alone keeps the 16-byte
descriptor for an otherwise narrow member. Empty files and explicit
directories use Stored with no descriptor. Unknown inputs reserve the
prospective wide header, descriptor and tail before the first read, even
when they turn out empty.

The physical extent and cumulative output counters include descriptors
and are equal for a forward stream. The packed byte count excludes
descriptors. A member contributes to the central directory after its
descriptor and the following cancellation check succeed.

Preflight failures leave earlier members usable. An admitted failure,
including an error on the first read, poisons the writer. Already accepted
bytes remain on the sink. Use a borrowed sink to retain access after an
error, for example to discard an incomplete file. Dropping the writer
performs no ZIP finalization. Call finish to write the central directory,
end records and archive comment. It returns Finished after the sink
flushes and cancellation is checked again. A transport may have accepted
bytes before a late failure, so use the successful result to determine
whether the archive was finalized.

### Traditional ZIP encryption

Use `ZipStreamWriter::add_zipcrypto_file` for legacy ZipCrypto
interoperability. ZipCrypto does not authenticate member data. The caller
supplies a borrowed UTF-8 password with no NUL bytes and fills eleven
header bytes with fresh operating-system cryptographic randomness for
each member. The call retains neither the password nor cipher state.
The entropy callback runs once after preflight and before source or sink
I/O. Entropy failure leaves the writer reusable and charges one attempt.

Encrypted files use the DOS time password-check byte and a signed data
descriptor. Empty encrypted files use Stored and still carry both the
encryption header and descriptor. The 12-byte encryption header counts
toward the packed size and can force ZIP64 framing for exact-length
Stored data. The descriptor counts toward physical extent and output
bytes. After admission, a source or sink failure poisons the writer.

## Split volumes

`ZipSplitWriter` writes clear Stored and Deflate members through
`write::split::VolumeProvider`. Set the per-volume capacity, volume-count
ceiling and physical attempt ceiling in `write::split::Options`. The
ordinary `WriterOptions` supplies source, encoding, metadata and byte
limits. Each provider call opens a fresh numbered sink after its predecessor
has been flushed and dropped. Provider calls, physical writes and flushes
consume the transport attempt allowance. Source reads, encoder steps and
logical payload writes consume the ordinary writer attempt allowance.

A split receipt uses a `Location` with a zero-based disk and relative byte
offset. `Finished` reports the central start in the same coordinates and
cumulative actual output bytes. Unused disk capacity contributes no bytes.
Local headers, signed descriptors, central records and the final end group
remain intact. The last central record shares a disk with the end group
when both fit together. Each record and the end group must fit individually.
A separate final disk can contain only the end group and archive comment.
The first disk begins with the spanning marker, including one-disk output.

The sinks hold provisional bytes until `finish` succeeds. A failure after
member admission or rotation preserves the first error and prevents further
members or successful finalization. Inspect the failure's disk, offset,
transport usage and writer usage. The caller owns sink storage, naming,
cleanup and publication.

Pinned 7-Zip verifies split Stored and Deflate payloads spanning three disks.
Pinned Info-ZIP joins the qualified one- and two-disk cases, central-directory
rollover and ZIP64 end-only output. Its join can truncate a member after an
exactly full intermediate volume, including archives that Info-ZIP itself
created. A classic end-only disk also has a join refusal. A classic end-only
disk with a large archive comment can be rejected by pinned 7-Zip. The split
fixture parser checks the encoded ranges independently of these readers.
