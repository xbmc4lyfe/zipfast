# Verified ZIP creation

Use `zipfast::zip::create::CreatePlan` to publish a new ZIP at a filesystem
path. The destination parent must exist. Add regular files and explicit
directories in archive order, then call `publish`. An empty plan publishes
an empty ZIP. See the [API example](../src/zip/create.rs).

The plan copies member names, comments, and any collision keys. The caller
chooses archive timestamps and permissions. The plan freezes absolute
source and destination spellings and holds the real destination parent
directory open. Dropping a plan before publication closes its handles
without creating a file.

## Sources and names

`add_file` opens a regular file without following a leaf symlink, captures
its identity, size, modification time, and change time, then closes the
handle. Publication reopens each path in turn and requires the original
stamp. It reads exactly the captured length and probes for EOF through
that handle. It checks the handle and path before and after reading, and
rechecks the path immediately before publication.

`add_open_file` retains the supplied handle under a separate limit and
also checks the named path. Positioned reads from byte zero protect the
stream from cursor changes through duplicate handles. A path source uses
one transient descriptor even in a large plan. Distinct archive names
can refer to the same source inode.

Path sources give up continuous inode ownership between checks. Stamps
detect observed changes and can miss inode reuse, indistinguishable
changes, or writes after the final check. Held handles pin the inode.
External exclusion or immutable inputs are required for a snapshot.
Sources may acquire a new access time when read. Creation never writes
or removes source data.

Member names are relative slash-separated paths. The plan rejects empty,
dot, and parent components, backslashes, absolute paths, initial drive
prefixes such as `C:`, and controls. Ordinary colons are allowed. UTF-8
names also reject Unicode control characters. Raw names preserve their
encoded bytes and use byte-level syntax checks. Directory names require
one trailing slash and the Stored method. Explicit directory entries
carry metadata and do not traverse the source filesystem.

`CollisionPolicy::Exact` rejects duplicate encoded names, file-directory
conflicts, and a regular file at an ancestor of another entry.
`CollisionPolicy::CallerKeys` additionally compares one caller-supplied
opaque key per component. It rejects aliases of a projected directory
with different original spellings. The caller chooses the normalization
policy for its intended extraction environment.

## Verification and native publication

Publication writes a private `0600` stage and verifies the exact open file
before applying the requested output mode. Verification checks local
and central metadata, contiguous record and payload ranges, the ZIP64
end chain when present, and the exact archive comment and EOF. It checks
every regular payload's length and CRC. Deflate must consume its entire
declared packed range. A raw comment that gives either ordinary reader
profile a different directory interpretation fails verification with
`AmbiguousDirectory`. The generic writer remains available for arbitrary
raw comments.

The commit operation uses `renameatx_np(RENAME_EXCL)` on macOS and
`renameat2(RENAME_NOREPLACE)` on Linux. An existing destination, including
a symlink, directory, or hard link, retains its name and contents. Among
two otherwise successful creators, exactly one publishes. The wrapper
rejects unqualified filesystems before staging and has no copy, hard-link,
or ordinary rename fallback. The allowlist covers local APFS, Linux tmpfs,
and the Linux ext-family magic. Native syscall errors remain authoritative.
The qualification test prints the filesystem that actually ran. Local
acceptance exercised APFS and tmpfs. Overlayfs, network, FUSE, XFS, and
btrfs filesystems are outside the allowlist.

Stage creation, commit, and explicit cleanup use single-component names
relative to the held parent. Generated stage names contain 16 random
characters. They differ from the target in the presence of an ASCII tilde,
which is preserved by the case folding and canonical normalization used
on eligible filesystems. This prevents a temporary name from aliasing the
target on a case-insensitive directory. [APFS filename rules](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/APFS_Guide/FAQ/FAQ.html)
and [ext4 filename rules](https://docs.kernel.org/6.2/admin-guide/ext4.html).

Use a caller-controlled parent directory and source namespace. Publication
and cleanup check observed parent and stage bindings. A matching lookup
followed by unlink cannot condition the unlink on the inode, so concurrent
renaming of stage names by another actor falls outside the namespace
contract. A detected foreign stage name is preserved. Process termination
or a cleanup failure can leave a stage. Dropping its handle never unlinks it.

## Outcomes and durability

Inspect `CreateFailure.publication` before retrying.

| Publication | Meaning |
| --- | --- |
| `NotPublished` | The transaction stopped before commit or the native operation definitively failed. |
| `Published` | The native commit succeeded. An error may report cleanup or directory synchronization. |
| `Unknown` | The native error leaves the result uncertain. Publication is not retried and a possible destination is preserved. |

The cleanup state reports an absent stage, a retained stage name, a foreign
name, or a failure checking or removing the owned stage. An uncertain
ownership check preserves the stage and reports the last known path. A
published archive remains in place after cleanup or synchronization errors.

`VisibilityOnly` publishes complete verified bytes atomically.
`SyncFileAndDirectory` also calls native `fsync` on the stage before
publication and the held parent afterward. `Synced` records successful
calls. It does not imply a hardware power-loss guarantee or macOS
`F_FULLFSYNC`. A file sync failure is precommit. A directory sync failure
is `Published` with `Unconfirmed` durability. Cancellation is cooperative
before commit. After commit, the bounded cleanup and sync attempts still
run.

## Resource ceilings

| Component | Default |
| --- | ---: |
| Entries | 1,000,000 |
| Retained caller source handles | 4,096 |
| Plan capacity, including receipts and sort indices | 128 MiB |
| Plan comparison and validation work | 2^32 |
| Exclusive stage-name attempts | 64 |
| Verification directory size and record count | 128 MiB and 1,000,000 |
| Aggregate strict parser and default discovery fetched bytes | 129 MiB |
| Equivalent raw verification metadata | 128 MiB |
| Verification parser scratch | 16 MiB |
| Verification fixed central records | 128 MiB |
| Cumulative verification reads | 4 TiB |
| Decoded verification bytes per member and per archive | 1 TiB and 2 TiB |
| Transaction attempts including reserved finalization | 2^32 |
| Reserved cleanup and directory sync attempts | 64 |

The [writer's own limits](zip-writer.md#resource-limits) also apply.
The verification record budget can lower the effective entry ceiling.
The plan accounts retained capacities before admission. Objects already
allocated by the caller are outside that accounting until admission.
Writer central storage is released before the verifier owns its raw
central projection. Payloads use bounded streaming buffers. Component
budgets exclude allocator and codec overhead and are not process memory
limits.

On Linux, choose a qualified temporary directory before running the
creation test matrix. Container `/tmp` is often overlayfs. The test
`native_filesystem_qualification` reports the actual filesystem. The
opt-in large test writes and verifies a real archive above 4 GiB.

```sh
cargo test --locked --lib native_filesystem_qualification -- --nocapture
cargo test --locked --test zip_create
cargo test --locked --release --test zip_create streamed_zip64_transaction_exceeds_four_gib -- --ignored
```
