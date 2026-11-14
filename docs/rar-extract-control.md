# Controlled selected RAR extraction

`rar5::session::RarSession::extract_selected_controlled` runs the existing
selected decoder, verifier, staged output owner and RAR5 solid history once.
It adds ordered Skip/Always/Ask policy, one synchronous `RarExtractObserver`,
and optional target-safe diagnostics. Existing `extract_selected`, Options,
Overwrite, run summaries and native decoder support retain their behavior.
RAR4 compressed solid history, Rename and command-line prompting are outside
this API.

Create `RarExtractControl::new(Some(file), mode, limits)` with the exact
already-open diagnostic File, or None. Construction performs no I/O, cloning
or allocation. Ask calls `overwrite` only for a valid existing regular target,
with its actual path and a scalar no-follow snapshot. Return Replace or Skip;
the observer owns all/never and input state. EOF/read/quit/cancellation/decision
input limits are owned `RarDecisionError` stops. Native target/source checks run
after a normal decision and after every normal outcome callback, including
the final callback. Unprocessed decision/control stops add no invented failed
or skipped counts. Completed publications remain counted if a later source
check fails.

The parent is held with macOS O_SEARCH or Linux O_PATH, plus
O_DIRECTORY/O_NOFOLLOW/O_CLOEXEC. Replacement does not require read permission
on the parent or existing target. Parent ancestry and target stamps are
checked after the decision and before the incumbent verified publication.
The caller must control the namespace between the latest checks and operation;
this is detection at checkpoints, not atomic check-and-write isolation.

## Lazy diagnostics and lifetimes

`early_diagnostic()` can admit a proven character stream, FIFO/pipe or socket
before a catalogue. None and unsupported descriptor kinds mute. Regular Files
remain PendingTargets until selection admission. Parser/setup errors can
therefore be silent on a regular File. Open a session independently of the
optional diagnostic descriptor; diagnostic aliases do not abort extraction.

The guard shares engine sanitization and flatten projection. Before native
mutation it admits selected candidates, including valid failed, older and
skipped names, parent obstructions and duplicate targets. It retains original
identities and each actual held stage/published winner. Its one root capability
and prepared relative-to-root C probes bound observation without opening every
target. Paths below system ancestor symlinks are qualified by their observed
prefix bindings; the native destination/parent symlink policy is unchanged.
Missing chains have explicit prefix observations. Prior bindings are checked
before known engine changes; foreign substitutions cannot become a new engine
baseline. A regular descriptor aliasing any protected byte-bearing object is
muted independently of native extraction.

`RarDiagnostic::snapshot()` is historical. Only `writer()` refreshes current
source/target/parent proof before lending the exact retained File. Quiet
callbacks and report construction do not request a refresh. Engine mutation
hooks separately charge the observations needed to retain expected bindings.
A sticky first proof failure revokes future writers and releases guard storage.
It never replaces a native error or stops otherwise valid extraction.

End the lent File borrow after each bounded, no-wait emission. End it before
waiting for input/readiness and before any retry or partial-write continuation;
request `writer()` again afterward. Do not clone, replace, swap, move out,
close, dup2 or otherwise substitute the File/descriptor, or write through a
second descriptor. This is a trusted caller protocol; a mutable File reference
does not enforce one write or prohibit waiting. The observer must handle its
own sink failures without an unguarded fallback.

The terminal `RarControlledExtractReport` owns the historical outcome and
borrows the session's original source capabilities and mutable control. It
retains no observer/selection/options borrow and clones no source descriptor.
Delayed terminal writers still refresh. `finish()` returns the outcome, final
usage, last historical diagnostic snapshot, first owned proof failure and
independent scalar teardown aftermath. Dropping the report does the same
close-only cleanup but leaves the first failure inspectable through control.
Finish/drop performs no normal directory restoration or other namespace
mutation. Finish the report before reusing the session or resetting control.

## Finite component accounting

| Native control default | Ceiling |
| --- | --- |
| Live owned buffer capacity | 128 MiB |
| Mapping/control work | 2^32 units |
| Observer decision calls | 1,000,000 |
| Newly introduced native control I/O attempts | 2^32 |
| Simultaneously owned plus uncertain decision parents | 1 |

| Optional diagnostic default | Ceiling |
| --- | --- |
| Selected targets | 65,536 |
| Parent/path records | 131,072 |
| Live proof buffer capacity | 64 MiB |
| Owned plus uncertain guard handles | 8 |
| Aggregate proof work | 2^30 units |
| Aggregate proof I/O attempts | 2^24 |
| I/O attempts per validation operation | 2^20 |

These are separate component ledgers, not process RSS/global syscall bounds.
Actual allocator capacities are charged and fallibly reserved before new work.
Prepared source/target/parent/leaf buffers and new event identities belong to
the native ledger; guard paths, histories and temporary projections belong to
proof. Scalar state and fixed stack syscall scratch are structurally bounded.
Admission/scan/compare work and retry attempts are checked before execution;
work units include bytes/visits in the new control paths, with conservative
precharged bounds for shared normalization and standard-library path traversal. Empty selections do
not allocate native per-run probe storage. Catalogue defaults remain 64
volumes, 1,000,000 entries, 64 MiB names and 128 MiB capacity; decoder defaults
remain 8 GiB packed/decoded and 256 MiB window.

Each new successful handle acquisition reserves a cleanup ticket. The owner
consumes that File with IntoRawFd and invokes pinned libc close exactly once,
reading errno immediately on failure. Every failure, including EINTR/EIO/EBADF,
is conservatively uncertain; its numeric descriptor is never retained,
reconstructed, probed or retried. Successful acquisitions partition into
owned + confirmed_closed + uncertain. Uncertain liabilities keep their slots;
peaks describe ownership, not liabilities. The first close failure, original
proof mute and native outcome remain independent. Arithmetic invariant failure
poisons accounting and still closes remaining owned handles once.

Report cleanup frees actual buffers and closes new guard/decision handles.
The diagnostic File, session inputs, incumbent tempfile/stage ownership and
incumbent directory metadata Files are outside this observable-close ledger.
Their ordinary Rust drops are not claims of confirmed OS closure. One supplied
diagnostic File is counted separately and recovered unchanged, with unchanged
flags. No total process FD or historical leak bound is asserted.

A control epoch is Ready -> Extracting -> Terminal -> Closed. Reuse requires
explicit `reset()`. Reset frees residual storage and returns owned aftermath;
it cannot clear uncertainty or accounting poison. Repeated failed reset never
retries close or grants fresh budgets. `into_diagnostic()` always returns the
original File plus owned aftermath. The enclosing caller must retain uncertain
liability; discarding recovery and constructing another control is not a
qualified budget reset. Reset cannot repair sticky source invalidation.

## Exact incumbent directory-drain exception (I2)

New controlled directory vectors, complete owned paths and record admission
are fallibly reserved and charged before root/member directory mutation. An
admitted record is committed without a later budget check or allocation.
Every ordinary terminal path explicitly drains committed records before the
report is returned, including control/native limit, allocation refusal,
EOF/read/quit/cancel and diagnostic mute. Last selected record per observed
identity wins; restoration remains deepest-first and best effort, including
unreadable-directory fallback. An unwinding Extraction drop is only a fallback.

Only the incumbent drain helper body is outside the new work/I/O/typed
allocation-refusal ceilings: identity/ordinal sorting and dedup, depth scanning,
parent inspection and existing PathBuf/fault allocation, directory open and
held metadata check, finish_file/time/permissions and the PermissionDenied
no-follow CString/symlink_metadata/fchmodat fallback with ordinary File drops.
New record storage/preparation and guard observations are counted and do not
inherit this exception. No finite cancellation latency or infallible-allocation
recovery is promised for that incumbent helper, existing decoder, tempfile or
payload I/O internals. No normal metadata mutation is deferred to report Drop.
