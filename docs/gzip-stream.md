# Shared gzip streams

`zipfast::stream::gzip` encodes one gzip member or decodes and verifies a
sequence of adjacent members. The source is a caller-owned `BufRead`, and the
sink is a caller-owned `Write`. Both stay open, and the engine does not flush
the sink. The same decoder handles extraction, integrity testing, and listing.
Pass `std::io::sink()` for testing or listing and collect any desired listing
fields in the member callback.

```rust
use std::io;
use zipfast::stream::gzip::{
    Control, DecodeOptions, DecodeOutcome, MemberEvent, TailPolicy, decode,
};

fn main() -> Result<(), zipfast::stream::gzip::Failure> {
    let options = DecodeOptions { tail: TailPolicy::Strict };
    let mut input = io::BufReader::new(io::stdin().lock());
    let outcome = decode(&mut input, &mut io::sink(), options, Control::default(), |event| {
        if let MemberEvent::Verified { header, decoded_bytes, .. } = event {
            // Copy any metadata the caller needs to retain past this callback.
            let _row = (header.index, header.metadata.filename, decoded_bytes);
        }
        Ok(())
    })?;
    match outcome {
        DecodeOutcome::Verified(report) => assert!(report.totals.members > 0),
        DecodeOutcome::NotGzip { .. } => { /* caller decides how to handle this input */ }
    }
    Ok(())
}
```

## Framing and metadata

- Encoding requires an explicit level in 0–9, operating-system code, and MTIME.
  `Metadata::default()` supplies unknown OS (255), unknown MTIME (0), and absent
  optional fields. Raw filename, comment, and extra fields can each hold up
  to 65,535 bytes. Filename and comment cannot contain NUL. Present-empty
  fields survive encoding and decoding. Options are validated before I/O.
- A `Header` event follows a valid header, including FHCRC when present, and
  precedes all output for that member. It carries the zero-based member index,
  its logical compressed offset, exact wire header length, and raw metadata.
  The engine neither interprets a filename as text nor uses it as a path.
  Encoding does not emit FHCRC.
- A `Verified` event follows successful CRC32 and modulo-2³² ISIZE checks and
  successful writes for that member. It adds the complete compressed member
  length and full 64-bit decoded length. Verification is delegated to flate2.
  Callback errors fail the operation. A failed verified-member callback still
  leaves that member in the failure's verified totals.
- A valid header or verified member gives no assurance about following members
  or tails. Output can reach the sink before trailer validation. Callers that
  require all-or-nothing publication stage both output and any list results
  until the final outcome.

## Detection and tails

The first two gzip identification bytes, `1f 8b`, commit to gzip. An empty
source, an initial lone `1f`, or a mismatched ID returns `NotGzip`. To pass
such input through, replay `prefix[..prefix_len as usize]` followed by reads
from the **same** buffered input. The decoder consumes one byte for an
immediate mismatch and up to two for a potential match. Any bytes prefetched
by the input remain available there. A source error, limit, or cancellation
during the probe fails the operation.

After a verified member, clean EOF completes the stream. Adjacent matching
IDs commit to the next member, including when its remaining header is
malformed. A lone `1f` after a member is a truncated next member.

- `Strict` rejects any other nonempty tail.
- `TerminalPaddingAndGarbage` scans that entire tail to EOF. A zero-only tail
  reports `Zeros { bytes }`. Any other tail reports
  `Garbage { bytes, leading_zeros }`. A valid gzip sequence following the
  first tail byte remains part of the tail.

## Limits, counters, and I/O

- `Limits::default()` leaves logical source, decoded, encoded, and member
  counts uncapped and sets a combined limit of 1,073,741,824 attempts. A source
  fill, a top-level codec call, and a sink write each cost an attempt. Codec
  loops that refill the source also consume the budget. Callers can reduce
  these limits for their workloads. Highly fragmented I/O consumes the
  attempt budget faster than large buffered transfers.
- Source limits count consumed bytes, including headers, trailers, detection,
  and accepted tails. A nonconsuming fill at the source boundary distinguishes
  exact EOF from extra data. The caller's buffer can physically prefetch past
  that boundary. Place a physical read limiter below the buffer when needed.
- Output limits cap the bytes accepted by the sink. At an exact limit, the
  engine can probe for one additional codec byte without writing it. Empty
  members can still verify at an exact decoded quota. A member quota rejects
  a recognized next member before parsing its header.
- Failure progress separates logical source consumed, bytes returned by the
  codec, bytes accepted by successful sink writes, and totals for complete
  verified members. A partial write advances the sink total by its accepted
  count, and a one-byte quota probe advances only the codec total. Successful
  compressed totals cover all member headers, compressed payloads, and
  trailers, excluding any accepted tail. Framing totals cover headers and
  eight-byte trailers. Successful source totals include any accepted tail
  when decoding and equal original bytes when encoding.
- Interrupted source and sink operations retry within the attempt budget.
  Terminal I/O and callback errors retain their original error values.
  `WouldBlock` is terminal. A zero-length write with pending output is
  `WriteZero`. After a failure, the engine performs no subsequent writes.
  Cancellation is checked at attempts, callbacks, and completion boundaries.
  A cancellation check cannot interrupt an I/O call already blocked in the
  operating system.
- The engine holds a 64 KiB transfer buffer and metadata for the current
  member. The locked flate2 1.1.10 parser accepts up to 65,535 bytes for each
  optional field, so the maximum wire header is 196,621 bytes. This wire
  bound excludes allocator capacity, flate2 state, and caller-owned buffers.

## Root gzip and tar behavior

The archive entry points use a pull reader.
`Codec::sniff` requires `1f 8b 08` for initial gzip recognition. The generic
scanner commits at `1f 8b` and returns a replayable non-gzip outcome for an
initial lone `1f`. The root reader and strict scanner reject nonempty tails.
The root reader can report a short tail as truncation because its decoder
tries to read another fixed header. The strict scanner reports trailing data
unless the prefix indicates a next member.

The root reader classifies the decoded stream as tar or a standalone file.
For tar it emits member contents and drains the compressed stream past the
tar end marker to verify later gzip members. The scanner emits all decoded
bytes, including tar headers, padding, and bytes after the tar end marker.
An all-zero stream is recognized as empty tar only for whole 512-byte blocks
from 1 KiB through 1 MiB. Other standalone streams replay the bytes used for
classification and produce one list entry sized across all members.

The standalone name comes from the first gzip header if usable, with text
conversion and path sanitization applied by root. Otherwise it comes from
the source basename, with `.tgz` and `.taz` mapping to `.tar`. The public
`gzip_name(path)` helper opens the path independently and reads through FNAME.
It can return a name even when a later header field or FHCRC fails validation.
Taking a name from the same stream during a future reader change is an
integration decision.

Root stages replacement output until verification succeeds. A selected read
may emit its payload before final verification and may be cancelled during
the drain. Standalone extraction that skips an existing destination stops
after classification and can leave later members unverified.
