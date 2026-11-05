//! Round trips through a small test-only encoder that writes blocks with fixed code lengths.

use super::*;
use crate::rar5::testenc::*;

/// Decodes on the calling thread and on workers, with and without the decoder working out the CRC32, and checks
/// all give the same output or the same error.
fn decode(stream: &[u8], size: u64, window: u64, piece: usize) -> Result<Vec<u8>> {
    let serial = decode_with(stream, size, window, piece, 0, Hash::Off);
    for (threads, hash) in [(3, Hash::Off), (0, Hash::Here), (3, Hash::Helper)] {
        let other = decode_with(stream, size, window, piece, threads, hash);
        match (&serial, &other) {
            (Ok(a), Ok(b)) => assert!(a == b, "{threads} workers, {hash:?}: different bytes"),
            (Err(a), Err(b)) => assert_eq!(a.to_string(), b.to_string(), "{threads} workers, {hash:?}: another error"),
            _ => panic!(
                "serial {:?} vs {threads} workers, {hash:?}: {:?}",
                serial.as_ref().map(|v| v.len()),
                other.as_ref().map(|v| v.len())
            ),
        }
    }
    serial
}

/// How a test's decoder treats the output's CRC32: not at all, or working it out with every stretch it can handed
/// over, either to wait until it is needed and be hashed on the calling thread, or to the helper thread.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Hash {
    Off,
    Here,
    Helper,
}

fn hashing(u: &mut Unpacker, hash: Hash) {
    if hash != Hash::Off {
        u.hand_over_window = 0;
        u.hand_over_min = 0;
        u.crc.helper = if hash == Hash::Helper { crc::Helper::Thread } else { crc::Helper::Held };
    }
}

/// Output gathered file by file, an empty slice starting the next, with the CRC32 the decoder hands over for each.
struct Hashed {
    hash: bool,
    files: Vec<(Vec<u8>, Option<u32>)>,
}

impl Hashed {
    fn new(hash: Hash) -> Self {
        Hashed { hash: hash != Hash::Off, files: vec![(Vec::new(), None)] }
    }

    /// The files and whatever was put after the last of them, each checked against the CRC32 handed over for it.
    fn checked(self) -> Vec<Vec<u8>> {
        let n = self.files.len();
        self.files
            .into_iter()
            .enumerate()
            .map(|(i, (bytes, crc))| {
                if self.hash && i + 1 < n {
                    assert_eq!(crc, Some(crc32fast::hash(&bytes)), "file {i}'s CRC");
                }
                bytes
            })
            .collect()
    }
}

impl Sink for Hashed {
    fn put(&mut self, b: &[u8]) -> Result<()> {
        if b.is_empty() {
            self.files.push((Vec::new(), None));
        } else {
            self.files.last_mut().unwrap().0.extend_from_slice(b);
        }
        Ok(())
    }

    fn wants_crc(&self) -> bool {
        self.hash
    }

    fn crc(&mut self, crc: u32) {
        let file = self.files.last_mut().unwrap();
        assert!(file.1.replace(crc).is_none(), "a second CRC for one file");
    }
}

fn decode_with(stream: &[u8], size: u64, window: u64, piece: usize, threads: usize, hash: Hash) -> Result<Vec<u8>> {
    let mut u = Unpacker::new(window)?;
    u.set_threads(threads, 0);
    hashing(&mut u, hash);
    u.reset(Some(size));
    let mut sink = Hashed::new(hash);
    for chunk in stream.chunks(piece.max(1)) {
        u.feed(chunk, &mut sink)?;
    }
    u.finish(&mut sink)?;
    sink.put(&[])?;
    let mut files = sink.checked();
    files.pop();
    Ok(files.pop().unwrap())
}

fn lits(s: &[u8]) -> Vec<Op> {
    s.iter().map(|&b| Op::Lit(b)).collect()
}

#[test]
fn literals() {
    let ops = lits(b"hello, world");
    let stream = block(&ops, true, true);
    assert_eq!(decode(&stream, 12, 1 << 17, usize::MAX).unwrap(), b"hello, world");
}

#[test]
fn matches_repeats_and_low_distance_bits() {
    let mut ops = lits(b"abcdefgh");
    ops.push(Op::Match(20, 1)); // a run of h
    ops.push(Op::Match(5, 8));
    ops.push(Op::Last);
    ops.extend((0..3000).map(|i| Op::Lit((i * 7 % 251) as u8)));
    ops.push(Op::Match(300, 2900)); // low-distance table, with bonus
    ops.push(Op::Rep(1, 10));
    ops.push(Op::Rep(0, 4097));
    ops.push(Op::Match(2, 37));
    ops.push(Op::Rep(3, 3));
    let want = model(&ops);
    let stream = block(&ops, true, true);
    assert_eq!(decode(&stream, want.len() as u64, 1 << 17, usize::MAX).unwrap(), want);
    // the same stream a byte at a time
    assert_eq!(decode(&stream, want.len() as u64, 1 << 17, 1).unwrap(), want);
}

#[test]
fn later_blocks_reuse_tables() {
    let a = lits(b"first block ");
    let b = vec![Op::Match(6, 12), Op::Lit(b'!')];
    let mut all = a.clone();
    all.extend(b.clone());
    let want = model(&all);
    let mut stream = block(&a, true, false);
    stream.extend(block(&b, false, true));
    assert_eq!(decode(&stream, want.len() as u64, 1 << 17, 5).unwrap(), want);
}

#[test]
fn the_window_wraps_and_flushes() {
    // 1 MiB through a 128 KiB window, with matches reaching 64 KiB back
    let mut ops = Vec::new();
    let mut seed = 1u32;
    for _ in 0..70_000 {
        seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
        ops.push(Op::Lit((seed >> 16) as u8));
    }
    let mut made = 70_000u64;
    while made < 1 << 20 {
        seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
        let dist = 1 + u64::from(seed >> 16) % 65_536;
        let len = 5 + (seed >> 8) % 4000;
        ops.push(Op::Match(len, dist));
        made += u64::from(len);
        ops.push(Op::Lit(seed as u8));
        made += 1;
    }
    let want = model(&ops);
    let mut stream = Vec::new();
    // blocks of a few thousand ops, tables only in the first
    for (i, chunk) in ops.chunks(4000).enumerate() {
        let last = (i + 1) * 4000 >= ops.len();
        stream.extend(block(chunk, i == 0, last));
    }
    let got = decode(&stream, want.len() as u64, 1 << 17, 100_000).unwrap();
    assert!(got == want, "mismatch");
}

#[test]
fn output_hashed_straight_from_the_window_matches_what_was_put() {
    // eight windows of output with matches from up to a window back, so stretches handed over are soon due to be
    // written over, and delta filters now and then, whose output is handed over too
    let window = 1u64 << 20;
    let mut seed = 7u32;
    let mut ops = Vec::new();
    let mut made = 0u64;
    let mut next_filter = 300_000;
    while made < 8 * window {
        seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
        if made >= next_filter {
            ops.push(Op::Filter { start: 0, len: 100_000, kind: 0, channels: 3 });
            next_filter += 1_500_000;
        }
        if made < 4096 || seed.is_multiple_of(3) {
            ops.push(Op::Lit((seed >> 16) as u8));
            made += 1;
        } else {
            let dist = 1 + u64::from(seed >> 8) % made.min(window);
            let len = 5 + (seed >> 4) % 4000;
            ops.push(Op::Match(len, dist));
            made += u64::from(len);
        }
    }
    let mut stream = Vec::new();
    let chunks: Vec<_> = ops.chunks(4000).collect();
    for (i, chunk) in chunks.iter().enumerate() {
        stream.extend(block(chunk, i == 0, i + 1 == chunks.len()));
    }
    // every way of decoding agrees, and each hashing one hands over the CRC of what it put
    let plain = decode(&stream, made, window, 70_000).unwrap();
    assert_eq!(plain.len() as u64, made);
    for (threads, hash) in [(0, Hash::Here), (3, Hash::Helper)] {
        let mut u = Unpacker::new(window).unwrap();
        u.set_threads(threads, 0);
        hashing(&mut u, hash);
        u.reset(Some(made));
        let mut sink = Hashed::new(hash);
        u.feed(&stream, &mut sink).unwrap();
        u.finish(&mut sink).unwrap();
        assert!(u.crc.handed_over > 20, "{hash:?}: {} stretches handed over", u.crc.handed_over);
        assert_eq!(sink.files[0].1, Some(crc32fast::hash(&plain)), "{hash:?}");
    }
}

#[test]
fn the_crc_helper_runs_only_beside_decoding_workers() {
    // a window big enough to hand output over, and more output than is emitted at once
    let data: Vec<u8> = (0..10u32 << 20).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    let ops = lits(&data);
    let chunks: Vec<_> = ops.chunks(1 << 19).collect();
    let mut stream = Vec::new();
    for (i, chunk) in chunks.iter().enumerate() {
        stream.extend(block(chunk, i == 0, i + 1 == chunks.len()));
    }
    for threads in [0, 3] {
        let mut u = Unpacker::new(16 << 20).unwrap();
        u.set_threads(threads, 0);
        u.reset(Some(data.len() as u64));
        let mut sink = Hashed { hash: true, files: vec![(Vec::new(), None)] };
        u.feed(&stream, &mut sink).unwrap();
        u.finish(&mut sink).unwrap();
        assert_eq!(sink.files[0].1, Some(crc32fast::hash(&data)), "{threads} workers");
        assert!(sink.files[0].0 == data, "{threads} workers");
        // with no workers, everything is hashed on the calling thread, as it is emitted
        assert_eq!(u.crc.handed_over > 0, threads > 0, "{threads} workers: {} handed over", u.crc.handed_over);
    }
}

#[test]
fn e8_filter_example() {
    // the spec's example: an E8 at offset 100 with operand 0x00000F00 becomes 0x00000E9B
    let mut data = vec![0u8; 200];
    data[100] = 0xe8;
    data[101..105].copy_from_slice(&0x0000_0f00u32.to_le_bytes());
    data[150] = 0xe8;
    data[151..155].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
    let mut ops = vec![Op::Filter { start: 0, len: 200, kind: 1, channels: 0 }];
    ops.extend(lits(&data));
    let stream = block(&ops, true, true);
    let got = decode(&stream, 200, 1 << 17, usize::MAX).unwrap();
    assert_eq!(&got[101..105], &0x0000_0e9bu32.to_le_bytes());
    // 0xFFFFFFF0 + 151 wraps to a small positive value, so the operand gains 0x1000000
    assert_eq!(&got[151..155], &0x00ff_fff0u32.to_le_bytes());
    assert_eq!(got[100], 0xe8);
}

#[test]
fn filters_leave_gaps_unfiltered_and_count_from_the_file_start() {
    let data: Vec<u8> = (0..400u32).map(|i| (i * 13) as u8).collect();
    // a delta filter over 100..200, announced at position 0, and an ARM filter over 300..340 announced later
    let mut ops = vec![Op::Filter { start: 100, len: 100, kind: 0, channels: 3 }];
    ops.extend(lits(&data[..250]));
    ops.push(Op::Filter { start: 50, len: 40, kind: 3, channels: 0 });
    ops.extend(lits(&data[250..]));
    let stream = block(&ops, true, true);
    let got = decode(&stream, 400, 1 << 17, 7).unwrap();
    assert_eq!(&got[..100], &data[..100]);
    assert_eq!(&got[200..300], &data[200..300]);
    assert_eq!(&got[340..], &data[340..]);
    // delta: planar input, interleaved negated running sums
    let src = &data[100..200];
    let mut want = [0u8; 100];
    let mut s = 0;
    for c in 0..3 {
        let mut acc = 0u8;
        let mut j = c;
        while j < 100 {
            acc = acc.wrapping_sub(src[s]);
            want[j] = acc;
            s += 1;
            j += 3;
        }
    }
    assert_eq!(&got[100..200], &want[..]);
    // ARM: words ending in 0xEB get their 24-bit field reduced by their position / 4
    for j in (300..340).step_by(4) {
        if data[j + 3] == 0xeb {
            let v = u32::from_le_bytes(data[j..j + 4].try_into().unwrap()) & 0xff_ffff;
            let v = (v.wrapping_sub(j as u32 / 4) & 0xff_ffff) | 0xeb00_0000;
            assert_eq!(&got[j..j + 4], &v.to_le_bytes());
        } else {
            assert_eq!(&got[j..j + 4], &data[j..j + 4]);
        }
    }
}

#[test]
fn rejects_bad_streams() {
    let ok = block(&lits(b"abc"), true, true);
    let mut bad = ok.clone();
    bad[1] ^= 1;
    assert!(decode(&bad, 3, 1 << 17, usize::MAX).is_err(), "header checksum");
    let far = block(&[Op::Lit(1), Op::Match(4, 2)], true, true);
    assert!(decode(&far, 5, 1 << 17, usize::MAX).is_err(), "match before the start");
    assert!(decode(&ok, 2, 1 << 17, usize::MAX).is_err(), "more data than declared");
    assert!(decode(&ok, 4, 1 << 17, usize::MAX).is_err(), "less data than declared");
    assert!(decode(&ok[..ok.len() - 1], 3, 1 << 17, usize::MAX).is_err(), "truncated");
    let no_tables = block(&lits(b"abc"), false, true);
    assert!(decode(&no_tables, 3, 1 << 17, usize::MAX).is_err(), "no tables");
}

#[test]
fn a_filter_over_the_whole_file_fits_the_window_chosen_for_it() {
    let data: Vec<u8> = (0..100_000u32).map(|i| (i * 7 % 251) as u8).collect();
    let mut ops = vec![Op::Filter { start: 0, len: 100_000, kind: 0, channels: 1 }];
    ops.extend(lits(&data));
    let stream = block(&ops, true, true);
    let window = window_for(4 << 20, Some(100_000), false).unwrap();
    let got = decode(&stream, 100_000, window, 4096).unwrap();
    assert_eq!(got.len(), 100_000);
}

/// Output is emitted every few MiB however big the window; filters of the longest range still come out whole,
/// wherever they fall against those points.
#[test]
fn longest_filters_across_the_points_output_is_emitted_at() {
    const MIB: usize = 1 << 20;
    let len = MAX_FILTER_LEN as usize;
    let data: Vec<u8> = (0..12 * MIB as u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    let mut ops = lits(&data[..3 * MIB + 5]);
    ops.push(Op::Filter { start: 0, len: len as u64, kind: 0, channels: 1 });
    ops.extend(lits(&data[3 * MIB + 5..7 * MIB + 9]));
    ops.push(Op::Filter { start: 0, len: len as u64, kind: 0, channels: 1 });
    ops.extend(lits(&data[7 * MIB + 9..]));
    let mut stream = Vec::new();
    let chunks: Vec<_> = ops.chunks(MIB / 2).collect();
    for (i, chunk) in chunks.iter().enumerate() {
        stream.extend(block(chunk, i == 0, i + 1 == chunks.len()));
    }
    let got = decode(&stream, data.len() as u64, 32 << 20, MIB).unwrap();
    let mut want = data.clone();
    for start in [3 * MIB + 5, 7 * MIB + 9] {
        // delta over one channel: negated running sums
        let mut acc = 0u8;
        for j in start..start + len {
            acc = acc.wrapping_sub(data[j]);
            want[j] = acc;
        }
    }
    assert!(got == want, "mismatch");
}

#[test]
fn window_sizes_stay_sane_for_any_stated_size() {
    assert_eq!(window_for(1 << 17, Some(u64::MAX - 1), false).unwrap(), 1 << 17);
    assert_eq!(window_for(1 << 22, Some(u64::MAX), false).unwrap(), 1 << 22);
    assert_eq!(window_for(1 << 22, Some(100_000), false).unwrap(), 1 << 18);
    assert_eq!(window_for(1 << 22, Some(10), false).unwrap(), 1 << 17);
    assert_eq!(window_for(1 << 22, Some(10), true).unwrap(), 1 << 22);
}

#[test]
fn tuned_codes_from_a_real_matcher_round_trip() {
    // text-like data with repeats near and far, plus a stretch of noise
    let mut data = Vec::new();
    let mut x = 12345u32;
    for i in 0..40_000u32 {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
        if i % 1000 < 700 {
            data.extend_from_slice(format!("line {} of {} ", i % 97, (x >> 20) % 13).as_bytes());
        } else {
            data.push((x >> 16) as u8);
        }
    }
    let ops = lz(&data, 1 << 20, 8);
    assert_eq!(model(&ops), data);
    assert!(ops.iter().any(|o| matches!(o, Op::Rep(..))) && ops.iter().any(|o| matches!(o, Op::Match(..))));
    let stream = tuned_stream(&ops, 5000);
    // whole, in pieces that split blocks and headers, and a byte at a time
    for piece in [usize::MAX, 4096, 7, 1] {
        assert_eq!(decode(&stream, data.len() as u64, 1 << 21, piece).unwrap(), data, "pieces of {piece}");
    }
}

#[test]
fn workers_agree_with_the_calling_thread_on_damaged_streams() {
    let mut data = Vec::new();
    let mut x = 99u32;
    for i in 0..30_000u32 {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
        if i % 500 < 300 {
            data.extend_from_slice(format!("{} {} ", i % 31, (x >> 22) % 7).as_bytes());
        } else {
            data.push((x >> 16) as u8);
        }
    }
    let ops = lz(&data, 1 << 16, 4);
    let stream = tuned_stream(&ops, 3000);
    let mut y = 7u64;
    for _ in 0..300 {
        y = y.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let mut bad = stream.clone();
        let at = (y >> 33) as usize % bad.len();
        bad[at] ^= 1 << ((y >> 20) % 8);
        // decode() itself checks the two agree
        let _ = decode(&bad, data.len() as u64, 1 << 17, 1 << 12);
    }
    // a wrong stated size, both ways
    let _ = decode(&stream, data.len() as u64 - 1, 1 << 17, usize::MAX);
    let _ = decode(&stream, data.len() as u64 + 1, 1 << 17, usize::MAX);
}

#[test]
fn an_earlier_blocks_error_comes_before_a_later_damaged_header() {
    let mut first: Vec<Op> = (0..100_000u32).map(|i| Op::Lit((i % 251) as u8)).collect();
    first.push(Op::Match(10, 500_000)); // reaches before the start of the data
    let mut stream = block(&first, true, false);
    let mut second = block(&[Op::Lit(1), Op::Lit(2)], false, true);
    second[1] ^= 0xff; // its header checksum
    stream.extend(second);
    for piece in [usize::MAX, 1 << 16, 1000, 1] {
        let err = decode(&stream, 200_000, 1 << 20, piece).unwrap_err();
        assert_eq!(err.to_string(), corrupt("match reaches before the start of the data").to_string(), "{piece}");
    }
}

#[test]
fn a_block_of_tiny_codes_is_finished_on_the_calling_thread() {
    // nine-bit codes that each stand for an 8-byte token: far past a worker's budget for this many packed bytes
    let mut ops = vec![Op::Lit(b'a'), Op::Lit(b'b'), Op::Match(2, 2)];
    ops.extend(std::iter::repeat_n(Op::Last, 400_000));
    let want = model(&ops);
    let stream = block(&ops, true, true);
    assert_eq!(decode(&stream, want.len() as u64, 1 << 21, usize::MAX).unwrap(), want);
    let mut u = Unpacker::new(1 << 21).unwrap();
    u.set_threads(2, 0);
    u.reset(Some(want.len() as u64));
    let mut out = Vec::new();
    let mut sink = |b: &[u8]| -> Result<()> {
        out.extend_from_slice(b);
        Ok(())
    };
    u.feed(&stream, &mut sink).unwrap();
    u.finish(&mut sink).unwrap();
    assert!(out == want);
    assert!(u.resumed > 0, "the worker should have stopped at its budget");
}

#[test]
fn a_worker_stopped_mid_run_still_hands_on_the_lengths_after_it() {
    // one run of blocks: tiny codes past the budget, then blocks without and with tables, then enough noise that
    // more runs follow and wait on the lengths the first run carries
    let mut ops = vec![Op::Lit(b'a'), Op::Lit(b'b'), Op::Match(2, 2)];
    ops.extend(std::iter::repeat_n(Op::Last, 300_000));
    let tail = lits(b"no tables here");
    // codes fitted to both, so the repeats take a bit each and the block after reads with the same tables
    let mut stream = tuned_blocks(&[&ops, &tail], false);
    assert!(stream.len() < JOB_BYTES);
    let mut all = ops;
    all.extend(tail);
    let mut x = 7u64;
    for i in 0..40 {
        let noise: Vec<Op> = (0..20_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                Op::Lit((x >> 24) as u8)
            })
            .collect();
        // every other block keeps the tables before it
        stream.extend(block(&noise, i % 2 == 0, i == 39));
        all.extend(noise);
    }
    let want = model(&all);
    for piece in [usize::MAX, 70_000] {
        assert_eq!(decode(&stream, want.len() as u64, 1 << 22, piece).unwrap(), want, "{piece}");
    }
    let mut u = Unpacker::new(1 << 22).unwrap();
    u.set_threads(2, 0);
    u.reset(Some(want.len() as u64));
    let mut n = 0;
    let mut sink = |b: &[u8]| -> Result<()> {
        n += b.len();
        Ok(())
    };
    u.feed(&stream, &mut sink).unwrap();
    u.finish(&mut sink).unwrap();
    assert_eq!(n, want.len());
    assert_eq!(u.resumed, 1, "the first run should have stopped at its budget");
    assert!(u.submitted > 3);
}

/// Incompressible data with a few skewed bytes and short matches: most literals share one code length, some are
/// shorter or longer, so the guess at four literals of that length is kept, cut short and refused in turn.
fn mostly_noise(n: usize, seed: u64) -> Vec<Op> {
    let mut x = seed | 1;
    let mut ops = Vec::new();
    let mut made = 0u64;
    while (made as usize) < n {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let r = (x >> 24) as u32;
        if r.is_multiple_of(211) && made > 1000 {
            let len = 3 + r % 40;
            ops.push(Op::Match(len, 1 + u64::from(r >> 8) % 900));
            made += u64::from(len);
        } else {
            // byte 7 a little more often, so it gets a shorter code; the rest share one length or near it
            let b = if r.is_multiple_of(37) { 7 } else { (r >> 8) as u8 };
            ops.push(Op::Lit(b));
            made += 1;
        }
    }
    ops
}

#[test]
fn quick_literals_round_trip_with_mixed_lengths() {
    for seed in [1, 2, 3] {
        let ops = mostly_noise(300_000, seed);
        let data = model(&ops);
        let stream = tuned_stream(&ops, 20_000);
        for piece in [usize::MAX, 10_000, 3] {
            assert!(decode(&stream, data.len() as u64, 1 << 20, piece).unwrap() == data, "seed {seed} piece {piece}");
        }
    }
    // the tables these blocks get do have a common literal length to guess with
    let ops = mostly_noise(50_000, 9);
    let block = tuned_block(&ops, true);
    let mut u = Unpacker::new(1 << 20).unwrap();
    u.set_threads(0, 0);
    u.reset(Some(model(&ops).len() as u64));
    let mut sink = |_: &[u8]| Ok(());
    u.feed(&block, &mut sink).unwrap();
    u.finish(&mut sink).unwrap();
    assert_eq!(u.tables.main.common, 8);

    // literals spread over several lengths, about a hundred at the most common one: guessing would often miss,
    // so it isn't tried
    let mut x = 77u64;
    let text: Vec<u8> = (0..60_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            ((x >> 8) as u8).min((x >> 40) as u8)
        })
        .collect();
    let ops = lits(&text);
    let mut u = Unpacker::new(1 << 20).unwrap();
    u.set_threads(0, 0);
    u.reset(Some(text.len() as u64));
    let mut out = Vec::new();
    let mut sink = |b: &[u8]| {
        out.extend_from_slice(b);
        Ok(())
    };
    u.feed(&tuned_block(&ops, true), &mut sink).unwrap();
    u.finish(&mut sink).unwrap();
    assert_eq!(u.tables.main.common, 0);
    assert!(out == text);
}

#[test]
fn eight_bit_codes_of_other_symbols_end_a_quick_run() {
    // noise with one short match about as often as each byte value, so the match gets an 8-bit code too
    let mut x = 11u64;
    let mut ops = Vec::new();
    for i in 0..200_000 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        if i > 100 && (x >> 20).is_multiple_of(256) {
            ops.push(Op::Match(4, 64));
        } else {
            ops.push(Op::Lit((x >> 32) as u8));
        }
    }
    let data = model(&ops);
    let block = tuned_block(&ops, true);
    let mut u = Unpacker::new(1 << 20).unwrap();
    u.set_threads(0, 0);
    u.reset(Some(data.len() as u64));
    let mut out = Vec::new();
    let mut sink = |b: &[u8]| {
        out.extend_from_slice(b);
        Ok(())
    };
    u.feed(&block, &mut sink).unwrap();
    u.finish(&mut sink).unwrap();
    assert!(out == data);
    let main = &u.tables.main;
    assert_eq!(main.common, 8);
    let at = |v: usize| main.lut[v << (LUT_BITS - 8)];
    assert!((0..256).any(|v| at(v) & 15 == 8 && at(v) >> 4 >= 256), "no other symbol got an 8-bit code");
    // the literal codes of length 8 are a range of 8-bit values, and `lit8` holds their literals in code order
    for v in 0..256usize {
        let i = (v as u8).wrapping_sub(main.first8);
        let literal8 = at(v) & 0xF00F == 8;
        assert_eq!(u16::from(i) < main.nlit8, literal8, "code {v}");
        if literal8 {
            assert_eq!(u16::from(main.lit8[usize::from(i)]), at(v) >> 4, "code {v}");
        }
    }
    // the same on workers, and fed in small pieces
    let stream = tuned_stream(&ops, 20_000);
    for threads in [0, 3] {
        for piece in [usize::MAX, 4_096] {
            assert!(decode_with(&stream, data.len() as u64, 1 << 20, piece, threads, Hash::Off).unwrap() == data);
        }
    }
}

#[test]
fn quick_literals_agree_with_workers_on_damage() {
    let ops = mostly_noise(120_000, 5);
    let data = model(&ops);
    let stream = tuned_stream(&ops, 9_000);
    let mut y = 3u64;
    for _ in 0..200 {
        y = y.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let mut bad = stream.clone();
        let at = (y >> 33) as usize % bad.len();
        bad[at] ^= 1 << ((y >> 20) % 8);
        let _ = decode(&bad, data.len() as u64, 1 << 20, 1 << 14);
    }
}

/// A file's packed bytes and declared size.
type SolidFile = (Vec<u8>, u64);

/// What each file of a solid stream decodes to, file by file, up to the first error and whose it is. Serially
/// (`threads` 0) each file is finished before the next starts; otherwise every file after the first is queued.
fn solid_run(
    files: &[SolidFile],
    threads: usize,
    piece: usize,
    hash: Hash,
) -> (Vec<Vec<u8>>, Option<(usize, String)>, u64) {
    let mut u = Unpacker::new(1 << 22).unwrap();
    u.set_threads(threads, u64::MAX);
    hashing(&mut u, hash);
    let mut sink = Hashed::new(hash);
    let mut run = || -> Result<()> {
        for (i, (stream, size)) in files.iter().enumerate() {
            if i == 0 {
                u.reset(Some(*size));
            } else if threads == 0 {
                u.next_file(Some(*size));
            } else {
                if i % 10 == 0 {
                    u.catch_up(4, &mut sink)?;
                    assert!(u.files_queued - u.files_begun <= 4);
                }
                u.queue_file(Some(*size));
            }
            if threads > 0 {
                u.force_parallel();
            }
            for chunk in stream.chunks(piece.max(1)) {
                u.feed(chunk, &mut sink)?;
            }
            if threads == 0 {
                u.finish(&mut sink)?;
                sink.put(&[])?;
            }
        }
        if threads > 0 {
            u.finish(&mut sink)?;
            sink.put(&[])?;
        }
        Ok(())
    };
    let err = run().err().map(|e| e.to_string());
    let resumed = u.resumed;
    drop(u);
    let mut outs = sink.checked();
    // the last entry is the file being decoded when it stopped, or an empty one after the last file
    let failed_at = outs.len() - 1;
    outs.pop();
    (outs, err.map(|e| (failed_at, e)), resumed)
}

fn noise_ops(n: usize, seed: u64) -> Vec<Op> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            Op::Lit((x >> 24) as u8)
        })
        .collect()
}

/// A solid stream of small and big files: fixed codes and tuned ones, files that keep the tables before them, files
/// that copy from earlier ones, an empty one, and one whose tokens are far past a worker's budget.
fn solid_files() -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut all: Vec<Op> = Vec::new();
    let mut files: Vec<(Vec<u8>, Vec<Op>)> = Vec::new();
    let mut fixed_before = false;
    for i in 0..60usize {
        let mut ops = match i % 7 {
            0 => noise_ops(3 + i * 11, i as u64),
            1 => noise_ops(40_000, i as u64),
            2 => lits(format!("file {i} says hello ").as_bytes()),
            3 if !all.is_empty() => {
                // copies from the files before
                let total = model(&all).len() as u64;
                vec![Op::Match(300, total.min(5000)), Op::Lit(b'.'), Op::Rep(0, 40)]
            }
            4 => Vec::new(),
            5 if i == 12 => {
                let mut v = vec![Op::Lit(b'a'), Op::Lit(b'b'), Op::Match(2, 2)];
                v.extend(std::iter::repeat_n(Op::Last, 450_000));
                v
            }
            _ => noise_ops(500, i as u64),
        };
        if ops.is_empty() && i % 7 != 4 {
            ops = lits(b"x");
        }
        let stream = match i % 3 {
            // fixed codes, keeping the tables before when they are fixed too
            0 => {
                let s = block(&ops, !fixed_before || i % 2 == 0, true);
                fixed_before = true;
                s
            }
            1 if ops.len() > 2_000 => {
                fixed_before = false;
                tuned_stream(&ops, 1_500)
            }
            _ => {
                fixed_before = true;
                block(&ops, true, true)
            }
        };
        all.extend(ops.iter().cloned());
        files.push((stream, ops));
    }
    let plain = model(&all);
    let mut at = 0;
    let mut out = Vec::new();
    let mut so_far = Vec::new();
    for (stream, ops) in files {
        so_far.extend(ops);
        let end = model(&so_far).len();
        out.push((stream, plain[at..end].to_vec()));
        at = end;
    }
    out
}

#[test]
fn queued_files_of_a_solid_stream_come_out_as_if_each_waited_for_the_one_before() {
    let files = solid_files();
    let input: Vec<SolidFile> = files.iter().map(|(s, p)| (s.clone(), p.len() as u64)).collect();
    let want: Vec<Vec<u8>> = files.iter().map(|(_, p)| p.clone()).collect();
    for hash in [Hash::Off, Hash::Here] {
        let (serial, err, _) = solid_run(&input, 0, usize::MAX, hash);
        assert_eq!(err, None);
        assert!(serial == want);
    }
    for hash in [Hash::Off, Hash::Helper] {
        for piece in [usize::MAX, 4_093] {
            let (queued, err, resumed) = solid_run(&input, 3, piece, hash);
            assert_eq!(err, None, "{piece}");
            assert!(queued == want, "{piece}");
            assert!(resumed > 0, "a worker should have stopped at its budget, with files after it in the run");
        }
    }
}

#[test]
fn a_queued_files_trouble_is_its_own_and_stops_the_files_after_it() {
    let files = solid_files();
    let good: Vec<SolidFile> = files.iter().map(|(s, p)| (s.clone(), p.len() as u64)).collect();
    let mut cases: Vec<(&str, Vec<SolidFile>)> = Vec::new();
    for k in [0, 8, 13, 30, 59] {
        let mut c = good.clone();
        let mid = c[k].0.len() / 2;
        c[k].0[mid.max(5)] ^= 0x5a;
        cases.push(("damaged", c));
        let mut c = good.clone();
        c[k].1 += 1;
        cases.push(("longer", c));
        let mut c = good.clone();
        c[k].1 = c[k].1.saturating_sub(1);
        cases.push(("shorter", c));
        let mut c = good.clone();
        let n = c[k].0.len();
        c[k].0.truncate(n - 2);
        cases.push(("cut short", c));
    }
    for (what, case) in &cases {
        for (piece, serial_hash, queued_hash) in
            [(usize::MAX, Hash::Off, Hash::Off), (777, Hash::Off, Hash::Off), (777, Hash::Here, Hash::Helper)]
        {
            let (s_out, s_err, _) = solid_run(case, 0, piece, serial_hash);
            let (q_out, q_err, _) = solid_run(case, 3, piece, queued_hash);
            // a flipped bit may only change a byte, which the file's checksum catches later
            assert!(s_err.is_some() || *what == "damaged", "{what}: the serial run should fail");
            assert_eq!(q_err, s_err, "{what} {piece}");
            assert!(q_out == s_out, "{what} {piece}");
        }
    }
}

#[cfg(target_arch = "aarch64")]
#[test]
fn sixteen_literals_at_a_time_match_one_at_a_time() {
    // a block whose literals nearly all have 8-bit codes, with codes of other lengths among them
    let ops = mostly_noise(60_000, 21);
    let data = model(&ops);
    let block = tuned_block(&ops, true);
    let mut u = Unpacker::new(1 << 20).unwrap();
    u.set_threads(0, 0);
    u.reset(Some(data.len() as u64));
    let mut out = Vec::new();
    let mut sink = |b: &[u8]| {
        out.extend_from_slice(b);
        Ok(())
    };
    u.feed(&block, &mut sink).unwrap();
    u.finish(&mut sink).unwrap();
    assert!(out == data);
    let main = &u.tables.main;
    assert_eq!(main.common, 8);
    let (header_len, payload, flags) = block_header(&block).unwrap().unwrap();
    let mut buf = block[header_len..header_len + payload].to_vec();
    buf.resize(payload + PAD, 0);
    let end_bits = (payload - 1) * 8 + usize::from(flags & 7) + 1;
    // the code of 8 bits at any bit position
    let code = |pos: usize| ((u16::from(buf[pos / 8]) << 8 | u16::from(buf[pos / 8 + 1])) >> (8 - pos % 8)) as u8;
    let starts = (1000..1400).chain(end_bits - 600..end_bits);
    let mut total = 0;
    for start in starts {
        for room in [0, 15, 16, 17, 40, 300, STAGE] {
            // one code at a time: as many literals as come in a row, in whole rounds of 16 that fit
            let rounds = if start + 136 <= end_bits { ((end_bits - start - 136) / 128 + 1).min(room / 16) } else { 0 };
            let mut want = Vec::new();
            while want.len() < 16 * rounds {
                let i = code(start + 8 * want.len()).wrapping_sub(main.first8);
                if u16::from(i) >= main.nlit8 {
                    break;
                }
                want.push(main.lit8[usize::from(i)]);
            }
            let mut bits = Bits::at(&buf, start);
            let mut got = [0u8; STAGE + 8];
            let k = main.run8(&mut bits, end_bits, &mut got, room);
            assert_eq!(&got[..k], &want[..], "start {start} room {room}");
            assert_eq!(bits.pos(), start + 8 * k, "start {start} room {room}");
            total += k;
        }
    }
    // plenty of the starts are inside runs of literal codes
    assert!(total > 20_000, "{total}");
}

/// The filters as they read: a byte at a time, from the input into a copy of it.
fn filter_reference(f: Filter, src: &[u8]) -> Vec<u8> {
    let n = src.len();
    let mut out = src.to_vec();
    match f.kind {
        FilterKind::Delta(channels) => {
            let mut s = 0;
            for c in 0..usize::from(channels) {
                let mut acc = 0u8;
                let mut j = c;
                while j < n {
                    acc = acc.wrapping_sub(src[s]);
                    out[j] = acc;
                    s += 1;
                    j += usize::from(channels);
                }
            }
        }
        FilterKind::E8 | FilterKind::E8E9 => {
            let mut j = 0;
            while j + 4 < n {
                if src[j] == 0xe8 || (f.kind == FilterKind::E8E9 && src[j] == 0xe9) {
                    let p = j + 1;
                    let pos = ((f.start + p as u64) % 0x100_0000) as u32;
                    let a = u32::from_le_bytes(src[p..p + 4].try_into().unwrap());
                    if a & 0x8000_0000 != 0 {
                        if a.wrapping_add(pos) & 0x8000_0000 == 0 {
                            out[p..p + 4].copy_from_slice(&a.wrapping_add(0x100_0000).to_le_bytes());
                        }
                    } else if a < 0x100_0000 {
                        out[p..p + 4].copy_from_slice(&a.wrapping_sub(pos).to_le_bytes());
                    }
                    j = p + 4;
                } else {
                    j += 1;
                }
            }
        }
        FilterKind::Arm => {
            let mut j = 0;
            while j + 3 < n {
                if src[j + 3] == 0xeb {
                    let v = u32::from_le_bytes(src[j..j + 4].try_into().unwrap()) & 0x00ff_ffff;
                    let q = ((f.start + j as u64) / 4) as u32;
                    let v = (v.wrapping_sub(q) & 0x00ff_ffff) | 0xeb00_0000;
                    out[j..j + 4].copy_from_slice(&v.to_le_bytes());
                }
                j += 4;
            }
        }
    }
    out
}

#[test]
fn filters_in_place_match_the_byte_at_a_time_reading() {
    // bytes heavy in opcodes and small addresses, at every length near the scan's word size
    let mut x = 5u64;
    let mut data = Vec::new();
    for _ in 0..20_000 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let r = (x >> 24) as u32;
        data.push(match r % 7 {
            0 => 0xe8,
            1 => 0xe9,
            2 => 0xeb,
            3 => 0,
            4 => 0xff,
            _ => (r >> 8) as u8,
        });
    }
    let kinds = [FilterKind::E8, FilterKind::E8E9, FilterKind::Arm, FilterKind::Delta(1), FilterKind::Delta(3)];
    let mut spare = Vec::new();
    for kind in kinds {
        for start in [0u64, 1, 0xff_fff0, 7_000_001] {
            for len in (0..40).chain([255, 256, 257, 4097, 20_000]) {
                let f = Filter { start, len: len as u64, kind };
                let src = &data[data.len() - len..];
                let mut got = src.to_vec();
                apply_filter(f, &mut got, &mut spare);
                assert!(got == filter_reference(f, src), "{kind:?} start {start} len {len}");
            }
        }
    }
}

#[test]
fn match_copies_equal_a_byte_at_a_time_and_touch_nothing_else() {
    let size = 4096usize;
    let mask = size as u64 - 1;
    let mut x = 9u64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let base: Vec<u8> = (0..size).map(|_| next() as u8).collect();
    for len in (2..70).chain([100, 255, 300]) {
        for _ in 0..400 {
            // the second time round the window, so a match may reach a whole window back
            let sp = size as u64 + next() % size as u64;
            let dist = match next() % 6 {
                0 => 1 + next() % 8,
                1 => 1 + next() % u64::from(len),
                2 => size as u64 - next() % 40,
                _ => 1 + next() % size as u64,
            };
            let mut got = base.clone();
            copy(Win::of(&mut got), sp, len, dist, sp + u64::from(len)).unwrap();
            let mut want = base.clone();
            for i in 0..u64::from(len) {
                want[((sp + i) & mask) as usize] = want[((sp + i - dist) & mask) as usize];
            }
            assert!(got == want, "len {len} dist {dist} at {}", sp & mask);
        }
    }
}

#[test]
fn packed_tokens_come_back_as_they_went_in() {
    let toks = [
        Tok::Lits(0),
        Tok::Lits(u32::MAX),
        Tok::Last,
        Tok::Rep { k: 0, len: 2 },
        Tok::Rep { k: 3, len: 4097 },
        Tok::Match { len: 2, dist: 1 },
        Tok::Match { len: 4100, dist: (1 << 33) - 1 },
        Tok::Filter { offset: 0, len: 4, kind: FilterKind::E8 },
        Tok::Filter { offset: u64::MAX, len: MAX_FILTER_LEN, kind: FilterKind::Delta(32) },
        Tok::Filter { offset: 7, len: 9, kind: FilterKind::Arm },
    ];
    let mut filters = Vec::new();
    let packed: Vec<Packed> = toks.iter().map(|&t| Packed::new(t, &mut filters)).collect();
    for (t, p) in toks.iter().zip(&packed) {
        assert_eq!(format!("{t:?}"), format!("{:?}", p.get(&filters)));
    }
}

#[test]
fn filter_records_count_against_a_workers_budget() {
    // nothing but filter records, a few bytes each packed: their fields, kept beside the tokens, overrun a worker's
    // budget for this many packed bytes
    let ops: Vec<Op> = (0..300_000u64).map(|i| Op::Filter { start: 4 * i, len: 4, kind: 1, channels: 0 }).collect();
    let stream = block(&ops, true, true);
    // the calling thread finds too many pending, as it would have decoding them itself
    let err = decode(&stream, 1 << 20, 1 << 20, usize::MAX).unwrap_err();
    assert_eq!(err.to_string(), corrupt("too many filters").to_string());
    // a worker reading the block stops at its budget
    let (header_len, payload, flags) = block_header(&stream).unwrap().unwrap();
    let mut buf = stream[header_len..header_len + payload].to_vec();
    buf.resize(payload + PAD, 0);
    let end_bits = (payload - 1) * 8 + usize::from(flags & 7) + 1;
    let mut bits = Bits::new(&buf);
    let lens = read_lengths(&mut Huff::new(), &mut bits, end_bits).unwrap();
    let mut t = Tables::empty();
    t.build(&lens).unwrap();
    let (mut toks, mut filters, mut lits) = (Vec::new(), Vec::new(), Vec::new());
    let budget = payload * parallel::BUDGET + (1 << 20);
    let stop = parallel::tokenize(&buf, bits.pos(), end_bits, &t, (&mut toks, &mut filters, &mut lits), budget);
    assert!(matches!(stop, Ok(Some(_))), "{:?} with {} filters read", stop.map(|_| ()), filters.len());
    assert!(filters.len() < ops.len());
}
