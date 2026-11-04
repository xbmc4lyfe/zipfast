//! Round trips through a small test-only encoder that writes blocks with fixed code lengths.

use super::*;
use crate::rar5::testenc::*;

/// Decodes on the calling thread and on workers, and checks both give the same output or the same error.
fn decode(stream: &[u8], size: u64, window: u64, piece: usize) -> Result<Vec<u8>> {
    let serial = decode_with(stream, size, window, piece, 0);
    let parallel = decode_with(stream, size, window, piece, 3);
    match (&serial, &parallel) {
        (Ok(a), Ok(b)) => assert!(a == b, "workers decoded different bytes"),
        (Err(a), Err(b)) => assert_eq!(a.to_string(), b.to_string(), "workers failed differently"),
        _ => {
            panic!("serial {:?} vs workers {:?}", serial.as_ref().map(|v| v.len()), parallel.as_ref().map(|v| v.len()))
        }
    }
    serial
}

fn decode_with(stream: &[u8], size: u64, window: u64, piece: usize, threads: usize) -> Result<Vec<u8>> {
    let mut u = Unpacker::new(window)?;
    u.set_threads(threads, 0);
    u.reset(Some(size));
    let mut out = Vec::new();
    let mut sink = |b: &[u8]| -> Result<()> {
        out.extend_from_slice(b);
        Ok(())
    };
    for chunk in stream.chunks(piece.max(1)) {
        u.feed(chunk, &mut sink)?;
    }
    u.finish(&mut sink)?;
    Ok(out)
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
    // nine-bit codes that each stand for a 24-byte token: far past a worker's budget for this many packed bytes
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
    ops.extend(std::iter::repeat_n(Op::Last, 150_000));
    let mut stream = block(&ops, true, false);
    assert!(stream.len() < JOB_BYTES);
    let mut all = ops;
    let tail = lits(b"no tables here");
    stream.extend(block(&tail, false, false));
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
