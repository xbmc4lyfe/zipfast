//! Times the RAR 5.0 decoder on a stream made from a local file by the test encoder.
//! `cargo run --release --example decode_bench -- <input> [window_log2] [runs]`
//! The encoded stream is cached next to the input as `<input>.w<window_log2>.r5s`, one per window size, since a
//! stream made for a big window may reach back farther than a smaller one allows.

use std::time::Instant;
use zipfast::rar5::testenc::{lz, tuned_stream};
use zipfast::rar5::unpack::Unpacker;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let input = &args[1];
    let wlog: u32 = args.get(2).map_or(22, |s| s.parse().unwrap());
    let runs: usize = args.get(3).map_or(5, |s| s.parse().unwrap());
    let data = std::fs::read(input).unwrap();
    let cache = format!("{input}.w{wlog}.r5s");
    let stream = match std::fs::read(&cache) {
        Ok(s) => s,
        Err(_) => {
            let t = Instant::now();
            let ops = lz(&data, 1 << wlog, 16);
            let s = tuned_stream(&ops, 1 << 18);
            eprintln!("encoded {} -> {} bytes in {:.1?}", data.len(), s.len(), t.elapsed());
            std::fs::write(&cache, &s).unwrap();
            s
        }
    };
    let mut best = f64::MAX;
    for _ in 0..runs {
        let mut u = Unpacker::new(1 << wlog).unwrap();
        u.reset(Some(data.len() as u64));
        let mut crc = crc32fast::Hasher::new();
        let mut n = 0usize;
        let t = Instant::now();
        let mut sink = |b: &[u8]| {
            n += b.len();
            crc.update(b);
            Ok(())
        };
        for chunk in stream.chunks(1 << 20) {
            u.feed(chunk, &mut sink).unwrap();
        }
        u.finish(&mut sink).unwrap();
        let s = t.elapsed().as_secs_f64();
        assert_eq!(n, data.len());
        assert_eq!(crc.finalize(), crc32fast::hash(&data));
        best = best.min(s);
    }
    println!(
        "{input}: {} MB, packed {:.1}%, best {:.3}s, {:.0} MB/s",
        data.len() >> 20,
        100.0 * stream.len() as f64 / data.len() as f64,
        best,
        data.len() as f64 / best / 1e6
    );
}
