// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// random-reference — the pure-Rust twin of the `random` package's performance pass
// (bench/bench.loft), one file, std only, built with `rustc -O`.  It computes the SAME
// workloads with the SAME arithmetic, in the same order, and prints the same rows, hash
// included: a row whose hash matches the loft build's is a like-for-like comparison.
//
//     rustc -O --edition=2021 bench/bench.rs -o bench/.build/stats_rs && bench/.build/stats_rs --n 50
//
// `rand` and `rand_indices` port the native crate (native/src/lib.rs): `rand_pcg`'s Pcg64
// (a 128-bit LCG with the XSL-RR output), seeded through `rand_core`'s `seed_from_u64`,
// reduced with `%` exactly as the crate reduces it.  Here the generator is an owned value
// called directly, so the loft/Rust ratio of those rows is the cost of the crossing.
// `get` and `indices` port the RandStream in src/random.loft: L'Ecuyer's combined LCG by
// Schrage's method, and Fisher-Yates over it.
use std::hint::black_box;
use std::time::Instant;

const FNV_OFFSET: i64 = 2166136261;
const FNV_PRIME: i64 = 16777619;

const DRAWS: i64 = 1_000_000;
const CALLS: i64 = 100;
const SHUFFLE_N: i64 = 4096;

fn fnv(h0: i64, v: &[i64]) -> i64 {
    let mut h = h0;
    for &x in v {
        let w = x & 0xFFFF_FFFF;
        for sh in [24, 16, 8, 0] {
            h = ((h ^ ((w >> sh) & 255)) * FNV_PRIME) & 0xFFFF_FFFF;
        }
    }
    h
}

struct Row {
    name: &'static str,
    iters: i64,
    us: i64,
    px: i64,
    hash: i64,
    sink: i64,
}

fn print_row(r: &Row) {
    let ns_op = r.us * 1000 / r.iters;
    let ns_px = if r.px > 0 { (r.us * 1000) as f64 / (r.iters * r.px) as f64 } else { 0.0 };
    println!("{}\t{}\t{}\t{}\t{}\t{:.3}\t{:x}", r.name, r.iters, r.us, ns_op, r.px, ns_px, r.hash);
    if r.sink == i64::MIN {
        println!("(unreachable — keeps the sink alive)");
    }
}

fn timed<F: FnMut(i64) -> i64>(n: i64, mut f: F) -> (i64, i64) {
    let t0 = Instant::now();
    let mut sink = 0i64;
    for r in 0..n {
        sink = sink.wrapping_add(f(black_box(r & 1)));
    }
    (t0.elapsed().as_micros() as i64, black_box(sink))
}

// ── rand_pcg 0.9: Pcg64 = Lcg128Xsl64 ───────────────────────────────

const MULTIPLIER: u128 = 0x2360_ED05_1FC6_5DA4_4385_DF64_9FCC_F645;

struct Pcg64 {
    state: u128,
    increment: u128,
}

impl Pcg64 {
    /// `rand_core::SeedableRng::seed_from_u64`: a PCG32 expands the seed into 32 bytes,
    /// which `Lcg128Xsl64::from_seed` reads as state and increment (little-endian).
    fn seed_from_u64(mut state: u64) -> Pcg64 {
        const MUL: u64 = 6364136223846793005;
        const INC: u64 = 11634580027462260723;
        let mut seed = [0u8; 32];
        for chunk in seed.chunks_exact_mut(4) {
            state = state.wrapping_mul(MUL).wrapping_add(INC);
            let s = state;
            let xorshifted = (((s >> 18) ^ s) >> 27) as u32;
            let rot = (s >> 59) as u32;
            chunk.copy_from_slice(&xorshifted.rotate_right(rot).to_le_bytes());
        }
        let mut w = [0u64; 4];
        for (i, c) in seed.chunks_exact(8).enumerate() {
            w[i] = u64::from_le_bytes(c.try_into().unwrap());
        }
        let st = u128::from(w[0]) | (u128::from(w[1]) << 64);
        let incr = u128::from(w[2]) | (u128::from(w[3]) << 64);
        let mut pcg = Pcg64 { state: st, increment: incr | 1 };
        pcg.state = pcg.state.wrapping_add(pcg.increment);
        pcg.step();
        pcg
    }

    #[inline]
    fn step(&mut self) {
        self.state = self.state.wrapping_mul(MULTIPLIER).wrapping_add(self.increment);
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.step();
        let rot = (self.state >> 122) as u32;
        let xsl = ((self.state >> 64) as u64) ^ (self.state as u64);
        xsl.rotate_right(rot)
    }
}

/// The crate's `n_rand`, minus the crossing.
#[inline]
fn rand(rng: &mut Pcg64, lo: i64, hi: i64) -> i64 {
    if lo == i64::MIN || hi == i64::MIN || lo > hi {
        return i64::MIN;
    }
    let range = (hi - lo + 1) as u64;
    lo + (rng.next_u64() % range) as i64
}

/// The crate's `n_rand_indices`, minus the crossing and the store copy.
fn rand_indices(rng: &mut Pcg64, n: i64) -> Vec<i64> {
    let count = if n == i64::MIN || n <= 0 { 0usize } else { n as usize };
    let mut indices: Vec<i64> = (0..count as i64).collect();
    for i in (1..indices.len()).rev() {
        let j = rng.next_u64() as usize % (i + 1);
        indices.swap(i, j);
    }
    indices
}

fn op_rand(salt: i64) -> (i64, i64) {
    let mut rng = Pcg64::seed_from_u64((1234 + salt) as u64);
    let mut sum = 0i64;
    let mut last = 0i64;
    for _ in 0..DRAWS {
        last = rand(&mut rng, 0, 999);
        sum += last;
    }
    (sum, last)
}

fn bench_rand(n: i64) -> Row {
    let (us, sink) = timed(n, |salt| {
        let (s, l) = op_rand(salt);
        s + l
    });
    let (s, l) = op_rand(0);
    Row { name: "rand", iters: n, us, px: DRAWS, hash: fnv(FNV_OFFSET, &[s, l]), sink }
}

fn op_rand_indices(salt: i64) -> i64 {
    let mut rng = Pcg64::seed_from_u64((5678 + salt) as u64);
    let mut acc = 0i64;
    let mut last: Vec<i64> = Vec::new();
    for c in 0..CALLS {
        last = rand_indices(&mut rng, black_box(SHUFFLE_N));
        acc += last[c as usize];
    }
    fnv(fnv(FNV_OFFSET, &last), &[acc])
}

fn bench_rand_indices(n: i64) -> Row {
    let (us, sink) = timed(n, op_rand_indices);
    Row { name: "rand_indices", iters: n, us, px: CALLS * SHUFFLE_N, hash: op_rand_indices(0), sink }
}

// ── src/random.loft: RandStream ─────────────────────────────────────

struct RandStream {
    s1: i64,
    s2: i64,
}

fn seed_stream(seed: i64) -> RandStream {
    let mut a = seed % 2147483562;
    if a < 0 {
        a = -a;
    }
    let mut t = seed % 2147483398;
    if t < 0 {
        t = -t;
    }
    let mix = ((a + 1) * 40014) % 2147483563;
    RandStream { s1: a + 1, s2: ((t + mix) % 2147483398) + 1 }
}

#[inline]
fn get(s: &mut RandStream, lo: i64, hi: i64) -> Option<i64> {
    if lo > hi {
        return None;
    }
    let k1 = s.s1 / 53668;
    let mut n1 = 40014 * (s.s1 - k1 * 53668) - k1 * 12211;
    if n1 < 0 {
        n1 += 2147483563;
    }
    let k2 = s.s2 / 52774;
    let mut n2 = 40692 * (s.s2 - k2 * 52774) - k2 * 3791;
    if n2 < 0 {
        n2 += 2147483399;
    }
    s.s1 = n1;
    s.s2 = n2;
    let mut z = (n1 - n2) % 2147483562;
    if z < 1 {
        z += 2147483562;
    }
    Some(lo + (z - 1) % (hi - lo + 1))
}

fn indices(s: &mut RandStream, n: i64) -> Vec<i64> {
    if n <= 0 {
        return Vec::new();
    }
    let mut out: Vec<i64> = (0..n).collect();
    let mut j = n - 1;
    while j > 0 {
        let k = get(s, 0, j).unwrap_or(0);
        out.swap(j as usize, k as usize);
        j -= 1;
    }
    out
}

fn op_get(salt: i64) -> i64 {
    let mut s = seed_stream(42 + salt);
    let mut sum = 0i64;
    for _ in 0..DRAWS {
        sum += get(&mut s, 0, 999).unwrap_or(0);
    }
    fnv(FNV_OFFSET, &[sum, s.s1, s.s2])
}

fn bench_get(n: i64) -> Row {
    let (us, sink) = timed(n, op_get);
    Row { name: "get", iters: n, us, px: DRAWS, hash: op_get(0), sink }
}

fn op_indices(salt: i64) -> i64 {
    let mut s = seed_stream(99 + salt);
    let mut acc = 0i64;
    let mut last: Vec<i64> = Vec::new();
    for c in 0..CALLS {
        last = indices(&mut s, black_box(SHUFFLE_N));
        acc += last[c as usize];
    }
    fnv(fnv(FNV_OFFSET, &last), &[acc])
}

fn bench_indices(n: i64) -> Row {
    let (us, sink) = timed(n, op_indices);
    Row { name: "indices", iters: n, us, px: CALLS * SHUFFLE_N, hash: op_indices(0), sink }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut n: i64 = 20;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--n" && i + 1 < args.len() {
            n = args[i + 1].parse().unwrap_or(20);
            i += 1;
        }
        i += 1;
    }
    if n < 1 {
        n = 1;
    }
    println!("routine\titers\tus\tns_op\tpx\tns_px\thash");
    print_row(&bench_rand(n));
    print_row(&bench_rand_indices(n));
    print_row(&bench_get(n));
    print_row(&bench_indices(n));
}
