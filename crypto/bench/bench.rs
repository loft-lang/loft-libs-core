// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// crypto-reference — the pure-Rust twin of the `crypto` package's performance pass
// (bench/bench.loft), one file built with `rustc -O`.  It computes the SAME workloads with
// the SAME algorithms, in the same order, and prints the same rows, hash included: a row
// whose hash matches the loft build's is a like-for-like comparison, and only then is a
// routine's loft time judged against it (@FR-Perf-Weight).  No dependencies and no
// cleverness — plain idiomatic Rust.
//
//     rustc -O --edition=2021 bench/bench.rs -o bench/.build/stats_rs && bench/.build/stats_rs --n 2
//
// The loft rows cross into the package's native crate (native/src); this twin carries the
// same code and calls it directly, with no crossing: SHA-256 (FIPS 180-4) as in
// native/src/sha256.rs, the hex rendering of native/src/lib.rs `cr_hex`, and the base64
// encoder and decoder of native/src/base64.rs.  So a row's ratio is the boundary: the text
// copies around `sha256`, and the store-owned `vector<u8>` `base64_to_bytes` allocates.
// `black_box` guards each op's INPUT (the repetition number, the input texts) and the sink —
// never anything inside a kernel.
use std::fmt::Write;
use std::hint::black_box;
use std::time::Instant;

const FNV_OFFSET: i64 = 2166136261;
const FNV_PRIME: i64 = 16777619;

const SMALL_MSGS: usize = 64;
const SMALL_CALLS: i64 = 50000;
const BIG_BYTES: i64 = 1048576;
const B64_INPUTS: usize = 16;
const B64_PAYLOAD: i64 = 4096;
const DECODES: i64 = 1000;

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

fn fnv_bytes(h0: i64, v: &[u8]) -> i64 {
    let mut h = h0;
    for &b in v {
        h = ((h ^ i64::from(b)) * FNV_PRIME) & 0xFFFF_FFFF;
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
}

// ── native/src/sha256.rs ────────────────────────────────────────────

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut result = [0u8; 32];
    for (i, val) in h.iter().enumerate() {
        result[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
    }
    result
}

/// native/src/lib.rs `cr_hex`: lower-case hex of each byte.
fn hex(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// `crypto::sha256`: the hex digest of a text's bytes.
fn sha256_hex(data: &str) -> String {
    hex(&sha256(data.as_bytes()))
}

// ── native/src/base64.rs ────────────────────────────────────────────

const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 { u32::from(chunk[1]) } else { 0 };
        let b2 = if chunk.len() > 2 { u32::from(chunk[2]) } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((n >> 18) & 63) as usize] as char);
        result.push(CHARS[((n >> 12) & 63) as usize] as char);
        result.push(if chunk.len() > 1 { CHARS[((n >> 6) & 63) as usize] as char } else { '=' });
        result.push(if chunk.len() > 2 { CHARS[(n & 63) as usize] as char } else { '=' });
    }
    result
}

fn b64_decode(input: &str) -> Vec<u8> {
    fn val(c: u8) -> u8 {
        match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => 0,
        }
    }
    let bytes: Vec<u8> = input.bytes().filter(|b| *b != b'=' && *b != b'\n').collect();
    let mut result = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        if chunk.len() < 2 {
            break;
        }
        let n = u32::from(val(chunk[0])) << 18
            | u32::from(val(chunk[1])) << 12
            | if chunk.len() > 2 { u32::from(val(chunk[2])) << 6 } else { 0 }
            | if chunk.len() > 3 { u32::from(val(chunk[3])) } else { 0 };
        result.push((n >> 16) as u8);
        if chunk.len() > 2 {
            result.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            result.push(n as u8);
        }
    }
    result
}

// ── The rows ────────────────────────────────────────────────────────

fn small_msgs() -> Vec<String> {
    (0..SMALL_MSGS as i64)
        .map(|j| (0..64i64).map(|k| (97 + (j * 7 + k * 13) % 26) as u8 as char).collect())
        .collect()
}

fn small_op(msgs: &[String], r: i64) -> i64 {
    let mut acc = 0i64;
    for i in 0..SMALL_CALLS {
        let d = sha256_hex(&msgs[((i + r) & 63) as usize]);
        acc += i64::from(d.as_bytes()[(i & 63) as usize]);
    }
    acc
}

fn bench_sha256_small(n: i64) -> Row {
    let msgs = small_msgs();
    let t0 = Instant::now();
    let mut sink = 0i64;
    for r in 0..n {
        sink += small_op(black_box(&msgs), black_box(r));
    }
    let us = t0.elapsed().as_micros() as i64;
    let mut h = FNV_OFFSET;
    for m in &msgs {
        h = fnv_bytes(h, sha256_hex(m).as_bytes());
    }
    let one = small_op(black_box(&msgs), black_box(0));
    Row { name: "sha256_small", iters: n, us, px: SMALL_CALLS, hash: fnv(h, &[one]), sink: black_box(sink) }
}

fn big_text(salt: i64) -> String {
    let mut t: String = (0..1024i64).map(|k| (32 + (k * 37 + salt * 11) % 95) as u8 as char).collect();
    for _ in 0..10 {
        t = t.repeat(2);
    }
    t
}

fn bench_sha256_1m(n: i64) -> Row {
    let inputs = [big_text(0), big_text(1)];
    let t0 = Instant::now();
    let mut sink = 0i64;
    for r in 0..n {
        let r = black_box(r);
        let d = sha256_hex(black_box(&inputs[(r & 1) as usize]));
        sink += i64::from(d.as_bytes()[(r & 63) as usize]);
    }
    let us = t0.elapsed().as_micros() as i64;
    let mut h = fnv_bytes(FNV_OFFSET, sha256_hex(&inputs[0]).as_bytes());
    h = fnv_bytes(h, sha256_hex(&inputs[1]).as_bytes());
    Row { name: "sha256_1m", iters: n, us, px: BIG_BYTES, hash: fnv(h, &[inputs[0].len() as i64]),
          sink: black_box(sink) }
}

fn b64_inputs() -> Vec<String> {
    (0..B64_INPUTS as i64)
        .map(|j| {
            let p: Vec<u8> = (0..B64_PAYLOAD).map(|k| ((k * 31 + j * 17 + (k >> 8) * 5) & 255) as u8).collect();
            b64_encode(&p)
        })
        .collect()
}

fn b64_op(ins: &[String], r: i64) -> i64 {
    let mut acc = 0i64;
    for i in 0..DECODES {
        let v = b64_decode(&ins[((i + r) & 15) as usize]);
        acc += v.len() as i64 + i64::from(v[((i * 7) & 4095) as usize]);
    }
    acc
}

fn bench_base64_to_bytes(n: i64) -> Row {
    let ins = b64_inputs();
    let t0 = Instant::now();
    let mut sink = 0i64;
    for r in 0..n {
        sink += b64_op(black_box(&ins), black_box(r));
    }
    let us = t0.elapsed().as_micros() as i64;
    let mut h = FNV_OFFSET;
    for s in &ins {
        h = fnv_bytes(h, &b64_decode(s));
    }
    let one = b64_op(black_box(&ins), black_box(0));
    Row { name: "base64_to_bytes", iters: n, us, px: DECODES, hash: fnv(h, &[one]), sink: black_box(sink) }
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
    let t0 = Instant::now();
    println!("routine\titers\tus\tns_op\tpx\tns_px\thash");
    let rows = [bench_sha256_small(n), bench_sha256_1m(n), bench_base64_to_bytes(n)];
    let mut sink = 0i64;
    for row in &rows {
        print_row(row);
        sink = sink.wrapping_add(row.sink);
    }
    println!("time: {}ms sink={}", t0.elapsed().as_millis(), sink);
}
