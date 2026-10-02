// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// cbor-reference — the pure-Rust twin of the `cbor` package's performance pass
// (bench/bench.loft), one file built with `rustc -O`.  It computes the SAME workloads with
// the SAME algorithm, in the same order, and prints the same rows, hash included: a row
// whose hash matches the loft build's is a like-for-like comparison, and only then is a
// routine's loft time judged against it (@FR-Perf-Weight).  No dependencies and no
// cleverness — plain idiomatic Rust, the speed an industry implementation reaches without
// effort, which is exactly what the bar should be.
//
//     rustc -O --edition=2021 bench/bench.rs -o bench/.build/stats_rs && bench/.build/stats_rs --n 2
//
// A port of src/cbor.loft: shortest-form heads, the canonical map order (each key encoded
// ONCE into a flat buffer, ranked by an O(n^2) bytewise compare with the index breaking
// ties, entries emitted in ascending rank), and a recursive-descent decoder that enforces
// shortest-form heads.  The idiom differs where Rust's differs: the encoder writes into one
// growing buffer instead of returning a vector per head and per node, a text payload is
// one `extend_from_slice`, and the decoder returns `Option<(Value, usize)>`.
// `black_box` guards each op's INPUT and the sink — never anything inside a kernel.
use std::hint::black_box;
use std::time::Instant;

const FNV_OFFSET: i64 = 2166136261;
const FNV_PRIME: i64 = 16777619;

const ENC_REPS: i64 = 1000;
const TEXTS: i64 = 64;
const TEXT_BYTES: i64 = 256;
const BYTES_REPS: i64 = 100;
const DEC_MAP_REPS: i64 = 400;
const ARR_INTS: i64 = 4096;
const DEC_ARR_REPS: i64 = 40;

fn fnv_byte(h: i64, b: i64) -> i64 {
    ((h ^ (b & 255)) * FNV_PRIME) & 0xFFFF_FFFF
}

fn fnv_int(h0: i64, x: i64) -> i64 {
    let mut h = h0;
    for s in 0..8 {
        h = fnv_byte(h, x >> (56 - s * 8));
    }
    h
}

fn fnv_bytes(h0: i64, v: &[u8]) -> i64 {
    v.iter().fold(h0, |h, &b| fnv_byte(h, b as i64))
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

// ── the codec ───────────────────────────────────────────────────────

#[derive(Clone, Debug)]
enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
}

/// The shortest-form head of `major` with argument `arg` (RFC 8949 §4.2.1).
fn head(buf: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    if arg < 24 {
        buf.push(m | arg as u8);
    } else if arg < 256 {
        buf.push(m | 24);
        buf.push(arg as u8);
    } else if arg < 65536 {
        buf.push(m | 25);
        buf.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg < 4294967296 {
        buf.push(m | 26);
        buf.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        buf.push(m | 27);
        buf.extend_from_slice(&arg.to_be_bytes());
    }
}

fn encode_map(buf: &mut Vec<u8>, entries: &[(Value, Value)]) {
    let n = entries.len();
    head(buf, 5, n as u64);
    // each key encoded once into a flat buffer, with its offset and length
    let mut keybuf = Vec::new();
    let mut spans = Vec::with_capacity(n);
    for (k, _) in entries {
        let start = keybuf.len();
        encode_into(&mut keybuf, k);
        spans.push(start..keybuf.len());
    }
    // rank[i] = how many keys sort strictly before key i (the index breaks ties)
    let key = |i: usize| &keybuf[spans[i].clone()];
    let ranks: Vec<usize> = (0..n)
        .map(|i| (0..n).filter(|&j| j != i && (key(j) < key(i) || (j < i && key(j) == key(i)))).count())
        .collect();
    // entries in ascending rank
    for target in 0..n {
        for i in 0..n {
            if ranks[i] == target {
                buf.extend_from_slice(key(i));
                encode_into(buf, &entries[i].1);
            }
        }
    }
}

fn encode_into(buf: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Null => head(buf, 7, 22),
        Value::Bool(b) => head(buf, 7, if *b { 21 } else { 20 }),
        Value::Int(x) => {
            if *x >= 0 {
                head(buf, 0, *x as u64)
            } else {
                head(buf, 1, (-1 - *x) as u64)
            }
        }
        Value::Bytes(b) => {
            head(buf, 2, b.len() as u64);
            buf.extend_from_slice(b);
        }
        Value::Text(t) => {
            head(buf, 3, t.len() as u64);
            buf.extend_from_slice(t.as_bytes());
        }
        Value::Array(items) => {
            head(buf, 4, items.len() as u64);
            for it in items {
                encode_into(buf, it);
            }
        }
        Value::Map(entries) => encode_map(buf, entries),
    }
}

fn encode(v: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_into(&mut buf, v);
    buf
}

/// One value at `pos`: the value and the position just past it, or None on malformed,
/// non-canonical or truncated input.
fn read_value(bytes: &[u8], pos: usize) -> Option<(Value, usize)> {
    let b = *bytes.get(pos)?;
    let major = b >> 5;
    let info = b & 31;
    let rest = &bytes[pos + 1..];
    let (arg, width): (u64, usize) = match info {
        0..=23 => (info as u64, 0),
        24 => {
            let a = *rest.first()? as u64;
            if a < 24 {
                return None;
            }
            (a, 1)
        }
        25 => {
            let a = u16::from_be_bytes(rest.get(..2)?.try_into().ok()?) as u64;
            if a < 256 {
                return None;
            }
            (a, 2)
        }
        26 => {
            let a = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as u64;
            if a < 65536 {
                return None;
            }
            (a, 4)
        }
        27 => {
            let a = u64::from_be_bytes(rest.get(..8)?.try_into().ok()?);
            if a >= 1 << 63 || a < 4294967296 {
                return None;
            }
            (a, 8)
        }
        _ => return None,
    };
    let p = pos + 1 + width;
    match major {
        0 => Some((Value::Int(arg as i64), p)),
        1 => Some((Value::Int(-1 - arg as i64), p)),
        2 => {
            let end = p.checked_add(arg as usize).filter(|&e| e <= bytes.len())?;
            Some((Value::Bytes(bytes[p..end].to_vec()), end))
        }
        3 => {
            let end = p.checked_add(arg as usize).filter(|&e| e <= bytes.len())?;
            Some((Value::Text(String::from_utf8_lossy(&bytes[p..end]).into_owned()), end))
        }
        4 => {
            let mut items = Vec::new();
            let mut q = p;
            for _ in 0..arg {
                let (v, next) = read_value(bytes, q)?;
                items.push(v);
                q = next;
            }
            Some((Value::Array(items), q))
        }
        5 => {
            let mut entries = Vec::new();
            let mut q = p;
            for _ in 0..arg {
                let (k, kn) = read_value(bytes, q)?;
                let (v, vn) = read_value(bytes, kn)?;
                entries.push((k, v));
                q = vn;
            }
            Some((Value::Map(entries), q))
        }
        7 => match info {
            20 => Some((Value::Bool(false), p)),
            21 => Some((Value::Bool(true), p)),
            22 => Some((Value::Null, p)),
            _ => None,
        },
        _ => None,
    }
}

/// The whole buffer as one value: `(value, next, ok)` as the library's `Decoded` carries it.
fn decode(bytes: &[u8]) -> (Value, usize, bool) {
    match read_value(bytes, 0) {
        Some((v, next)) if next == bytes.len() => (v, next, true),
        Some((_, next)) => (Value::Null, next, false),
        None => (Value::Null, 0, false),
    }
}

fn fnv_value(h0: i64, v: &Value) -> i64 {
    match v {
        Value::Null => fnv_byte(h0, 0),
        Value::Bool(b) => fnv_byte(fnv_byte(h0, 1), *b as i64),
        Value::Int(x) => fnv_int(fnv_byte(h0, 2), *x),
        Value::Bytes(b) => fnv_bytes(fnv_int(fnv_byte(h0, 3), b.len() as i64), b),
        Value::Text(t) => fnv_bytes(fnv_int(fnv_byte(h0, 4), t.len() as i64), t.as_bytes()),
        Value::Array(items) => {
            items.iter().fold(fnv_int(fnv_byte(h0, 5), items.len() as i64), fnv_value)
        }
        Value::Map(entries) => entries
            .iter()
            .fold(fnv_int(fnv_byte(h0, 6), entries.len() as i64), |h, (k, v)| {
                fnv_value(fnv_value(h, k), v)
            }),
    }
}

// ── the workloads ───────────────────────────────────────────────────

fn entry(k: &str, v: Value) -> (Value, Value) {
    (Value::Text(k.to_string()), v)
}

fn make_map(r: i64) -> Value {
    let s = r & 1;
    let nested = (0..8).map(|i| 7 - i).map(|k| entry(&format!("n{k}"), Value::Int(k * 1000 + s))).collect();
    let payload = (0..16).map(|j| ((j * 29 + s) & 255) as u8).collect();
    Value::Map(vec![
        entry("zeta", Value::Int(1000000 + s)),
        entry("id", Value::Int(42 + s)),
        entry("alpha", Value::Text(format!("hello world {s}"))),
        entry("name", Value::Text("cbor-bench".to_string())),
        entry("b", Value::Bool(s == 0)),
        entry("count", Value::Int(300 + s)),
        entry(
            "tags",
            Value::Array(vec![Value::Text("a".into()), Value::Text("bb".into()), Value::Int(7 + s)]),
        ),
        entry("payload", Value::Bytes(payload)),
        entry("big", Value::Int(5000000000 + s)),
        entry("none", Value::Null),
        entry("neg", Value::Int(-5000 - s)),
        entry("nested", Value::Map(nested)),
    ])
}

fn make_texts(r: i64) -> Value {
    Value::Array(
        (0..TEXTS)
            .map(|i| {
                let b: Vec<u8> = (0..TEXT_BYTES).map(|j| (97 + (i * 7 + j + (r & 1)) % 26) as u8).collect();
                Value::Text(String::from_utf8(b).unwrap())
            })
            .collect(),
    )
}

fn make_ints(r: i64) -> Value {
    Value::Array(
        (0..ARR_INTS)
            .map(|i| {
                let v = (i * 7919 + (r & 1)) % 70000;
                Value::Int(if i & 1 == 1 { -1 - v } else { v })
            })
            .collect(),
    )
}

fn encode_op(r: i64) -> i64 {
    let m = make_map(r);
    let mut sink = 0i64;
    for k in 0..ENC_REPS {
        let out = encode(black_box(&m));
        sink += out.len() as i64 + out[(k & 31) as usize] as i64;
    }
    sink
}

fn bytes_op(r: i64) -> i64 {
    let v = make_texts(r);
    let mut sink = 0i64;
    for k in 0..BYTES_REPS {
        let out = encode(black_box(&v));
        sink += out.len() as i64 + out[(k & 1023) as usize] as i64;
    }
    sink
}

fn decode_op(r: i64) -> i64 {
    let map = encode(&make_map(r));
    let arr = encode(&make_ints(r));
    let mut sink = 0i64;
    for _ in 0..DEC_MAP_REPS {
        sink += decode(black_box(&map)).1 as i64;
    }
    for _ in 0..DEC_ARR_REPS {
        sink += decode(black_box(&arr)).1 as i64;
    }
    sink
}

fn decode_hash() -> i64 {
    let (av, an, aok) = decode(&encode(&make_map(0)));
    let (bv, bn, bok) = decode(&encode(&make_ints(0)));
    let mut h = fnv_value(FNV_OFFSET, &av);
    h = fnv_int(fnv_byte(h, aok as i64), an as i64);
    h = fnv_value(h, &bv);
    fnv_int(fnv_byte(h, bok as i64), bn as i64)
}

fn timed<F: FnMut(i64) -> i64>(n: i64, mut f: F) -> (i64, i64) {
    let t0 = Instant::now();
    let mut sink = 0i64;
    for r in 0..n {
        sink = sink.wrapping_add(f(black_box(r)));
    }
    (t0.elapsed().as_micros() as i64, black_box(sink))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut n = 20i64;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--n" && i + 1 < args.len() {
            n = args[i + 1].parse().unwrap_or(0);
            i += 1;
        }
        i += 1;
    }
    if n < 1 {
        n = 1;
    }
    let t0 = Instant::now();
    println!("routine\titers\tus\tns_op\tpx\tns_px\thash");
    let (us, sink) = timed(n, encode_op);
    let r1 = Row { name: "encode", iters: n, us, px: ENC_REPS, hash: fnv_bytes(FNV_OFFSET, &encode(&make_map(0))), sink };
    let (us, sink) = timed(n, bytes_op);
    let r2 = Row {
        name: "encode_bytes",
        iters: n,
        us,
        px: BYTES_REPS * TEXTS * TEXT_BYTES,
        hash: fnv_bytes(FNV_OFFSET, &encode(&make_texts(0))),
        sink,
    };
    let (us, sink) = timed(n, decode_op);
    let r3 = Row {
        name: "decode",
        iters: n,
        us,
        px: DEC_MAP_REPS * 44 + DEC_ARR_REPS * (ARR_INTS + 1),
        hash: decode_hash(),
        sink,
    };
    let mut total = 0i64;
    for row in [&r1, &r2, &r3] {
        print_row(row);
        total += row.sink;
    }
    println!("time: {}ms sink={}", t0.elapsed().as_millis(), total);
}
