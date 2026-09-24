// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// arguments-reference — the pure-Rust twin of the `arguments` package's performance pass
// (bench/bench.loft), one file built with `rustc -O`.  It computes the SAME workload with
// the SAME algorithm, in the same order, and prints the same row, hash included: a row
// whose hash matches the loft build's is a like-for-like comparison, and only then is a
// routine's loft time judged against it (@FR-Perf-Weight).  No dependencies and no
// cleverness — plain idiomatic Rust, the speed an industry implementation reaches without
// effort, which is exactly what the bar should be.
//
//     rustc -O --edition=2021 bench/bench.rs -o bench/.build/stats_rs && bench/.build/stats_rs --n 2
//
// A port of src/arguments.loft's `parse`: reset the results, lex argv into tokens against
// the option table (a linear scan with a text compare per option; for a long name the
// exact scan first, then a prefix scan that counts the candidates; the kind of an option
// found by the same full scan the library makes), then walk the tokens pairing a value
// option with the following word, and finally check the required options.  Tokens borrow
// from argv where the library copies; a stored value is an owned `String`, as it must be.
// `black_box` guards each op's INPUT and the sink — never anything inside a kernel.
use std::hint::black_box;
use std::time::Instant;

const FNV_OFFSET: i64 = 2166136261;
const FNV_PRIME: i64 = 16777619;

const PARSES: i64 = 2000;

const NAMES: &str = "verbose quiet output input format level color config dry-run force recursive jobs timeout retry log-file log-level user group mode prefix suffix exclude include depth follow size since until sort reverse width height encoding locale cache-dir no-cache threads seed profile trace";
const KINDS: &str = "FFVVVVOVFFFVVVVVVVOVVVVVFVVVOFVVVVVFVVOF";
const SHORTS: &str = "abcdefghijklmnopqrstuvwxyz";

fn fnv_byte(h: i64, b: i64) -> i64 {
    ((h ^ (b & 255)) * FNV_PRIME) & 0xFFFF_FFFF
}

fn fnv_text(h0: i64, t: &str) -> i64 {
    fnv_byte(t.bytes().fold(h0, |h, b| fnv_byte(h, b as i64)), 0)
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

// ── the parser ──────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Flag,
    Value,
    Optional,
}

struct Opt {
    short_name: String,
    long_name: String,
    kind: Kind,
    mandatory: bool,
}

struct Args {
    options: Vec<Opt>,
    results: Vec<Option<String>>,
    positionals: Vec<String>,
    err: String,
}

enum Tok<'a> {
    OptFlag(usize),
    NeedVal(usize),
    HasVal(usize, &'a str),
    Pos(&'a str),
    Bad(String),
}

const AMBIGUOUS: i64 = -2;

impl Args {
    fn new() -> Args {
        Args { options: Vec::new(), results: Vec::new(), positionals: Vec::new(), err: String::new() }
    }

    fn register(&mut self, s: &str, l: &str, kind: Kind, mandatory: bool) {
        self.options.push(Opt { short_name: s.to_string(), long_name: l.to_string(), kind, mandatory });
        self.results.push(None);
    }

    /// The index of a long option, allowing an unambiguous prefix; -1 unknown, -2 ambiguous.
    fn find_long_opt(&self, name: &str) -> i64 {
        if let Some(i) = self.options.iter().position(|o| o.long_name == name) {
            return i as i64;
        }
        let mut found = -1;
        let mut count = 0;
        for (i, o) in self.options.iter().enumerate() {
            if !o.long_name.is_empty() && o.long_name.starts_with(name) {
                found = i as i64;
                count += 1;
            }
        }
        match count {
            1 => found,
            0 => -1,
            _ => AMBIGUOUS,
        }
    }

    fn find_short_opt(&self, ch: char) -> i64 {
        let mut b = [0u8; 4];
        let ch = ch.encode_utf8(&mut b);
        self.options
            .iter()
            .position(|o| !o.short_name.is_empty() && o.short_name == *ch)
            .map_or(-1, |i| i as i64)
    }

    /// The library's `opt_kind`: a full scan for the entry at `idx`, the last match wins.
    fn opt_kind(&self, idx: i64) -> Kind {
        let mut k = Kind::Flag;
        for (i, o) in self.options.iter().enumerate() {
            if i as i64 == idx {
                k = o.kind;
            }
        }
        k
    }

    fn opt_label(&self, idx: usize) -> String {
        let o = &self.options[idx];
        if o.long_name.is_empty() { format!("-{}", o.short_name) } else { format!("--{}", o.long_name) }
    }

    fn ambiguous_matches(&self, name: &str) -> String {
        let v: Vec<String> = self
            .options
            .iter()
            .filter(|o| !o.long_name.is_empty() && o.long_name.starts_with(name))
            .map(|o| format!("'--{}'", o.long_name))
            .collect();
        v.join(", ")
    }

    fn classify<'a>(&self, argv: &'a [String]) -> Vec<Tok<'a>> {
        let mut toks = Vec::new();
        let mut past = false;
        for arg in argv {
            let arg = arg.as_str();
            if past {
                toks.push(Tok::Pos(arg));
            } else if arg == "--" {
                past = true;
            } else if arg == "-" {
                toks.push(Tok::Pos("-"));
            } else if let Some(body) = arg.strip_prefix("--") {
                match body.find('=') {
                    None => {
                        let li = self.find_long_opt(body);
                        if li == AMBIGUOUS {
                            toks.push(Tok::Bad(format!(
                                "option '--{body}' is ambiguous; candidates: {}",
                                self.ambiguous_matches(body)
                            )));
                        } else if li < 0 {
                            toks.push(Tok::Bad(format!("unrecognized option '--{body}'")));
                        } else {
                            toks.push(match self.opt_kind(li) {
                                Kind::Flag => Tok::OptFlag(li as usize),
                                Kind::Optional => Tok::HasVal(li as usize, ""),
                                Kind::Value => Tok::NeedVal(li as usize),
                            });
                        }
                    }
                    Some(eq) => {
                        let (lname, lval) = (&body[..eq], &body[eq + 1..]);
                        let li = self.find_long_opt(lname);
                        if li == AMBIGUOUS {
                            toks.push(Tok::Bad(format!(
                                "option '--{lname}' is ambiguous; candidates: {}",
                                self.ambiguous_matches(lname)
                            )));
                        } else if li < 0 {
                            toks.push(Tok::Bad(format!("unrecognized option '--{lname}'")));
                        } else if self.opt_kind(li) == Kind::Flag {
                            toks.push(Tok::Bad(format!("option '--{lname}' doesn't allow an argument")));
                        } else {
                            toks.push(Tok::HasVal(li as usize, lval));
                        }
                    }
                }
            } else if arg.chars().count() > 1 && arg.starts_with('-') {
                let cluster = &arg[1..];
                for (at, ch) in cluster.char_indices() {
                    let si = self.find_short_opt(ch);
                    if si < 0 {
                        toks.push(Tok::Bad(format!("invalid option -- '{ch}'")));
                        break;
                    }
                    if self.opt_kind(si) == Kind::Flag {
                        toks.push(Tok::OptFlag(si as usize));
                    } else {
                        let rest = &cluster[at + ch.len_utf8()..];
                        if !rest.is_empty() {
                            toks.push(Tok::HasVal(si as usize, rest));
                        } else if self.opt_kind(si) == Kind::Optional {
                            toks.push(Tok::HasVal(si as usize, ""));
                        } else {
                            toks.push(Tok::NeedVal(si as usize));
                        }
                        break;
                    }
                }
            } else {
                toks.push(Tok::Pos(arg));
            }
        }
        toks
    }

    fn parse(&mut self, argv: &[String]) -> bool {
        self.err.clear();
        self.positionals.clear();
        for r in self.results.iter_mut() {
            *r = None;
        }
        let toks = self.classify(argv);
        let mut pos = 0;
        let mut guard = 0;
        while pos < toks.len() {
            guard += 1;
            if guard > 1_000_000 {
                break;
            }
            match &toks[pos..] {
                [Tok::NeedVal(idx), Tok::Pos(word), ..] => {
                    self.results[*idx] = Some(word.to_string());
                    pos += 2;
                }
                [Tok::NeedVal(idx), ..] => {
                    self.err = format!("option '{}' requires an argument", self.opt_label(*idx));
                    return false;
                }
                [Tok::HasVal(idx, value), ..] => {
                    self.results[*idx] = Some(value.to_string());
                    pos += 1;
                }
                [Tok::OptFlag(idx), ..] => {
                    self.results[*idx] = Some("true".to_string());
                    pos += 1;
                }
                [Tok::Pos(word), ..] => {
                    self.positionals.push(word.to_string());
                    pos += 1;
                }
                [Tok::Bad(msg), ..] => {
                    self.err = msg.clone();
                    return false;
                }
                [] => break,
            }
        }
        for (i, o) in self.options.iter().enumerate() {
            if o.mandatory && self.results[i].is_none() {
                self.err = format!("option '{}' is required", self.opt_label(i));
                return false;
            }
        }
        true
    }

    fn get(&self, name: &str) -> Option<&str> {
        let i = self.options.iter().position(|o| o.long_name == name)?;
        self.results[i].as_deref()
    }
}

// ── the workload ────────────────────────────────────────────────────

fn make_args() -> Args {
    let mut a = Args::new();
    for (i, name) in NAMES.split(' ').enumerate() {
        let s = if i < 26 { &SHORTS[i..i + 1] } else { "" };
        match &KINDS[i..i + 1] {
            "F" => a.register(s, name, Kind::Flag, false),
            "O" => a.register(s, name, Kind::Optional, false),
            _ => a.register(s, name, Kind::Value, name == "format"),
        }
    }
    a
}

fn make_argv(r: i64) -> Vec<String> {
    let s = r & 1;
    vec![
        "--verbose".to_string(),
        "--output".to_string(),
        format!("out{s}.bin"),
        "--format=json".to_string(),
        "--thr".to_string(),
        format!("{}", 8 + s),
        "-ab".to_string(),
        format!("-l{}", 4 + s),
        "-m".to_string(),
        format!("3{s}"),
        format!("file{s}.txt"),
        "--color".to_string(),
        "--mode=fast".to_string(),
        "--recur".to_string(),
        format!("--enc=utf{}", 8 + s),
        "-kjy".to_string(),
        "--log-level".to_string(),
        "debug".to_string(),
        format!("--since=2026-01-0{s}"),
        "--no-cache".to_string(),
        "--seed".to_string(),
        format!("1234{s}"),
        "second.txt".to_string(),
        "--trace".to_string(),
    ]
}

fn parse_op(r: i64) -> i64 {
    let mut a = make_args();
    let argv = make_argv(r);
    let mut sink = 0i64;
    for _ in 0..PARSES {
        if a.parse(black_box(&argv)) {
            sink += 1;
        }
        sink += a.positionals.len() as i64 + a.get("seed").unwrap_or("").len() as i64;
    }
    sink
}

fn parse_hash() -> i64 {
    let mut a = make_args();
    let ok = a.parse(&make_argv(0));
    let mut h = fnv_byte(FNV_OFFSET, ok as i64);
    for name in NAMES.split(' ') {
        h = match a.get(name) {
            None => fnv_byte(h, 1),
            Some(v) => fnv_text(h, v),
        };
    }
    for p in &a.positionals {
        h = fnv_text(h, p);
    }
    h
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
    let (us, sink) = timed(n, parse_op);
    let row = Row { name: "parse", iters: n, us, px: PARSES * 24, hash: parse_hash(), sink };
    print_row(&row);
    println!("time: {}ms sink={}", t0.elapsed().as_millis(), row.sink);
}
