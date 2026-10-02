// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// zttext-reference — the pure-Rust twin of the `zttext` package's performance pass
// (bench/bench.loft), one file built with `rustc -O`.  It computes the SAME workloads with
// the SAME algorithms, in the same order, and prints the same rows, hash included: a row
// whose hash matches the loft build's is a like-for-like comparison, and only then is a
// routine's loft time judged against it (@FR-Perf-Weight).  No dependencies and no
// cleverness — plain idiomatic Rust, the speed an industry implementation reaches without
// effort, which is exactly what the bar should be.
//
//     rustc -O --edition=2021 bench/bench.rs -o bench/.build/stats_rs && bench/.build/stats_rs --n 2
//
// Each routine is a port of its loft original in src/zttext.loft, quadratic parts included:
// an insert still copies the whole append-only buffer (a `Vec<char>` clone), undo still
// prepends each inverse group to everything built so far, the layout still slices the runs
// of every token again for each of its three passes over it.  What is idiomatic Rust rather
// than a transliteration is the representation: a run is a `&[char]` slice of the buffer
// rather than a freshly built text, and an edit that keeps the buffer MOVES it into the new
// document rather than copying it.  `black_box` guards each op's INPUT and the sink —
// never anything inside a kernel.
use std::hint::black_box;
use std::time::Instant;

const FNV_OFFSET: i64 = 2166136261;
const FNV_PRIME: i64 = 16777619;

const PIECES: i64 = 5000;
const PIECE_LEN: i64 = 20;
const DOC_CHARS: i64 = 100000;
const COLUMN: f64 = 72.0;
const INSERTS: i64 = 500;
const INSERT_LEN: i64 = 20;
const DELETES: i64 = 50;
const LOCATES: i64 = 2000;
const TXN_PIECES: i64 = 1000;
const TXN_OPS: i64 = 300;

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

fn fnv_text(h0: i64, s: &str) -> i64 {
    let mut h = h0;
    for &b in s.as_bytes() {
        h = ((h ^ b as i64) * FNV_PRIME) & 0xFFFF_FFFF;
    }
    h
}

fn micro(v: f64) -> i64 {
    (v * 1000000.0) as i64
}

fn flag(b: bool) -> i64 {
    b as i64
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

fn timed<F: FnMut(i64) -> i64>(n: i64, mut f: F) -> (i64, i64) {
    let t0 = Instant::now();
    let mut sink = 0i64;
    for r in 0..n {
        sink = sink.wrapping_add(f(black_box(r)));
    }
    (t0.elapsed().as_micros() as i64, black_box(sink))
}

// ── The content core (M0) ───────────────────────────────────────────

#[derive(Clone, Copy)]
struct Piece {
    start: i64,
    count: i64,
    style: i64,
}

#[derive(Clone)]
struct Doc {
    buf: Vec<char>,
    pieces: Vec<Piece>,
}

fn empty_doc() -> Doc {
    Doc { buf: Vec::new(), pieces: Vec::new() }
}

fn clampi(x: i64, lo: i64, hi: i64) -> i64 {
    if x < lo {
        return lo;
    }
    if x > hi {
        return hi;
    }
    x
}

fn materialise(d: &Doc) -> String {
    let mut out = String::new();
    for p in &d.pieces {
        for j in p.start..p.start + p.count {
            out.push(d.buf[j as usize]);
        }
    }
    out
}

fn locate(d: &Doc, a: i64) -> (i64, i64) {
    let mut cum = 0;
    for (i, p) in d.pieces.iter().enumerate() {
        if a < cum + p.count {
            return (i as i64, a - cum);
        }
        cum += p.count;
    }
    (d.pieces.len() as i64, 0)
}

fn insert_text(d: &Doc, a: i64, s: &str, style: i64) -> Doc {
    let n = s.chars().count() as i64;
    if n == 0 {
        return d.clone();
    }
    let mut nb = d.buf.clone();
    let base = nb.len() as i64;
    nb.extend(s.chars());
    let newp = Piece { start: base, count: n, style };
    let (pi, ro) = locate(d, a);
    let mut np: Vec<Piece> = Vec::new();
    for (i, p) in d.pieces.iter().enumerate() {
        if i as i64 == pi {
            if ro > 0 {
                np.push(Piece { start: p.start, count: ro, style: p.style });
            }
            np.push(newp);
            if ro < p.count {
                np.push(Piece { start: p.start + ro, count: p.count - ro, style: p.style });
            }
        } else {
            np.push(*p);
        }
    }
    if pi >= d.pieces.len() as i64 {
        np.push(newp);
    }
    Doc { buf: nb, pieces: np }
}

fn delete_range(pieces: &[Piece], a: i64, b: i64) -> Vec<Piece> {
    if b <= a {
        return pieces.to_vec();
    }
    let mut np: Vec<Piece> = Vec::new();
    let mut cum = 0;
    for p in pieces {
        let ps = cum;
        let pe = cum + p.count;
        let lend = if a < pe { a } else { pe };
        if lend > ps {
            np.push(Piece { start: p.start, count: lend - ps, style: p.style });
        }
        let rstart = if b > ps { b } else { ps };
        if pe > rstart {
            np.push(Piece { start: p.start + (rstart - ps), count: pe - rstart, style: p.style });
        }
        cum = pe;
    }
    np
}

fn set_style(pieces: &[Piece], a: i64, b: i64, style: i64) -> Vec<Piece> {
    if b <= a {
        return pieces.to_vec();
    }
    let mut np: Vec<Piece> = Vec::new();
    let mut cum = 0;
    for p in pieces {
        let ps = cum;
        let pe = cum + p.count;
        let m1 = clampi(a, ps, pe);
        let m2 = clampi(b, ps, pe);
        if m1 > ps {
            np.push(Piece { start: p.start, count: m1 - ps, style: p.style });
        }
        if m2 > m1 {
            np.push(Piece { start: p.start + (m1 - ps), count: m2 - m1, style });
        }
        if pe > m2 {
            np.push(Piece { start: p.start + (m2 - ps), count: pe - m2, style: p.style });
        }
        cum = pe;
    }
    np
}

/// The styled runs of [a, b): one slice of the buffer per overlapping piece fragment.
fn slice_runs(d: &Doc, a: i64, b: i64) -> Vec<(&[char], i64)> {
    let mut runs = Vec::new();
    if b <= a {
        return runs;
    }
    let mut cum = 0;
    for p in &d.pieces {
        let ps = cum;
        let pe = cum + p.count;
        let lo = clampi(a, ps, pe);
        let hi = clampi(b, ps, pe);
        if hi > lo {
            let from = (p.start + (lo - ps)) as usize;
            runs.push((&d.buf[from..from + (hi - lo) as usize], p.style));
        }
        cum = pe;
    }
    runs
}

fn char_styles(d: &Doc) -> Vec<i64> {
    let mut out = Vec::new();
    for p in &d.pieces {
        for _ in 0..p.count {
            out.push(p.style);
        }
    }
    out
}

// ── Transactions and undo ───────────────────────────────────────────

enum Op {
    Ins { at: i64, str: String, style: i64 },
    Del { from: i64, to: i64 },
    Sty { from: i64, to: i64, style: i64 },
}

fn apply_op(d: Doc, op: &Op) -> Doc {
    match op {
        Op::Ins { at, str, style } => insert_text(&d, *at, str, *style),
        Op::Del { from, to } => {
            let pieces = delete_range(&d.pieces, *from, *to);
            Doc { buf: d.buf, pieces }
        }
        Op::Sty { from, to, style } => {
            let pieces = set_style(&d.pieces, *from, *to, *style);
            Doc { buf: d.buf, pieces }
        }
    }
}

fn inv_op_group(pre: &Doc, op: &Op) -> Vec<Op> {
    let mut ops = Vec::new();
    match op {
        Op::Ins { at, str, .. } => {
            ops.push(Op::Del { from: *at, to: at + str.chars().count() as i64 });
        }
        Op::Del { from, to } => {
            let mut pos = *from;
            for (s, style) in slice_runs(pre, *from, *to) {
                ops.push(Op::Ins { at: pos, str: s.iter().collect(), style });
                pos += s.len() as i64;
            }
        }
        Op::Sty { from, to, .. } => {
            let mut pos = *from;
            for (s, style) in slice_runs(pre, *from, *to) {
                ops.push(Op::Sty { from: pos, to: pos + s.len() as i64, style });
                pos += s.len() as i64;
            }
        }
    }
    ops
}

/// The inverse transaction: each op's group is PREPENDED to everything built so far, as the
/// library does — quadratic in the op count.
fn invert(d: &Doc, t: &[Op]) -> Vec<Op> {
    let mut cur = d.clone();
    let mut result: Vec<Op> = Vec::new();
    for op in t {
        let g = inv_op_group(&cur, op);
        result.splice(0..0, g);
        cur = apply_op(cur, op);
    }
    result
}

// ── Style + measure ports ───────────────────────────────────────────

struct Style {
    size: f64,
    #[allow(dead_code)]
    weight: i64,
    #[allow(dead_code)]
    italic: bool,
    #[allow(dead_code)]
    dir: i64,
}

fn default_resolver(_id: i64) -> Style {
    Style { size: 1.0, weight: 0, italic: false, dir: 0 }
}

fn mono_measure(s: &[char], st: &Style) -> f64 {
    (s.len() as f64) * st.size
}

fn run_height(st: &Style) -> f64 {
    st.size
}

// ── Layout (M1) ─────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct Rect {
    x: f64,
    y: f64,
    w: f64,
    h: f64,
}

#[derive(Clone, Copy)]
struct LBox {
    rect: Rect,
    ks: i64,
    ke: i64,
    style: i64,
    hyphen: bool,
}

#[derive(Clone, Copy)]
struct LaidLine {
    cs: i64,
    ce: i64,
    y: f64,
    h: f64,
    para_end: bool,
    right: f64,
}

#[derive(Clone)]
struct Layout {
    boxes: Vec<LBox>,
    lines: Vec<LaidLine>,
}

#[derive(Clone, Copy)]
struct Token {
    word: bool,
    ts: i64,
    te: i64,
    disc: bool,
    brk: bool,
}

fn is_space(c: char) -> bool {
    c == ' '
}
fn is_nl(c: char) -> bool {
    c as u32 == 10
}
fn is_shy(c: char) -> bool {
    c as u32 == 173
}

fn seg(d: &Doc) -> Vec<Token> {
    let mut toks = Vec::new();
    let s = materialise(d);
    let cs: Vec<char> = s.chars().collect();
    let n = cs.len();
    let mut i = 0;
    while i < n {
        let ch = cs[i];
        if is_shy(ch) {
            toks.push(Token { word: false, ts: i as i64, te: i as i64 + 1, disc: true, brk: false });
            i += 1;
        } else if is_nl(ch) {
            let start = i;
            while i < n && is_nl(cs[i]) {
                i += 1;
            }
            toks.push(Token { word: false, ts: start as i64, te: i as i64, disc: false, brk: true });
        } else if is_space(ch) {
            let start = i;
            while i < n && is_space(cs[i]) {
                i += 1;
            }
            toks.push(Token { word: false, ts: start as i64, te: i as i64, disc: false, brk: false });
        } else {
            let start = i;
            while i < n && !is_space(cs[i]) && !is_shy(cs[i]) && !is_nl(cs[i]) {
                i += 1;
            }
            toks.push(Token { word: true, ts: start as i64, te: i as i64, disc: false, brk: false });
        }
    }
    toks
}

fn token_width<R: Fn(i64) -> Style, M: Fn(&[char], &Style) -> f64>(
    d: &Doc,
    tok: &Token,
    resolve: &R,
    measure: &M,
) -> f64 {
    if tok.disc {
        return 0.0;
    }
    let mut w = 0.0;
    for (s, style) in slice_runs(d, tok.ts, tok.te) {
        w += measure(s, &resolve(style));
    }
    w
}

fn next_line<R: Fn(i64) -> Style, M: Fn(&[char], &Style) -> f64>(
    d: &Doc,
    toks: &[Token],
    from: usize,
    w_col: f64,
    resolve: &R,
    measure: &M,
) -> (usize, usize, i64, bool) {
    let mut i = from;
    let mut acc = 0.0;
    let mut pending = 0.0;
    let mut line_has_word = false;
    let mut last_word_end = from;
    while i < toks.len() {
        let tok = &toks[i];
        if tok.brk {
            return (last_word_end, i + 1, -1, true);
        }
        let wtok = token_width(d, tok, resolve, measure);
        if tok.word {
            if !line_has_word {
                acc = wtok;
                last_word_end = i + 1;
                line_has_word = true;
                i += 1;
            } else if acc + pending + wtok <= w_col {
                acc += pending + wtok;
                pending = 0.0;
                last_word_end = i + 1;
                i += 1;
            } else {
                let mut hy = -1;
                if i > 0 && toks[i - 1].disc {
                    hy = i as i64 - 1;
                }
                return (last_word_end, i, hy, false);
            }
        } else {
            pending += wtok;
            i += 1;
        }
    }
    (last_word_end, i, -1, false)
}

#[allow(clippy::too_many_arguments)]
fn place_line<R: Fn(i64) -> Style, M: Fn(&[char], &Style) -> f64>(
    d: &Doc,
    toks: &[Token],
    first: usize,
    last_excl: usize,
    hyphen_disc: i64,
    para_end: bool,
    y: f64,
    resolve: &R,
    measure: &M,
) -> (Vec<LBox>, LaidLine) {
    let mut lh = 0.0;
    for tok in &toks[first..last_excl] {
        if !tok.disc {
            for (_, style) in slice_runs(d, tok.ts, tok.te) {
                let hh = run_height(&resolve(style));
                if hh > lh {
                    lh = hh;
                }
            }
        }
    }
    let mut boxes = Vec::new();
    let mut x = 0.0;
    let mut line_cs = -1;
    let mut line_ce = -1;
    for tok in &toks[first..last_excl] {
        if !tok.disc {
            let mut roff = tok.ts;
            for (s, style) in slice_runs(d, tok.ts, tok.te) {
                let st = resolve(style);
                let rw = measure(s, &st);
                let rh = run_height(&st);
                if line_cs < 0 {
                    line_cs = roff;
                }
                let len = s.len() as i64;
                boxes.push(LBox { rect: Rect { x, y, w: rw, h: rh }, ks: roff, ke: roff + len, style, hyphen: false });
                line_ce = roff + len;
                x += rw;
                roff += len;
            }
        }
    }
    if hyphen_disc >= 0 {
        let disc = &toks[hyphen_disc as usize];
        let druns = slice_runs(d, disc.ts, disc.te);
        let hstyle = if !druns.is_empty() { druns[0].1 } else { 0 };
        let hst = resolve(hstyle);
        let hw = measure(&['-'], &hst);
        let hh2 = run_height(&hst);
        if hh2 > lh {
            lh = hh2;
        }
        boxes.push(LBox { rect: Rect { x, y, w: hw, h: hh2 }, ks: disc.ts, ke: disc.te, style: hstyle, hyphen: true });
        line_ce = disc.te;
    }
    (boxes, LaidLine { cs: line_cs, ce: line_ce, y, h: lh, para_end, right: 0.0 })
}

fn layout_tokens_from<R: Fn(i64) -> Style, M: Fn(&[char], &Style) -> f64>(
    d: &Doc,
    toks: &[Token],
    y0: f64,
    resolve: &R,
    measure: &M,
    w_col: f64,
    para_gap: f64,
) -> Layout {
    let mut boxes = Vec::new();
    let mut lines = Vec::new();
    let mut y = y0;
    let mut cur = 0;
    while cur < toks.len() {
        let (last_excl, next_tok, hy, para) = next_line(d, toks, cur, w_col, resolve, measure);
        if last_excl > cur {
            let pe = para || next_tok >= toks.len();
            let (pboxes, pline) = place_line(d, toks, cur, last_excl, hy, pe, y, resolve, measure);
            boxes.extend(pboxes);
            lines.push(LaidLine { right: w_col, ..pline });
            y += pline.h;
            if para {
                y += para_gap;
            }
        } else if para {
            y += para_gap;
        }
        cur = next_tok;
    }
    Layout { boxes, lines }
}

fn flow_layout_full<R: Fn(i64) -> Style, M: Fn(&[char], &Style) -> f64>(
    d: &Doc,
    resolve: &R,
    measure: &M,
    w_col: f64,
) -> Layout {
    layout_tokens_from(d, &seg(d), 0.0, resolve, measure, w_col, 0.0)
}

// ── Incremental patch (M3) ──────────────────────────────────────────

fn doc_chars(d: &Doc) -> Vec<char> {
    materialise(d).chars().collect()
}

fn dirty(old_d: &Doc, new_d: &Doc) -> (i64, i64, i64) {
    let oc = doc_chars(old_d);
    let ostyle = char_styles(old_d);
    let nc = doc_chars(new_d);
    let nstyle = char_styles(new_d);
    let lo_len = oc.len();
    let hi_len = nc.len();
    let mn = lo_len.min(hi_len);
    let mut lo = 0;
    while lo < mn && oc[lo] == nc[lo] && ostyle[lo] == nstyle[lo] {
        lo += 1;
    }
    let mut su = 0;
    while su < mn - lo
        && oc[lo_len - 1 - su] == nc[hi_len - 1 - su]
        && ostyle[lo_len - 1 - su] == nstyle[hi_len - 1 - su]
    {
        su += 1;
    }
    (lo as i64, (lo_len - su) as i64, (hi_len - su) as i64)
}

struct PatchResult {
    layout: Layout,
    recomputed: i64,
    reused: i64,
}

fn full_patch<R: Fn(i64) -> Style, M: Fn(&[char], &Style) -> f64>(
    new_d: &Doc,
    resolve: &R,
    measure: &M,
    w_col: f64,
) -> PatchResult {
    let fl = flow_layout_full(new_d, resolve, measure, w_col);
    let recomputed = fl.boxes.len() as i64;
    PatchResult { layout: fl, recomputed, reused: 0 }
}

fn patch<R: Fn(i64) -> Style, M: Fn(&[char], &Style) -> f64>(
    old_layout: &Layout,
    old_doc: &Doc,
    new_doc: &Doc,
    resolve: &R,
    measure: &M,
    w_col: f64,
) -> PatchResult {
    let (lo, hi_old, hi_new) = dirty(old_doc, new_doc);
    if lo == hi_old && lo == hi_new {
        return PatchResult { layout: old_layout.clone(), recomputed: 0, reused: old_layout.boxes.len() as i64 };
    }
    if old_layout.lines.is_empty() {
        return full_patch(new_doc, resolve, measure, w_col);
    }
    let delta = hi_new - hi_old;
    let mut cix: i64 = -1;
    for (i, ln) in old_layout.lines.iter().enumerate() {
        if ln.cs >= 0 && ln.cs <= lo {
            cix = i as i64;
        }
    }
    if cix < 0 {
        return full_patch(new_doc, resolve, measure, w_col);
    }
    let lstart = (cix - 1).max(0) as usize;
    let sline = old_layout.lines[lstart];
    let start_char = sline.cs;
    let start_y = sline.y;
    if start_char <= 0 {
        return full_patch(new_doc, resolve, measure, w_col);
    }
    let ntoks = seg(new_doc);
    let ti0 = match ntoks.iter().position(|t| t.ts >= start_char) {
        Some(i) if ntoks[i].ts == start_char => i,
        _ => return full_patch(new_doc, resolve, measure, w_col),
    };
    let mut out_boxes: Vec<LBox> = old_layout.boxes.iter().filter(|b| b.ke <= start_char).copied().collect();
    let mut out_lines: Vec<LaidLine> = old_layout.lines[..lstart].to_vec();
    let mut recomputed = 0i64;
    let mut cur = ti0;
    let mut y = start_y;
    let mut converged = false;
    let mut conv_old_line: i64 = -1;
    let mut conv_y = 0.0;
    while cur < ntoks.len() {
        let (last_excl, next_tok, hy, para) = next_line(new_doc, &ntoks, cur, w_col, resolve, measure);
        if last_excl > cur {
            let pe = para || next_tok >= ntoks.len();
            let (pboxes, pline) = place_line(new_doc, &ntoks, cur, last_excl, hy, pe, y, resolve, measure);
            recomputed += pboxes.len() as i64;
            out_boxes.extend(pboxes);
            out_lines.push(LaidLine { right: w_col, ..pline });
            y += pline.h;
        }
        cur = next_tok;
        if cur < ntoks.len() {
            let nsc = ntoks[cur].ts;
            if nsc > hi_new {
                for (k, ol) in old_layout.lines.iter().enumerate() {
                    if ol.cs == nsc - delta {
                        conv_old_line = k as i64;
                    }
                }
                if conv_old_line >= 0 {
                    converged = true;
                    conv_y = y;
                }
            }
        }
        if converged {
            break;
        }
    }
    if converged {
        let olj = old_layout.lines[conv_old_line as usize];
        let ydelta = conv_y - olj.y;
        for b in &old_layout.boxes {
            if b.ks >= olj.cs {
                out_boxes.push(LBox {
                    rect: Rect { y: b.rect.y + ydelta, ..b.rect },
                    ks: b.ks + delta,
                    ke: b.ke + delta,
                    ..*b
                });
            }
        }
        for ol in &old_layout.lines[conv_old_line as usize..] {
            out_lines.push(LaidLine { cs: ol.cs + delta, ce: ol.ce + delta, y: ol.y + ydelta, ..*ol });
        }
    }
    let reused = out_boxes.len() as i64 - recomputed;
    PatchResult { layout: Layout { boxes: out_boxes, lines: out_lines }, recomputed, reused }
}

// ── The documents ───────────────────────────────────────────────────

fn lcg(s: i64) -> i64 {
    (s * 1103515245 + 12345) & 0x7FFF_FFFF
}

fn letter(v: i64) -> char {
    char::from_u32((97 + v) as u32).unwrap()
}

fn gen_chars(n: i64, shift: i64) -> Vec<char> {
    let mut out: Vec<char> = Vec::new();
    let mut s = 12345i64;
    let mut words = 0;
    while (out.len() as i64) < n {
        s = lcg(s);
        let wl = 3 + (s >> 16) % 14;
        s = lcg(s);
        let shy = if ((s >> 16) & 7) == 0 && wl >= 6 { wl / 2 } else { -1 };
        for j in 0..wl {
            if j == shy {
                out.push('\u{AD}');
            }
            s = lcg(s);
            out.push(letter(((s >> 16) % 26 + shift) % 26));
        }
        words += 1;
        if words % 40 == 0 {
            out.push('\n');
            if ((s >> 20) & 3) == 0 {
                out.push('\n');
            }
        } else {
            out.push(' ');
            s = lcg(s);
            if ((s >> 16) & 15) == 0 {
                out.push(' ');
            }
        }
    }
    out.truncate(n as usize);
    out
}

fn piece_doc(np: i64, plen: i64, shift: i64) -> Doc {
    let buf = gen_chars(np * plen, shift);
    let pieces = (0..np)
        .map(|k| Piece { start: ((k * 7919) % np) * plen, count: plen, style: (k + shift) % 3 })
        .collect();
    Doc { buf, pieces }
}

fn one_doc(n: i64, shift: i64) -> Doc {
    Doc { buf: gen_chars(n, shift), pieces: vec![Piece { start: 0, count: n, style: 0 }] }
}

fn gen_word(k: i64, width: i64, shift: i64) -> String {
    let mut out: String = (0..width - 1).map(|j| letter((k * 7 + j + shift) % 26)).collect();
    out.push(' ');
    out
}

// ── The rows ────────────────────────────────────────────────────────

fn fnv_layout(h0: i64, l: &Layout) -> i64 {
    let mut ints = Vec::new();
    for b in &l.boxes {
        ints.extend([micro(b.rect.x), micro(b.rect.y), micro(b.rect.w), micro(b.rect.h), b.ks, b.ke, b.style, flag(b.hyphen)]);
    }
    for ln in &l.lines {
        ints.extend([ln.cs, ln.ce, micro(ln.y), micro(ln.h), flag(ln.para_end), micro(ln.right)]);
    }
    fnv(h0, &ints)
}

fn fnv_doc(d: &Doc) -> i64 {
    let mut ints: Vec<i64> = d.buf.iter().map(|&c| c as i64).collect();
    for p in &d.pieces {
        ints.extend([p.start, p.count, p.style]);
    }
    fnv(FNV_OFFSET, &ints)
}

fn fnv_tokens(toks: &[Token]) -> i64 {
    let mut ints = Vec::new();
    for t in toks {
        ints.extend([flag(t.word), t.ts, t.te, flag(t.disc), flag(t.brk)]);
    }
    fnv(FNV_OFFSET, &ints)
}

fn pick<'a>(r: i64, d0: &'a Doc, d1: &'a Doc) -> &'a Doc {
    black_box(if r & 1 == 0 { d0 } else { d1 })
}

fn bench_seg(n: i64, d0: &Doc, d1: &Doc) -> Row {
    let (us, sink) = timed(n, |r| seg(pick(r, d0, d1)).len() as i64);
    Row { name: "seg", iters: n, us, px: DOC_CHARS, hash: fnv_tokens(&seg(black_box(d0))), sink }
}

fn insert_op(words: &[String]) -> Doc {
    let mut d = empty_doc();
    for k in 0..INSERTS {
        let a = (k * 7919) % (k * INSERT_LEN + 1);
        d = insert_text(&d, a, &words[k as usize], k % 4);
    }
    d
}

fn bench_insert(n: i64) -> Row {
    let w0: Vec<String> = (0..INSERTS).map(|k| gen_word(k, INSERT_LEN, 0)).collect();
    let w1: Vec<String> = (0..INSERTS).map(|k| gen_word(k, INSERT_LEN, 1)).collect();
    let (us, sink) = timed(n, |r| {
        let w = black_box(if r & 1 == 0 { &w0 } else { &w1 });
        insert_op(w).pieces.len() as i64
    });
    Row { name: "insert_text", iters: n, us, px: INSERTS, hash: fnv_doc(&insert_op(black_box(&w0))), sink }
}

fn bench_flow(n: i64) -> Row {
    let d0 = one_doc(DOC_CHARS, 0);
    let d1 = one_doc(DOC_CHARS, 1);
    let (us, sink) = timed(n, |r| {
        flow_layout_full(pick(r, &d0, &d1), &default_resolver, &mono_measure, COLUMN).boxes.len() as i64
    });
    let one = flow_layout_full(black_box(&d0), &default_resolver, &mono_measure, COLUMN);
    Row { name: "flow_layout_full", iters: n, us, px: DOC_CHARS, hash: fnv_layout(FNV_OFFSET, &one), sink }
}

fn bench_materialise(n: i64, d0: &Doc, d1: &Doc) -> Row {
    let (us, sink) = timed(n, |r| materialise(pick(r, d0, d1)).len() as i64);
    let one = materialise(black_box(d0));
    Row { name: "materialise", iters: n, us, px: DOC_CHARS, hash: fnv_text(FNV_OFFSET, &one), sink }
}

fn delete_op(d: &Doc) -> Vec<Piece> {
    let mut pieces = delete_range(&d.pieces, 0, 0);
    for k in 0..DELETES {
        let left = DOC_CHARS - 3 * k;
        let a = (k * 7919) % (left - 3);
        pieces = delete_range(&pieces, a, a + 3);
    }
    pieces
}

fn bench_delete(n: i64, d0: &Doc, d1: &Doc) -> Row {
    let (us, sink) = timed(n, |r| delete_op(pick(r, d0, d1)).len() as i64);
    let mut ints = Vec::new();
    for p in delete_op(black_box(d0)) {
        ints.extend([p.start, p.count, p.style]);
    }
    Row { name: "delete_range", iters: n, us, px: DELETES, hash: fnv(FNV_OFFSET, &ints), sink }
}

fn locate_op(d: &Doc, shift: i64) -> Vec<i64> {
    let mut out = Vec::new();
    for j in 0..LOCATES {
        let a = ((j * 7919) % PIECES) * PIECE_LEN + 5 + shift;
        let (pi, ro) = locate(d, a);
        out.push(pi);
        out.push(ro);
    }
    out
}

fn bench_locate(n: i64, d: &Doc) -> Row {
    let (us, sink) = timed(n, |r| locate_op(black_box(d), r & 1)[1]);
    Row { name: "locate", iters: n, us, px: LOCATES, hash: fnv(FNV_OFFSET, &locate_op(black_box(d), 0)), sink }
}

fn gen_txn(shift: i64) -> Vec<Op> {
    let mut ops = Vec::new();
    let mut len = TXN_PIECES * PIECE_LEN;
    for k in 0..TXN_OPS {
        let pos = (k * 7919) % (len - 40);
        match k % 3 {
            0 => {
                let s: String = (0..5).map(|j| letter((k + j + shift) % 26)).collect();
                ops.push(Op::Ins { at: pos, str: s, style: k % 4 + shift });
                len += 5;
            }
            1 => {
                ops.push(Op::Del { from: pos, to: pos + 4 });
                len -= 4;
            }
            _ => ops.push(Op::Sty { from: pos, to: pos + 30, style: k % 5 + shift }),
        }
    }
    ops
}

fn fnv_txn(t: &[Op]) -> i64 {
    let mut h = FNV_OFFSET;
    for op in t {
        match op {
            Op::Ins { at, str, style } => {
                h = fnv(h, &[0, *at, *style, str.chars().count() as i64]);
                h = fnv_text(h, str);
            }
            Op::Del { from, to } => h = fnv(h, &[1, *from, *to]),
            Op::Sty { from, to, style } => h = fnv(h, &[2, *from, *to, *style]),
        }
    }
    h
}

fn bench_invert(n: i64) -> Row {
    let d0 = piece_doc(TXN_PIECES, PIECE_LEN, 0);
    let d1 = piece_doc(TXN_PIECES, PIECE_LEN, 1);
    let t0 = gen_txn(0);
    let t1 = gen_txn(1);
    let (us, sink) = timed(n, |r| {
        let (d, t) = black_box(if r & 1 == 0 { (&d0, &t0) } else { (&d1, &t1) });
        invert(d, t).len() as i64
    });
    let one = invert(black_box(&d0), &t0);
    Row { name: "invert", iters: n, us, px: TXN_OPS, hash: fnv_txn(&one), sink }
}

struct PatchFix {
    old: Doc,
    lay: Layout,
    new: Doc,
}

fn patch_fix(shift: i64, word: &str) -> PatchFix {
    let old = one_doc(DOC_CHARS, shift);
    let lay = flow_layout_full(&old, &default_resolver, &mono_measure, COLUMN);
    let new = insert_text(&old, DOC_CHARS / 2, word, 0);
    PatchFix { old, lay, new }
}

fn patch_run(pf: &PatchFix) -> PatchResult {
    patch(&pf.lay, &pf.old, &pf.new, &default_resolver, &mono_measure, COLUMN)
}

fn bench_patch(n: i64) -> Row {
    let f0 = patch_fix(0, "vwxyz");
    let f1 = patch_fix(1, "wxyza");
    let (us, sink) = timed(n, |r| {
        let p = patch_run(black_box(if r & 1 == 0 { &f0 } else { &f1 }));
        p.recomputed + p.layout.boxes.len() as i64
    });
    let one = patch_run(black_box(&f0));
    let h = fnv(FNV_OFFSET, &[one.recomputed, one.reused]);
    Row { name: "patch", iters: n, us, px: DOC_CHARS, hash: fnv_layout(h, &one.layout), sink }
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
    let d0 = piece_doc(PIECES, PIECE_LEN, 0);
    let d1 = piece_doc(PIECES, PIECE_LEN, 1);
    let rows = [
        bench_seg(n, &d0, &d1),
        bench_insert(n),
        bench_flow(n),
        bench_materialise(n, &d0, &d1),
        bench_delete(n, &d0, &d1),
        bench_locate(n, &d0),
        bench_invert(n),
        bench_patch(n),
    ];
    let mut sink = 0i64;
    for row in &rows {
        print_row(row);
        sink = sink.wrapping_add(row.sink);
    }
    println!("time: {}ms sink={}", t0.elapsed().as_millis(), sink);
}
