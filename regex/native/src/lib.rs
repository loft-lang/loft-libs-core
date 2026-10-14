// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Native regex bridge for the `regex` loft package, wrapping the Rust `regex`
//! crate — the de-facto-standard, linear-time, ReDoS-safe engine.  Same shape
//! as `random` / `crypto`: bare `#[no_mangle] extern "C"`, i64 ABI with the
//! `i64::MIN` null sentinel, text args as `(ptr, len)`.
//!
//! Every offset this bridge answers is a BYTE offset on a code-point boundary:
//! the engine matches `&str` by `char`, and a pattern that could match inside a
//! code point does not compile.  Spans are answered by ONE function, `n_spans`
//! (@PLN192 § re-assertion sites); the `_at` searches exist for the lazy split,
//! which must not re-slice the subject (a slice restarts `^` and `\b`).
//!
//! Patterns are passed inline (no compile step / handle).  A thread-local cache
//! maps `pattern -> compiled Regex, or the parser's error` so each distinct
//! pattern compiles once; repeated calls are hash lookups.  A pattern that did
//! not compile is cached with its message, so it is neither re-attempted nor
//! re-reported: `n_pattern_error` hands the message out ONCE (the loft side logs
//! it, @C80's channel for an unguarded fault) and "" ever after.  The cache
//! never evicts — ideal for the handful of literal patterns a script uses; a
//! program generating many *dynamic* patterns would grow it unbounded
//! (acceptable for this library's script-tool scope).

#![allow(clippy::missing_safety_doc)]

use loft_ffi::{LoftRef, LoftStore, LoftStr};
use loft_ffi_macros::loft_native;
use regex::Regex;
use std::cell::RefCell;
use std::collections::HashMap;

/// A cached pattern: the compiled engine, or the parser's message and whether
/// it has been handed out already.
enum Cached {
    Ok(Regex),
    Err { message: String, reported: bool },
}

thread_local! {
    static CACHE: RefCell<HashMap<String, Cached>> = RefCell::new(HashMap::new());
}

/// Borrow a loft text argument `(ptr, len)` as `&str` (lossless; invalid
/// UTF-8 or a null/empty pointer yields `""`).
#[inline]
unsafe fn rx_str<'a>(ptr: *const u8, len: usize) -> &'a str {
    if ptr.is_null() || len == 0 {
        ""
    } else {
        std::str::from_utf8(unsafe { std::slice::from_raw_parts(ptr, len) }).unwrap_or("")
    }
}

/// Look up (or compile-and-cache) `pat`, then run `f` against the compiled
/// regex.  Returns `miss` when the pattern is invalid.  The fast path —
/// pattern already cached — allocates nothing.
#[inline]
fn with_compiled<R>(pat: &str, miss: R, f: impl FnOnce(&Regex) -> R) -> R {
    CACHE.with(|c| {
        if let Some(slot) = c.borrow().get(pat) {
            return match slot {
                Cached::Ok(re) => f(re),
                Cached::Err { .. } => miss,
            };
        }
        let compiled = match Regex::new(pat) {
            Ok(re) => Cached::Ok(re),
            Err(e) => Cached::Err {
                message: e.to_string(),
                reported: false,
            },
        };
        let result = match &compiled {
            Cached::Ok(re) => f(re),
            Cached::Err { .. } => miss,
        };
        c.borrow_mut().insert(pat.to_owned(), compiled);
        result
    })
}

/// Clamp a caller's start offset into `input`: at most its length, and moved
/// forward to the next code-point boundary — a loft caller advancing past an
/// empty match by one byte may land inside a character.  A null (`i64::MIN`)
/// or negative start reads as 0.
#[inline]
fn start_at(input: &str, from: i64) -> usize {
    let mut at = if from == i64::MIN || from < 0 {
        0
    } else {
        usize::try_from(from).unwrap_or(usize::MAX).min(input.len())
    };
    while at < input.len() && !input.is_char_boundary(at) {
        at += 1;
    }
    at
}

/// `#native "n_is_match"` — true if `pattern` matches anywhere in `input`.
/// An invalid pattern returns false.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_is_match(
    pat_ptr: *const u8,
    pat_len: usize,
    in_ptr: *const u8,
    in_len: usize,
) -> bool {
    let pat = unsafe { rx_str(pat_ptr, pat_len) };
    let input = unsafe { rx_str(in_ptr, in_len) };
    with_compiled(pat, false, |re| re.is_match(input))
}

/// `#native "n_match_start"` — byte offset of the START of the first match
/// of `pattern` in `input`, or `i64::MIN` (loft `null`) when there is no
/// match / the pattern is invalid.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_match_start(
    pat_ptr: *const u8,
    pat_len: usize,
    in_ptr: *const u8,
    in_len: usize,
) -> i64 {
    let pat = unsafe { rx_str(pat_ptr, pat_len) };
    let input = unsafe { rx_str(in_ptr, in_len) };
    with_compiled(pat, i64::MIN, |re| {
        re.find(input).map_or(i64::MIN, |m| m.start() as i64)
    })
}

/// `#native "n_match_start_at"` — the START of the first match of `pattern` in
/// `input` at or after byte `from`, with the WHOLE input as context (`^`, `$`
/// and `\b` see the bytes before `from`), or `i64::MIN`.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_match_start_at(
    pat_ptr: *const u8,
    pat_len: usize,
    in_ptr: *const u8,
    in_len: usize,
    from: i64,
) -> i64 {
    let pat = unsafe { rx_str(pat_ptr, pat_len) };
    let input = unsafe { rx_str(in_ptr, in_len) };
    let at = start_at(input, from);
    with_compiled(pat, i64::MIN, |re| {
        re.find_at(input, at).map_or(i64::MIN, |m| m.start() as i64)
    })
}

/// `#native "n_match_end_at"` — the END of that same match, or `i64::MIN`.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_match_end_at(
    pat_ptr: *const u8,
    pat_len: usize,
    in_ptr: *const u8,
    in_len: usize,
    from: i64,
) -> i64 {
    let pat = unsafe { rx_str(pat_ptr, pat_len) };
    let input = unsafe { rx_str(in_ptr, in_len) };
    let at = start_at(input, from);
    with_compiled(pat, i64::MIN, |re| {
        re.find_at(input, at).map_or(i64::MIN, |m| m.end() as i64)
    })
}

/// `#native "n_spans"` — the spans of the first match of `pattern` in `input`
/// at or after byte `from`, as one `vector<integer>` of pairs: `[s0, e0, s1,
/// e1, …]`, group 0 (the whole match) first, then every capture group in
/// pattern order, a group that did not take part as `-1, -1`.  An empty vector
/// when there is no match or the pattern is invalid.  The ONE span-answering
/// function of this bridge: every `Match` the loft side builds comes from here.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_spans(
    mut store: LoftStore,
    pat_ptr: *const u8,
    pat_len: usize,
    in_ptr: *const u8,
    in_len: usize,
    from: i64,
) -> LoftRef {
    let pat = unsafe { rx_str(pat_ptr, pat_len) };
    let input = unsafe { rx_str(in_ptr, in_len) };
    let at = start_at(input, from);
    let spans: Vec<i64> = with_compiled(pat, Vec::new(), |re| {
        re.captures_at(input, at).map_or_else(Vec::new, |caps| {
            let mut v = Vec::with_capacity(caps.len() * 2);
            for i in 0..caps.len() {
                match caps.get(i) {
                    Some(m) => {
                        v.push(m.start() as i64);
                        v.push(m.end() as i64);
                    }
                    None => {
                        v.push(-1);
                        v.push(-1);
                    }
                }
            }
            v
        })
    });
    let mut vec = unsafe { store.alloc_vector(8, spans.len() as u32) };
    for s in spans {
        unsafe { store.vector_push_long(&mut vec, s) };
    }
    vec
}

/// `#native "n_group_names"` — the capture-group names of `pattern`, one per
/// group in pattern order, each preceded by `\n` (so one unnamed group is
/// `"\n"` and no group at all is `""`).  "" for an invalid pattern.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_group_names(pat_ptr: *const u8, pat_len: usize) -> LoftStr {
    let pat = unsafe { rx_str(pat_ptr, pat_len) };
    let names = with_compiled(pat, String::new(), |re| {
        let mut out = String::new();
        for name in re.capture_names().skip(1) {
            out.push('\n');
            out.push_str(name.unwrap_or(""));
        }
        out
    });
    loft_ffi::ret(names)
}

/// `#native "n_replace_native"` — `input` with the first `limit` matches of
/// `pattern` replaced by `template` (`$1`, `${name}`, `$$`), every match when
/// `limit` is 0 or null.  The input unchanged when the pattern is invalid.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_replace_native(
    pat_ptr: *const u8,
    pat_len: usize,
    in_ptr: *const u8,
    in_len: usize,
    tpl_ptr: *const u8,
    tpl_len: usize,
    limit: i64,
) -> LoftStr {
    let pat = unsafe { rx_str(pat_ptr, pat_len) };
    let input = unsafe { rx_str(in_ptr, in_len) };
    let template = unsafe { rx_str(tpl_ptr, tpl_len) };
    let limit = if limit == i64::MIN || limit <= 0 {
        0usize
    } else {
        usize::try_from(limit).unwrap_or(usize::MAX)
    };
    let out = with_compiled(pat, input.to_owned(), |re| {
        re.replacen(input, limit, template).into_owned()
    });
    loft_ffi::ret(out)
}

/// `#native "n_pattern_error"` — the parser's message for a pattern that does
/// not compile, handed out ONCE per pattern per process; "" for a pattern that
/// compiles and for one already reported.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_pattern_error(pat_ptr: *const u8, pat_len: usize) -> LoftStr {
    let pat = unsafe { rx_str(pat_ptr, pat_len) };
    with_compiled(pat, (), |_| ());
    let message = CACHE.with(|c| {
        let mut cache = c.borrow_mut();
        match cache.get_mut(pat) {
            Some(Cached::Err { message, reported }) if !*reported => {
                *reported = true;
                message.clone()
            }
            _ => String::new(),
        }
    });
    loft_ffi::ret(message)
}

// The `loft_ffi::loft_register! { … }` invocation is GENERATED by `build.rs`
// (via `loft-ffi-build::generate_register_from_loft`) scanning this crate's
// loft sources for `#native` annotations.  Defining a native function IS
// registering it — no hand-maintained symbol list.
include!(concat!(env!("OUT_DIR"), "/loft_register_gen.rs"));
