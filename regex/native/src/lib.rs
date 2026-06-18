// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Native regex bridge for the `regex` loft package.  Three `#native`
//! symbols wrap the Rust `regex` crate — the de-facto-standard,
//! linear-time, ReDoS-safe engine.  Same shape as `random`/`crypto`: bare
//! `#[no_mangle] extern "C"`, i64 ABI with the `i64::MIN` null sentinel,
//! text args as `(ptr, len)`.
//!
//! ABI signatures (all on existing interpreter marshaller arms):
//!   n_is_match   (text, text) -> bool
//!   n_match_start(text, text) -> i64   first-match start offset, or i64::MIN
//!   n_match_end  (text, text) -> i64   first-match end offset, or i64::MIN
//!
//! The loft surface exposes `matches` (text method + free fn), `find` (wraps
//! `n_match_start`), and a `split` iterator built in loft from
//! `match_start`/`match_end` — plus `regex_find`/`regex_split` text methods.
//!
//! Patterns are passed inline (no compile step / handle).  A thread-local
//! cache maps `pattern -> compiled Regex` so each distinct pattern
//! compiles once; repeated calls are hash lookups.  An invalid pattern is
//! cached as `None`, so a bad pattern is not re-attempted either.  The
//! cache never evicts — ideal for the handful of literal patterns a script
//! uses; a program generating many *dynamic* patterns would grow it
//! unbounded (acceptable for this library's script-tool scope).

#![allow(clippy::missing_safety_doc)]

use loft_ffi::LoftStr;
use loft_ffi_macros::loft_native;
use regex::Regex;
use std::cell::RefCell;
use std::collections::HashMap;

thread_local! {
    static CACHE: RefCell<HashMap<String, Option<Regex>>> =
        RefCell::new(HashMap::new());
    // The `replace*` natives own their result bytes; ride a thread-local
    // `String` out as a `LoftStr` (the caller copies before the next regex
    // call) — same pattern as crypto's `cr_ret`.
    static RET_BUF: RefCell<String> = RefCell::new(String::new());
}

/// String → `LoftStr` for the text-returning `replace*` natives.
fn rx_ret(out: String) -> LoftStr {
    RET_BUF.with(|b| {
        *b.borrow_mut() = out;
        let r = b.borrow();
        loft_ffi::ret_ref(r.as_str())
    })
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
        // Fast path: already compiled — no allocation.
        if let Some(slot) = c.borrow().get(pat) {
            return slot.as_ref().map_or(miss, f);
        }
        // Slow path: compile once, run, then cache (Some or None).
        let compiled = Regex::new(pat).ok();
        let result = compiled.as_ref().map_or(miss, f);
        c.borrow_mut().insert(pat.to_owned(), compiled);
        result
    })
}

/// `#native "n_is_match"` — true if `pattern` matches anywhere in `input`.
/// An invalid pattern returns false.  (The loft-side `matches` / `text`
/// method wraps this.)
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
/// match / the pattern is invalid.  The loft-side `find` wraps this.
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

/// `#native "n_match_end"` — byte offset of the END of the first match of
/// `pattern` in `input`, or `i64::MIN` (loft `null`) when there is no match
/// / the pattern is invalid.  Used by the loft-side `split` iterator.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_match_end(
    pat_ptr: *const u8,
    pat_len: usize,
    in_ptr: *const u8,
    in_len: usize,
) -> i64 {
    let pat = unsafe { rx_str(pat_ptr, pat_len) };
    let input = unsafe { rx_str(in_ptr, in_len) };
    with_compiled(pat, i64::MIN, |re| {
        re.find(input).map_or(i64::MIN, |m| m.end() as i64)
    })
}

// --- Capture groups (drive the loft-side `match_groups` coroutine) ---

/// `#native "n_group_count"` — number of capture groups in the FIRST match of
/// `pattern` in `input` (index 0 = whole match, 1..n = captures), or 0 when
/// there is no match / the pattern is invalid.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_group_count(
    pat_ptr: *const u8,
    pat_len: usize,
    in_ptr: *const u8,
    in_len: usize,
) -> i64 {
    let pat = unsafe { rx_str(pat_ptr, pat_len) };
    let input = unsafe { rx_str(in_ptr, in_len) };
    with_compiled(pat, 0, |re| re.captures(input).map_or(0, |c| c.len() as i64))
}

/// `#native "n_group_text"` — the matched substring of capture group `group`
/// in the FIRST match of `pattern` in `input`, or `""` when there is no match
/// / the group did not participate / `group` is out of range / the pattern is
/// invalid.  Returning the substring directly keeps the loft side free of
/// byte-offset slicing and null handling.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_group_text(
    pat_ptr: *const u8,
    pat_len: usize,
    in_ptr: *const u8,
    in_len: usize,
    group: i64,
) -> LoftStr {
    if group < 0 {
        return rx_ret(String::new());
    }
    let pat = unsafe { rx_str(pat_ptr, pat_len) };
    let input = unsafe { rx_str(in_ptr, in_len) };
    rx_ret(with_compiled(pat, String::new(), |re| {
        re.captures(input)
            .and_then(|c| c.get(group as usize))
            .map_or(String::new(), |m| m.as_str().to_owned())
    }))
}

// --- Replace (one-shot; no coroutine needed) ---

/// `#native "n_replace_first"` — `input` with the FIRST match of `pattern`
/// replaced by `repl` (`$1` / `$name` references supported).  Invalid pattern
/// → `input` returned unchanged.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_replace_first(
    pat_ptr: *const u8,
    pat_len: usize,
    in_ptr: *const u8,
    in_len: usize,
    repl_ptr: *const u8,
    repl_len: usize,
) -> LoftStr {
    let pat = unsafe { rx_str(pat_ptr, pat_len) };
    let input = unsafe { rx_str(in_ptr, in_len) };
    let repl = unsafe { rx_str(repl_ptr, repl_len) };
    rx_ret(with_compiled(pat, input.to_owned(), |re| {
        re.replace(input, repl).into_owned()
    }))
}

/// `#native "n_replace_all_raw"` — `input` with EVERY non-overlapping match of
/// `pattern` replaced by `repl`.  Invalid pattern → `input` unchanged.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_replace_all_raw(
    pat_ptr: *const u8,
    pat_len: usize,
    in_ptr: *const u8,
    in_len: usize,
    repl_ptr: *const u8,
    repl_len: usize,
) -> LoftStr {
    let pat = unsafe { rx_str(pat_ptr, pat_len) };
    let input = unsafe { rx_str(in_ptr, in_len) };
    let repl = unsafe { rx_str(repl_ptr, repl_len) };
    rx_ret(with_compiled(pat, input.to_owned(), |re| {
        re.replace_all(input, repl).into_owned()
    }))
}

// The `loft_ffi::loft_register! { … }` invocation is GENERATED by `build.rs`
// (via `loft-ffi-build::generate_register_from_loft`) scanning this crate's
// loft sources for `#native` annotations.  Defining a native function IS
// registering it — no hand-maintained symbol list.
include!(concat!(env!("OUT_DIR"), "/loft_register_gen.rs"));
