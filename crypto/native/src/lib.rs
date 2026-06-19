// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Native crypto primitives for the `crypto` loft package.  SHA-256, HMAC,
//! base64, and Ed25519 (RFC 8032) signatures.  The hashing / base64 symbols
//! bridge to zero-dependency pure-Rust impls in `sha256.rs` / `base64.rs`;
//! Ed25519 wraps the vetted `ed25519-dalek` crate in `ed25519.rs`.
//!
//! Every exported `n_*` fn carries `#[loft_native]`, so the build script emits
//! a `loft_register_bridges_v1` table and the interpreter dispatches through
//! the generated uniform marshal bridges (the legacy raw-ptr arm-set is gone).
//!
//! ABI matches the package format: text args arrive as `(ptr, len)`
//! pairs; text returns ride a `LoftStr` borrowed from a thread-local
//! buffer (the caller copies the bytes before the next crypto call).

#![allow(clippy::missing_safety_doc)]

use loft_ffi::LoftStr;
use loft_ffi_macros::loft_native;

mod base64;
mod ed25519;
mod sha256;

thread_local! {
    static CRYPTO_BUF: std::cell::RefCell<String> =
        const { std::cell::RefCell::new(String::new()) };
}

#[inline]
unsafe fn cr_in<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(ptr, len) }
    }
}

fn cr_hex(data: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn cr_ret(out: String) -> LoftStr {
    CRYPTO_BUF.with(|b| {
        *b.borrow_mut() = out;
        let r = b.borrow();
        loft_ffi::ret_ref(r.as_str())
    })
}

/// `#native "n_sha256"` — hex-encoded SHA-256 of `data`.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_sha256(data_ptr: *const u8, data_len: usize) -> LoftStr {
    let data = unsafe { cr_in(data_ptr, data_len) };
    cr_ret(cr_hex(&sha256::sha256(data)))
}

/// `#native "n_hmac_sha256"` — hex-encoded HMAC-SHA-256(key, data).
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_hmac_sha256(
    key_ptr: *const u8,
    key_len: usize,
    data_ptr: *const u8,
    data_len: usize,
) -> LoftStr {
    let key = unsafe { cr_in(key_ptr, key_len) };
    let data = unsafe { cr_in(data_ptr, data_len) };
    cr_ret(cr_hex(&sha256::hmac_sha256(key, data)))
}

/// `#native "n_base64_encode"` — standard base64 of `data`.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_base64_encode(data_ptr: *const u8, data_len: usize) -> LoftStr {
    let data = unsafe { cr_in(data_ptr, data_len) };
    cr_ret(base64::encode(data))
}

/// `#native "n_base64_decode"` — decode standard base64 `data` (lossy UTF-8).
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_base64_decode(data_ptr: *const u8, data_len: usize) -> LoftStr {
    let data = unsafe { cr_in(data_ptr, data_len) };
    let raw = base64::decode(std::str::from_utf8(data).unwrap_or(""));
    cr_ret(String::from_utf8_lossy(&raw).into_owned())
}

/// `#native "n_base64url_encode"` — URL-safe base64 (JWT-style, no padding).
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_base64url_encode(data_ptr: *const u8, data_len: usize) -> LoftStr {
    let data = unsafe { cr_in(data_ptr, data_len) };
    cr_ret(base64::encode_url(data))
}

// ── Ed25519 (RFC 8032) — text-only base64 API ──────────────────────────
//
// All key / message / signature bytes ride as standard base64 `text` so the
// FFI stays text-only.  A loft secret key is the RFC 8032 32-byte seed; the
// public key (32B) and signature (64B) are the dalek-canonical encodings.
// Malformed input never panics — `public_key`/`sign` return "" and `verify`
// returns false (the lib's loft-safe lenient convention).

/// `#native "n_ed25519_public_key"` — 32-byte public key (base64) from a
/// 32-byte secret seed (base64); "" if the seed is not 32 bytes.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_ed25519_public_key(sk_ptr: *const u8, sk_len: usize) -> LoftStr {
    let sk = unsafe { std::str::from_utf8(cr_in(sk_ptr, sk_len)).unwrap_or("") };
    cr_ret(ed25519::public_key(sk))
}

/// `#native "n_ed25519_sign"` — 64-byte Ed25519 signature (base64) over the
/// base64 `message` bytes under the 32-byte secret seed; "" on bad seed.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_ed25519_sign(
    sk_ptr: *const u8,
    sk_len: usize,
    msg_ptr: *const u8,
    msg_len: usize,
) -> LoftStr {
    let sk = unsafe { std::str::from_utf8(cr_in(sk_ptr, sk_len)).unwrap_or("") };
    let msg = unsafe { std::str::from_utf8(cr_in(msg_ptr, msg_len)).unwrap_or("") };
    cr_ret(ed25519::sign(sk, msg))
}

/// `#native "n_ed25519_verify"` — true iff `signature` (base64, 64B) is valid
/// over the base64 `message` bytes under `public_key` (base64, 32B).
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_ed25519_verify(
    pk_ptr: *const u8,
    pk_len: usize,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
    sig_len: usize,
) -> bool {
    let pk = unsafe { std::str::from_utf8(cr_in(pk_ptr, pk_len)).unwrap_or("") };
    let msg = unsafe { std::str::from_utf8(cr_in(msg_ptr, msg_len)).unwrap_or("") };
    let sig = unsafe { std::str::from_utf8(cr_in(sig_ptr, sig_len)).unwrap_or("") };
    ed25519::verify(pk, msg, sig)
}

// The `loft_register!` + `loft_register_bridges!` invocations are generated by
// `build.rs` from the co-located `#native` annotations in `../src/*.loft`
// (loft-ffi-build), so the symbol list lives in exactly one place — adding a
// crypto symbol is a `#native` line + the `#[loft_native]` body above.
include!(concat!(env!("OUT_DIR"), "/loft_register_gen.rs"));
