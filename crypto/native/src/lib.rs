// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Native crypto primitives for the `crypto` loft package.  SHA-256, HMAC,
//! base64, Ed25519 (RFC 8032) signatures, X25519 (RFC 7748) key agreement,
//! HKDF-SHA256 (RFC 5869), AES-256-GCM AEAD, and an OS CSPRNG.  The hashing /
//! base64 symbols bridge to zero-dependency pure-Rust impls in `sha256.rs` /
//! `base64.rs`; the asymmetric, KDF, AEAD, and RNG primitives wrap the vetted
//! RustCrypto + dalek crates (`ed25519.rs`, `x25519.rs`, `hkdf.rs`,
//! `aes256gcm.rs`, `random.rs`).
//!
//! Every exported `n_*` fn carries `#[loft_native]`, so the build script emits
//! a `loft_register_bridges_v1` table and the interpreter dispatches through
//! the generated uniform marshal bridges (the legacy raw-ptr arm-set is gone).
//!
//! ABI matches the package format: text args arrive as `(ptr, len)`
//! pairs; text returns ride a `LoftStr` borrowed from a thread-local
//! buffer (the caller copies the bytes before the next crypto call).

#![allow(clippy::missing_safety_doc)]

use loft_ffi::{LoftRef, LoftStore, LoftStr};
use loft_ffi_macros::loft_native;

mod aes256gcm;
mod base64;
mod ed25519;
mod hkdf;
mod hpke_bytes;
mod random;
mod sha256;
mod x25519;

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

// ── X25519 ECDH (RFC 7748) — text-only base64 API ──────────────────────
//
// A loft secret key is a 32-byte X25519 scalar (base64); a public key is the
// 32-byte u-coordinate (base64); the shared secret is the raw 32-byte DH
// output (base64).  Wrong-length input returns "" (lenient convention).

/// `#native "n_x25519_dh"` — 32-byte X25519 shared secret (base64) from our
/// secret scalar (base64, 32B) and the peer's public key (base64, 32B); ""
/// if either is the wrong length.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_x25519_dh(
    sk_ptr: *const u8,
    sk_len: usize,
    pk_ptr: *const u8,
    pk_len: usize,
) -> LoftStr {
    let sk = unsafe { std::str::from_utf8(cr_in(sk_ptr, sk_len)).unwrap_or("") };
    let pk = unsafe { std::str::from_utf8(cr_in(pk_ptr, pk_len)).unwrap_or("") };
    cr_ret(x25519::dh(sk, pk))
}

// ── HKDF-SHA256 (RFC 5869) — text-only base64 API ──────────────────────
//
// salt / ikm / info are base64 bytes; the okm is base64.  An empty base64
// salt selects the RFC 5869 §2.2 all-zero salt.  `length` is the OKM byte
// count; "" if it exceeds 255*32 or is non-positive.

/// `#native "n_hkdf_sha256"` — `length` bytes of HKDF-SHA256 OKM (base64) from
/// salt/ikm/info (each base64); "" if length > 255*32 or length <= 0.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_hkdf_sha256(
    salt_ptr: *const u8,
    salt_len: usize,
    ikm_ptr: *const u8,
    ikm_len: usize,
    info_ptr: *const u8,
    info_len: usize,
    length: i32,
) -> LoftStr {
    let salt = unsafe { std::str::from_utf8(cr_in(salt_ptr, salt_len)).unwrap_or("") };
    let ikm = unsafe { std::str::from_utf8(cr_in(ikm_ptr, ikm_len)).unwrap_or("") };
    let info = unsafe { std::str::from_utf8(cr_in(info_ptr, info_len)).unwrap_or("") };
    cr_ret(hkdf::sha256(salt, ikm, info, length))
}

/// `#native "n_hkdf_extract"` — HKDF-Extract: the 32-byte PRK (base64)
/// `HMAC-SHA256(salt, ikm)`.  An empty base64 `salt` selects the all-zero salt.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_hkdf_extract(
    salt_ptr: *const u8,
    salt_len: usize,
    ikm_ptr: *const u8,
    ikm_len: usize,
) -> LoftStr {
    let salt = unsafe { std::str::from_utf8(cr_in(salt_ptr, salt_len)).unwrap_or("") };
    let ikm = unsafe { std::str::from_utf8(cr_in(ikm_ptr, ikm_len)).unwrap_or("") };
    cr_ret(hkdf::extract(salt, ikm))
}

/// `#native "n_hkdf_expand"` — HKDF-Expand from an existing 32-byte PRK:
/// `length` bytes of OKM (base64); "" on a short PRK, length > 255*32, or
/// length <= 0.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_hkdf_expand(
    prk_ptr: *const u8,
    prk_len: usize,
    info_ptr: *const u8,
    info_len: usize,
    length: i32,
) -> LoftStr {
    let prk = unsafe { std::str::from_utf8(cr_in(prk_ptr, prk_len)).unwrap_or("") };
    let info = unsafe { std::str::from_utf8(cr_in(info_ptr, info_len)).unwrap_or("") };
    cr_ret(hkdf::expand(prk, info, length))
}

// ── Raw-byte <-> base64 bridges (for HPKE labeled-string composition) ───
//
// loft `text` is UTF-8-validated, so non-UTF-8 byte strings (DH outputs,
// PRKs, the labeled `suite_id` bytes) cannot ride as `text`.  loft assembles
// them in a `vector<u8>` and crosses the base64 boundary through these two
// inverse bridges.  The `LoftStore` first param is supplied by the bridge.

/// `#native "n_bytes_to_base64"` — standard base64 `text` of a `vector<u8>`.
/// A null / empty vector encodes to "".
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_bytes_to_base64(store: LoftStore, bytes: LoftRef) -> LoftStr {
    cr_ret(unsafe { hpke_bytes::encode(&store, &bytes) })
}

/// `#native "n_base64_to_bytes"` — `vector<u8>` from standard base64 `text`.
/// A malformed or empty string yields an empty vector.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_base64_to_bytes(
    mut store: LoftStore,
    b64_ptr: *const u8,
    b64_len: usize,
) -> LoftRef {
    let b64 = unsafe { std::str::from_utf8(cr_in(b64_ptr, b64_len)).unwrap_or("") };
    unsafe { hpke_bytes::decode(&mut store, b64) }
}

/// `#native "n_bytes_concat_b64"` — base64 of `bytes(a) || bytes(b)`.
///
/// Text-in / text-out (no store interaction), so loft assembles labeled byte
/// strings by repeated concatenation without a store-allocated `vector<u8>`.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_bytes_concat_b64(
    a_ptr: *const u8,
    a_len: usize,
    b_ptr: *const u8,
    b_len: usize,
) -> LoftStr {
    let a = unsafe { std::str::from_utf8(cr_in(a_ptr, a_len)).unwrap_or("") };
    let b = unsafe { std::str::from_utf8(cr_in(b_ptr, b_len)).unwrap_or("") };
    cr_ret(hpke_bytes::concat_b64(a, b))
}

// ── AES-256-GCM AEAD — text-only base64 API ────────────────────────────
//
// key (32B) / nonce (12B) / aad / plaintext|ciphertext are base64.  `seal`
// returns ciphertext||tag (16-byte tag appended); `open` returns "" on any
// authentication failure.  A nonce MUST NOT repeat under one key.

/// `#native "n_aes256gcm_seal"` — base64 of (ciphertext||16-byte-tag) for
/// `plaintext` under key (32B)/nonce (12B), binding `aad`; "" on bad lengths.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_aes256gcm_seal(
    key_ptr: *const u8,
    key_len: usize,
    nonce_ptr: *const u8,
    nonce_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    pt_ptr: *const u8,
    pt_len: usize,
) -> LoftStr {
    let key = unsafe { std::str::from_utf8(cr_in(key_ptr, key_len)).unwrap_or("") };
    let nonce = unsafe { std::str::from_utf8(cr_in(nonce_ptr, nonce_len)).unwrap_or("") };
    let aad = unsafe { std::str::from_utf8(cr_in(aad_ptr, aad_len)).unwrap_or("") };
    let pt = unsafe { std::str::from_utf8(cr_in(pt_ptr, pt_len)).unwrap_or("") };
    cr_ret(aes256gcm::seal(key, nonce, aad, pt))
}

/// `#native "n_aes256gcm_open"` — base64 plaintext for `ciphertext`
/// (ciphertext||tag, base64) under key (32B)/nonce (12B), binding `aad`; ""
/// on authentication failure or bad lengths.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_aes256gcm_open(
    key_ptr: *const u8,
    key_len: usize,
    nonce_ptr: *const u8,
    nonce_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    ct_ptr: *const u8,
    ct_len: usize,
) -> LoftStr {
    let key = unsafe { std::str::from_utf8(cr_in(key_ptr, key_len)).unwrap_or("") };
    let nonce = unsafe { std::str::from_utf8(cr_in(nonce_ptr, nonce_len)).unwrap_or("") };
    let aad = unsafe { std::str::from_utf8(cr_in(aad_ptr, aad_len)).unwrap_or("") };
    let ct = unsafe { std::str::from_utf8(cr_in(ct_ptr, ct_len)).unwrap_or("") };
    cr_ret(aes256gcm::open(key, nonce, aad, ct))
}

// ── CSPRNG — OS random bytes ────────────────────────────────────────────

/// `#native "n_random_bytes"` — `length` OS-CSPRNG random bytes (base64); ""
/// for length <= 0 or an OS RNG failure.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_random_bytes(length: i32) -> LoftStr {
    cr_ret(random::bytes(length))
}

// The `loft_register!` + `loft_register_bridges!` invocations are generated by
// `build.rs` from the co-located `#native` annotations in `../src/*.loft`
// (loft-ffi-build), so the symbol list lives in exactly one place — adding a
// crypto symbol is a `#native` line + the `#[loft_native]` body above.
include!(concat!(env!("OUT_DIR"), "/loft_register_gen.rs"));
