// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Browser-WASM bridge for the `crypto` library.
//!
//! `loft --html` routes each `#native "n_<x>"` whose symbol appears in the
//! `[wasm.bridge].routes` table (`loft.toml`) to the matching `pub fn` here; the
//! generated standalone Rust binary links this crate as `--extern crypto_wasm=…`
//! and calls the bridge directly (no cdylib `dlopen`, no `State` indirection at
//! runtime, so neither the native cdylib ABI nor the interpreter `replace_native`
//! mechanism applies).  A text-returning `#native` already has a `-> String`
//! wrapper, so a `text -> text` bridge returns the `String` directly with no store
//! reshaping (the loft #407 convention); a `boolean` return is emitted `as u8`.
//!
//! Two sourcing strategies, chosen by the primitive's dependencies:
//!
//! * **shared** (hashing + base64) — the native crate's SHA-256/HMAC and base64
//!   live in ZERO-DEPENDENCY modules, so the bridge includes the SAME source via
//!   `#[path]`.  The `--html` bridge build threads only `--extern loft=…`, so a
//!   dependency-free module compiles unchanged here, and *sharing* (not
//!   re-transcribing) keeps native and wasm byte-identical BY CONSTRUCTION — the
//!   one-home rule, no second implementation to drift.
//! * **re-implemented** (HKDF) — HKDF's native module sits on the RustCrypto `hkdf`
//!   crate, which the `--extern loft`-only bridge build cannot resolve.  HKDF is a
//!   thin, fully-specified (RFC 5869) construction over the shared `hmac_sha256`,
//!   so it is re-expressed here and pinned to the RFC 5869 Appendix-A vectors on
//!   BOTH backends: two correct RFC-5869 implementations agree on every input, so
//!   the KAT proves `native == wasm`.
//!
//! The curve / AEAD / CSPRNG primitives (ed25519, x25519, aes256gcm, random_bytes)
//! sit on dalek / RustCrypto / OsRng and must NOT be hand-rolled.  They are
//! intentionally ABSENT from the routes table until the build-extension path
//! (compile this crate's vetted deps to wasm) lands (@PLN84 ZT-B): an unrouted
//! `#native` on wasm is a clean compile/link error, never a wrong answer.

#![allow(dead_code)] // exposed for codegen-emitted call sites

use loft::database::Stores;

// Shared with native — same source, zero external deps => byte-identical output.
#[path = "../../native/src/sha256.rs"]
mod sha256;
#[path = "../../native/src/base64.rs"]
mod base64;

fn hex(data: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ── Hashing — raw text bytes -> hex digest ──────────────────────────────────

/// `crypto::sha256(data: text) -> text` — hex SHA-256 of the raw `data` bytes.
pub fn crypto_sha256(_stores: &mut Stores, data: &str) -> String {
    hex(&sha256::sha256(data.as_bytes()))
}

/// `crypto::hmac_sha256(key: text, data: text) -> text` — hex HMAC-SHA256.
pub fn crypto_hmac_sha256(_stores: &mut Stores, key: &str, data: &str) -> String {
    hex(&sha256::hmac_sha256(key.as_bytes(), data.as_bytes()))
}

// ── base64 — raw text bytes <-> base64 text ─────────────────────────────────

/// `crypto::base64_encode(data: text) -> text` — standard base64 of `data` bytes.
pub fn crypto_base64_encode(_stores: &mut Stores, data: &str) -> String {
    base64::encode(data.as_bytes())
}

/// `crypto::base64_decode(data: text) -> text` — standard base64 decode (lossy UTF-8),
/// matching the native `n_base64_decode` contract.
pub fn crypto_base64_decode(_stores: &mut Stores, data: &str) -> String {
    String::from_utf8_lossy(&base64::decode(data)).into_owned()
}

/// `crypto::base64url_encode(data: text) -> text` — URL-safe base64, no padding.
pub fn crypto_base64url_encode(_stores: &mut Stores, data: &str) -> String {
    base64::encode_url(data.as_bytes())
}

// ── HKDF-SHA256 (RFC 5869) — base64 in/out, over the shared hmac_sha256 ──────

/// HKDF-Extract (RFC 5869 §2.2): `PRK = HMAC-SHA256(salt, ikm)`, with an empty
/// salt selecting the HashLen-zero default salt (HMAC zero-pads the key to the
/// 64-byte block, so 32 zeros and the RFC default coincide).
fn hkdf_extract_raw(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let zeros = [0u8; 32];
    let salt = if salt.is_empty() { &zeros[..] } else { salt };
    sha256::hmac_sha256(salt, ikm)
}

/// HKDF-Expand (RFC 5869 §2.3) from a >=32-byte PRK.  `None` on a short PRK or
/// `length` outside `1..=255*32` — the native lib's lenient `""` cases.
fn hkdf_expand_raw(prk: &[u8], info: &[u8], length: usize) -> Option<Vec<u8>> {
    if prk.len() < 32 || length == 0 || length > 255 * 32 {
        return None;
    }
    let n = length.div_ceil(32);
    let mut okm = Vec::with_capacity(n * 32);
    let mut t: Vec<u8> = Vec::new();
    for i in 1..=n {
        let mut input = t.clone(); // T(i-1)
        input.extend_from_slice(info);
        input.push(i as u8);
        t = sha256::hmac_sha256(prk, &input).to_vec();
        okm.extend_from_slice(&t);
    }
    okm.truncate(length);
    Some(okm)
}

/// `crypto::hkdf_extract(salt_b64, ikm_b64) -> text` — base64 32-byte PRK.
pub fn crypto_hkdf_extract(_stores: &mut Stores, salt_b64: &str, ikm_b64: &str) -> String {
    let prk = hkdf_extract_raw(&base64::decode(salt_b64), &base64::decode(ikm_b64));
    base64::encode(&prk)
}

/// `crypto::hkdf_expand(prk_b64, info_b64, length) -> text` — base64 OKM; "" on error.
pub fn crypto_hkdf_expand(
    _stores: &mut Stores,
    prk_b64: &str,
    info_b64: &str,
    length: i32,
) -> String {
    if length <= 0 {
        return String::new();
    }
    match hkdf_expand_raw(
        &base64::decode(prk_b64),
        &base64::decode(info_b64),
        length as usize,
    ) {
        Some(okm) => base64::encode(&okm),
        None => String::new(),
    }
}

/// `crypto::hkdf_sha256(salt_b64, ikm_b64, info_b64, length) -> text` — base64 OKM
/// (extract-then-expand); "" if `length <= 0` or `length > 255*32`.
pub fn crypto_hkdf_sha256(
    _stores: &mut Stores,
    salt_b64: &str,
    ikm_b64: &str,
    info_b64: &str,
    length: i32,
) -> String {
    if length <= 0 {
        return String::new();
    }
    let prk = hkdf_extract_raw(&base64::decode(salt_b64), &base64::decode(ikm_b64));
    match hkdf_expand_raw(&prk, &base64::decode(info_b64), length as usize) {
        Some(okm) => base64::encode(&okm),
        None => String::new(),
    }
}
