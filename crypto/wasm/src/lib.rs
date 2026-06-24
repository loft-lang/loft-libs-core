// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Browser-WASM bridge for the `crypto` library.
//!
//! `loft --html` routes each `#native "n_<x>"` whose symbol appears in the
//! `[wasm.bridge].routes` table (`loft.toml`) to the matching `pub fn` here; the
//! generated standalone Rust binary links this crate as `--extern crypto_wasm=…`
//! and calls the bridge directly (no cdylib `dlopen`, no `State` indirection at
//! runtime).  A text-returning `#native` already has a `-> String` wrapper, so a
//! `text -> text` bridge returns the `String` directly with no store reshaping
//! (the loft #407 convention); a `boolean` return is emitted `as u8`.
//!
//! Every primitive is **SHARED** byte-identical with native via `#[path]` — the
//! bridge imports the SAME source modules the native cdylib uses, so `native ==
//! wasm` holds BY CONSTRUCTION (one home, no second implementation to drift):
//!
//! * **Zero-dep modules** (`sha256.rs`, `base64.rs`) compile under the
//!   `--extern loft`-only bridge build directly.
//! * **dalek / RustCrypto modules** (`ed25519.rs`, `x25519.rs`, `aes256gcm.rs`)
//!   need the vetted crates (Cargo.toml).  `loft --html` provides them to rustc
//!   via a `-L dependency=…` search path built from this crate's manifest (the
//!   build-extension in `src/main.rs`).  Their deterministic ops — sign / verify /
//!   diffie_hellman / seal / open — need NO RNG, so the crates compile to
//!   wasm32-unknown-unknown without getrandom or wasm-bindgen.
//!
//! HKDF is the one re-implementation: its native module sits on the RustCrypto
//! `hkdf` crate; here it is a pure-Rust RFC-5869 expansion over the shared
//! `hmac_sha256`, pinned to the RFC 5869 Appendix-A vectors on both backends.
//!
//! `random_bytes` is the one HOST-IMPORT bridge (not pure compute): it needs OS
//! entropy, which on wasm is the synchronous `crypto.getRandomValues` exposed by
//! `wasm/host.js` as the `loft_crypto.random_fill` import — the one Web Crypto call
//! that is not a Promise, so it fits loft's synchronous host ABI.

#![allow(dead_code)] // exposed for codegen-emitted call sites

use loft::database::Stores;
use loft::keys::DbRef;

// Shared with native — same source => byte-identical output.  The first two are
// dependency-free; the last three pull the dalek/RustCrypto crates (Cargo.toml),
// which `loft --html` compiles to wasm32 and threads in via `-L dependency`.
#[path = "../../native/src/sha256.rs"]
mod sha256;
#[path = "../../native/src/base64.rs"]
mod base64;
#[path = "../../native/src/ed25519.rs"]
mod ed25519;
#[path = "../../native/src/x25519.rs"]
mod x25519;
#[path = "../../native/src/aes256gcm.rs"]
mod aes256gcm;

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

/// `crypto::sha256_b64(data_b64: text) -> text` — base64 SHA-256 of the raw bytes
/// decoded from base64 `data_b64`.  Lets callers hash arbitrary (non-UTF-8) bytes;
/// mirrors the native `n_sha256_b64` (the `content_hash` path, §4/§6).
pub fn crypto_sha256_b64(_stores: &mut Stores, data_b64: &str) -> String {
    base64::encode(&sha256::sha256(&base64::decode(data_b64)))
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

// ── Raw-byte <-> base64 (the ztcbor signing / content_hash path) ────────────
//
// loft `text` is UTF-8-validated, so non-UTF-8 byte strings (DH outputs, digests,
// canonical-CBOR records) cannot ride as `text`; loft assembles them in a
// `vector<u8>` and crosses the base64 boundary here.  The two vector<u8> bridges
// read / allocate the byte vector in the IN-PROCESS loft store through the SAME
// layout `Stores::fs_read_bytes` / `fs_write_bytes` use (element stride 1: a
// 4-byte outer vector pointer to an inner record whose payload is one byte per
// element) — so `native == wasm` holds by construction.  `bytes_concat_b64` is
// pure text-in / text-out and never touches the store.

/// `crypto::bytes_to_base64(bytes: vector<u8>) -> text` — standard base64 of a
/// `vector<u8>`.  A null / empty vector encodes to "".  Reads the byte payload
/// exactly as `Stores::fs_write_bytes` does.
pub fn crypto_bytes_to_base64(stores: &mut Stores, bytes: &DbRef) -> String {
    let length = loft::vector::length_vector(bytes, &stores.allocations);
    let data: Vec<u8> = if bytes.rec == 0 || bytes.pos == 0 || length == 0 {
        Vec::new()
    } else {
        let store = stores.store_mut(bytes);
        let vec_rec = store.get_u32_raw(bytes.rec, bytes.pos);
        if vec_rec == 0 {
            Vec::new()
        } else {
            store.buffer(vec_rec)[..length as usize].to_vec()
        }
    };
    base64::encode(&data)
}

/// `crypto::base64_to_bytes(b64: text) -> vector<u8>` — `vector<u8>` from standard
/// base64 `text`.  A malformed / empty string yields an empty vector.  Allocates
/// the result vector exactly as `Stores::fs_read_bytes` does (stride 1).
pub fn crypto_base64_to_bytes(stores: &mut Stores, b64: &str) -> DbRef {
    let data = base64::decode(b64);
    let vec = stores.database(4);
    let count = data.len() as u32;
    let rec = loft::vector::alloc_vector_from_bytes(stores.store_mut(&vec), 1, count, &data);
    stores.store_mut(&vec).set_u32_raw(vec.rec, vec.pos, rec);
    vec
}

/// `crypto::bytes_concat_b64(a_b64, b_b64: text) -> text` — base64 of
/// `bytes(a) || bytes(b)`.  Pure text-in / text-out (no store interaction), so
/// loft can assemble labeled byte strings by repeated concatenation.
pub fn crypto_bytes_concat_b64(_stores: &mut Stores, a_b64: &str, b_b64: &str) -> String {
    let mut bytes = base64::decode(a_b64);
    bytes.extend_from_slice(&base64::decode(b_b64));
    base64::encode(&bytes)
}

// ── HKDF-SHA256 (RFC 5869) — base64 in/out, over the shared hmac_sha256 ──────

/// HKDF-Extract (RFC 5869 §2.2): `PRK = HMAC-SHA256(salt, ikm)`, with an empty
/// salt selecting the HashLen-zero default salt.
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

// ── Ed25519 (RFC 8032) — base64 in/out, SHARED with native ──────────────────

/// `crypto::ed25519_public_key(secret_key_b64) -> text` — 32-byte public key.
pub fn crypto_ed25519_public_key(_stores: &mut Stores, sk_b64: &str) -> String {
    ed25519::public_key(sk_b64)
}

/// `crypto::ed25519_sign(secret_key_b64, message_b64) -> text` — 64-byte signature.
pub fn crypto_ed25519_sign(_stores: &mut Stores, sk_b64: &str, msg_b64: &str) -> String {
    ed25519::sign(sk_b64, msg_b64)
}

/// `crypto::ed25519_verify(public_key_b64, message_b64, signature_b64) -> boolean`.
pub fn crypto_ed25519_verify(
    _stores: &mut Stores,
    pk_b64: &str,
    msg_b64: &str,
    sig_b64: &str,
) -> bool {
    ed25519::verify(pk_b64, msg_b64, sig_b64)
}

// ── X25519 ECDH (RFC 7748) — base64 in/out, SHARED with native ──────────────

/// `crypto::x25519_dh(secret_key_b64, public_key_b64) -> text` — 32-byte shared secret.
pub fn crypto_x25519_dh(_stores: &mut Stores, sk_b64: &str, pk_b64: &str) -> String {
    x25519::dh(sk_b64, pk_b64)
}

// ── AES-256-GCM AEAD — base64 in/out, SHARED with native ────────────────────

/// `crypto::aes256gcm_seal(key_b64, nonce_b64, aad_b64, plaintext_b64) -> text`.
pub fn crypto_aes256gcm_seal(
    _stores: &mut Stores,
    key_b64: &str,
    nonce_b64: &str,
    aad_b64: &str,
    pt_b64: &str,
) -> String {
    aes256gcm::seal(key_b64, nonce_b64, aad_b64, pt_b64)
}

/// `crypto::aes256gcm_open(key_b64, nonce_b64, aad_b64, ciphertext_b64) -> text`.
pub fn crypto_aes256gcm_open(
    _stores: &mut Stores,
    key_b64: &str,
    nonce_b64: &str,
    aad_b64: &str,
    ct_b64: &str,
) -> String {
    aes256gcm::open(key_b64, nonce_b64, aad_b64, ct_b64)
}

// ── CSPRNG — random_bytes via a synchronous getRandomValues host import ──────

// Host import: fill `[ptr, ptr+len)` of wasm linear memory with CSPRNG bytes.
// Provided by `wasm/host.js` via the browser's synchronous `crypto.getRandomValues`
// — the one Web Crypto call that is NOT a Promise, so it suits loft's synchronous
// host ABI (unlike `crypto.subtle.*`, which would need asyncify — that is B2).
#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "loft_crypto")]
unsafe extern "C" {
    fn random_fill(ptr: *mut u8, len: usize);
}

/// `crypto::random_bytes(length) -> text` — base64 of `length` CSPRNG bytes; "" for
/// `length <= 0`.  On wasm the entropy is the host's `crypto.getRandomValues`; a
/// non-wasm build (never exercised — native uses the cdylib's OsRng) leaves the
/// buffer zeroed, kept only so the bridge crate compiles for `cargo check`.
pub fn crypto_random_bytes(_stores: &mut Stores, length: i32) -> String {
    if length <= 0 {
        return String::new();
    }
    let mut buf = vec![0u8; length as usize];
    // SAFETY: the host fills exactly `buf.len()` bytes at the buffer's pointer.
    #[cfg(target_arch = "wasm32")]
    unsafe {
        random_fill(buf.as_mut_ptr(), buf.len());
    }
    base64::encode(&buf)
}
