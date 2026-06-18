// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Native crypto primitives for the `crypto` loft package.  Five `#native`
//! symbols (`n_sha256`, `n_hmac_sha256`, `n_base64_encode`,
//! `n_base64_decode`, `n_base64url_encode`) bridge to zero-dependency
//! pure-Rust SHA-256 / HMAC / base64 impls in `sha256.rs` and `base64.rs`.
//! `n_hmac_sha256_raw` was removed 2026-05-30 along with the loft-side
//! `jwt_sign` it was the sole consumer of.  Moved out of the loft compiler crate in plan-12
//! phase 1a (2026-05-23) to drain library code from `src/native.rs` and
//! `src/codegen_runtime.rs`.
//!
//! ABI matches the package format: text args arrive as `(ptr, len)`
//! pairs; text returns ride a `LoftStr` borrowed from a thread-local
//! buffer (the caller copies the bytes before the next crypto call).

#![allow(clippy::missing_safety_doc)]

use loft_ffi::LoftStr;
use loft_ffi_macros::loft_native;

// v0.3 primitive deps (see the v0.3 section near the bottom of this file).
// base64 (de)coding reuses the crate's own pure-Rust `base64` module below —
// no `base64` crate, keeping the dependency set to the crypto crates only.
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hpke::{
    aead::{AeadTag, ChaCha20Poly1305 as HpkeChaCha},
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
};
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Pub, StaticSecret as X25519Secret};
use zeroize::Zeroizing;
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce as ChaChaNonce, XChaCha20Poly1305, XNonce,
};
use aes_gcm::{Aes256Gcm, Nonce as GcmNonce};

mod base64;
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

// ====================================================================
// v0.3 — Ed25519 / X25519 / HPKE / AEAD / HKDF / CSPRNG
//
// Every function stays within the legacy native-dispatch shapes the
// interpreter supports — `() -> text`, `(text) -> text`, `(text) -> bool`
// — so the package loads on any loft >= 0.8 with no interpreter change.
// Multi-field inputs/outputs are base64-STANDARD values joined with '|'
// (outside the base64 alphabet, so the split is unambiguous; the length
// field of hkdf_expand and the count of random ride as plain decimals,
// also '|'-free).  On error a function returns "" and stashes a message
// retrievable via `crypto_last_error()`.  No homegrown crypto: every
// primitive is a vetted RustCrypto / dalek crate.
// ====================================================================

thread_local! {
    static CRYPTO_ERR: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}

/// Success: clear the error channel and return `out` as the result text.
fn cr_ok(out: String) -> LoftStr {
    CRYPTO_ERR.with(|e| e.borrow_mut().clear());
    cr_ret(out)
}

/// Failure: record `msg` for `crypto_last_error()` and return empty text.
fn cr_err(msg: &str) -> LoftStr {
    CRYPTO_ERR.with(|e| {
        let mut b = e.borrow_mut();
        b.clear();
        b.push_str(msg);
    });
    cr_ret(String::new())
}

fn b64e(b: &[u8]) -> String {
    base64::encode(b)
}

/// A `text` argument as `&str` (valid UTF-8 by the loft ABI; empty if null).
unsafe fn packed_str<'a>(ptr: *const u8, len: usize) -> &'a str {
    std::str::from_utf8(unsafe { cr_in(ptr, len) }).unwrap_or("")
}

/// Split a '|'-joined packed argument into exactly `n` base64-decoded fields.
fn unpack(s: &str, n: usize) -> Result<Vec<Vec<u8>>, String> {
    let parts: Vec<&str> = s.split('|').collect();
    if parts.len() != n {
        return Err(format!("expected {n} packed fields, got {}", parts.len()));
    }
    Ok(parts.into_iter().map(base64::decode).collect())
}

// HPKE suite (fixed): DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20Poly1305.
type HpkeKem = X25519HkdfSha256;
type HpkeAead = HpkeChaCha;
type HpkeKdf = HkdfSha256;
const HPKE_TAG_LEN: usize = 16;

// ── 1. CSPRNG ───────────────────────────────────────────────────────

/// `#native "n_crypto_random"` — base64 of `<count>` OS-CSPRNG bytes.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_crypto_random(ptr: *const u8, len: usize) -> LoftStr {
    let spec = unsafe { packed_str(ptr, len) };
    let n: usize = match spec.trim().parse() {
        Ok(n) => n,
        Err(_) => return cr_err("random: invalid byte count"),
    };
    if n > (1 << 20) {
        return cr_err("random: count out of range (0..=1MB)");
    }
    let mut buf = vec![0u8; n];
    if let Err(e) = getrandom::getrandom(&mut buf) {
        return cr_err(&format!("random: OS CSPRNG failed: {e}"));
    }
    cr_ok(b64e(&buf))
}

// ── 2. Ed25519 (RFC 8032) ───────────────────────────────────────────

/// `#native "n_crypto_ed25519_keypair"` — `"<secret_b64>|<public_b64>"` (32B each).
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_crypto_ed25519_keypair() -> LoftStr {
    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key();
    cr_ok(format!("{}|{}", b64e(&sk.to_bytes()), b64e(pk.as_bytes())))
}

/// `#native "n_crypto_ed25519_sign"` — packed `secret|message` → signature (64B).
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_crypto_ed25519_sign(ptr: *const u8, len: usize) -> LoftStr {
    let f = match unpack(unsafe { packed_str(ptr, len) }, 2) {
        Ok(f) => f,
        Err(e) => return cr_err(&e),
    };
    let sk_bytes = Zeroizing::new(f[0].clone());
    if sk_bytes.len() != 32 {
        return cr_err("ed25519_sign: secret must be 32 bytes");
    }
    let arr: [u8; 32] = sk_bytes[..].try_into().unwrap();
    let sk = SigningKey::from_bytes(&arr);
    let sig: Signature = sk.sign(&f[1]);
    cr_ok(b64e(&sig.to_bytes()))
}

/// `#native "n_crypto_ed25519_verify"` — packed `public|message|signature` → bool.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_crypto_ed25519_verify(ptr: *const u8, len: usize) -> bool {
    let f = match unpack(unsafe { packed_str(ptr, len) }, 3) {
        Ok(f) => f,
        Err(_) => return false,
    };
    if f[0].len() != 32 || f[2].len() != 64 {
        return false;
    }
    let pk_arr: [u8; 32] = f[0][..].try_into().unwrap();
    let sig_arr: [u8; 64] = f[2][..].try_into().unwrap();
    let pk = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(&sig_arr);
    pk.verify(&f[1], &sig).is_ok()
}

// ── 3. X25519 (RFC 7748) ────────────────────────────────────────────

/// `#native "n_crypto_x25519_keypair"` — `"<secret_b64>|<public_b64>"` (32B each).
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_crypto_x25519_keypair() -> LoftStr {
    let sk = X25519Secret::random_from_rng(OsRng);
    let pk: X25519Pub = (&sk).into();
    cr_ok(format!("{}|{}", b64e(&sk.to_bytes()), b64e(pk.as_bytes())))
}

/// `#native "n_crypto_x25519_dh"` — packed `secret|peer_public` → raw DH (32B).
/// Pipe the result through HKDF before use as a key.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_crypto_x25519_dh(ptr: *const u8, len: usize) -> LoftStr {
    let f = match unpack(unsafe { packed_str(ptr, len) }, 2) {
        Ok(f) => f,
        Err(e) => return cr_err(&e),
    };
    if f[0].len() != 32 || f[1].len() != 32 {
        return cr_err("x25519_dh: keys must be 32 bytes");
    }
    let sk_arr: [u8; 32] = f[0][..].try_into().unwrap();
    let pk_arr: [u8; 32] = f[1][..].try_into().unwrap();
    let sk = X25519Secret::from(sk_arr);
    let pk = X25519Pub::from(pk_arr);
    cr_ok(b64e(sk.diffie_hellman(&pk).as_bytes()))
}

// ── 4. HPKE (RFC 9180) ──────────────────────────────────────────────

/// `#native "n_crypto_hpke_seal"` — packed `recipient_pub|info|aad|plaintext`
/// → `"<enc_b64>|<ciphertext_with_tag_b64>"`.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_crypto_hpke_seal(ptr: *const u8, len: usize) -> LoftStr {
    let f = match unpack(unsafe { packed_str(ptr, len) }, 4) {
        Ok(f) => f,
        Err(e) => return cr_err(&e),
    };
    let recipient_pub = match <HpkeKem as KemTrait>::PublicKey::from_bytes(&f[0]) {
        Ok(k) => k,
        Err(_) => return cr_err("hpke_seal: invalid recipient public key"),
    };
    let (encapped, mut sender) = match hpke::setup_sender::<HpkeAead, HpkeKdf, HpkeKem, _>(
        &OpModeS::Base,
        &recipient_pub,
        &f[1],
        &mut OsRng,
    ) {
        Ok(v) => v,
        Err(e) => return cr_err(&format!("hpke_seal: setup failed: {e:?}")),
    };
    let mut ct = f[3].clone();
    let tag: AeadTag<HpkeAead> = match sender.seal_in_place_detached(&mut ct, &f[2]) {
        Ok(t) => t,
        Err(e) => return cr_err(&format!("hpke_seal: seal failed: {e:?}")),
    };
    ct.extend_from_slice(&tag.to_bytes());
    cr_ok(format!("{}|{}", b64e(&encapped.to_bytes()), b64e(&ct)))
}

/// `#native "n_crypto_hpke_open"` — packed `secret|info|aad|enc|ciphertext` → plaintext.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_crypto_hpke_open(ptr: *const u8, len: usize) -> LoftStr {
    let f = match unpack(unsafe { packed_str(ptr, len) }, 5) {
        Ok(f) => f,
        Err(e) => return cr_err(&e),
    };
    let sk_bytes = Zeroizing::new(f[0].clone());
    let recipient_sk = match <HpkeKem as KemTrait>::PrivateKey::from_bytes(&sk_bytes) {
        Ok(k) => k,
        Err(_) => return cr_err("hpke_open: invalid recipient secret key"),
    };
    let encapped = match <HpkeKem as KemTrait>::EncappedKey::from_bytes(&f[3]) {
        Ok(k) => k,
        Err(_) => return cr_err("hpke_open: invalid encapsulated key"),
    };
    let mut receiver =
        match hpke::setup_receiver::<HpkeAead, HpkeKdf, HpkeKem>(&OpModeR::Base, &recipient_sk, &encapped, &f[1]) {
            Ok(v) => v,
            Err(e) => return cr_err(&format!("hpke_open: setup failed: {e:?}")),
        };
    let ct_with_tag = &f[4];
    if ct_with_tag.len() < HPKE_TAG_LEN {
        return cr_err("hpke_open: ciphertext shorter than tag");
    }
    let split = ct_with_tag.len() - HPKE_TAG_LEN;
    let (ct, tag_bytes) = ct_with_tag.split_at(split);
    let tag = match AeadTag::<HpkeAead>::from_bytes(tag_bytes) {
        Ok(t) => t,
        Err(_) => return cr_err("hpke_open: invalid tag"),
    };
    let mut buf = ct.to_vec();
    if let Err(e) = receiver.open_in_place_detached(&mut buf, &f[2], &tag) {
        return cr_err(&format!("hpke_open: auth failed: {e:?}"));
    }
    cr_ok(b64e(&buf))
}

// ── 5. AEAD: ChaCha20-Poly1305 ──────────────────────────────────────

/// `#native "n_crypto_chacha_seal"` — packed `key|nonce|aad|plaintext` → ct||tag.
/// key = 32B, nonce = 12B; caller MUST keep nonces unique per key.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_crypto_chacha_seal(ptr: *const u8, len: usize) -> LoftStr {
    let f = match unpack(unsafe { packed_str(ptr, len) }, 4) {
        Ok(f) => f,
        Err(e) => return cr_err(&e),
    };
    if f[0].len() != 32 || f[1].len() != 12 {
        return cr_err("chacha_seal: key=32B, nonce=12B");
    }
    let cipher = match ChaCha20Poly1305::new_from_slice(&f[0]) {
        Ok(c) => c,
        Err(_) => return cr_err("chacha_seal: bad key length"),
    };
    match cipher.encrypt(ChaChaNonce::from_slice(&f[1]), Payload { msg: &f[3], aad: &f[2] }) {
        Ok(ct) => cr_ok(b64e(&ct)),
        Err(e) => cr_err(&format!("chacha_seal: {e:?}")),
    }
}

/// `#native "n_crypto_chacha_open"` — packed `key|nonce|aad|ciphertext` → plaintext.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_crypto_chacha_open(ptr: *const u8, len: usize) -> LoftStr {
    let f = match unpack(unsafe { packed_str(ptr, len) }, 4) {
        Ok(f) => f,
        Err(e) => return cr_err(&e),
    };
    if f[0].len() != 32 || f[1].len() != 12 {
        return cr_err("chacha_open: key=32B, nonce=12B");
    }
    let cipher = match ChaCha20Poly1305::new_from_slice(&f[0]) {
        Ok(c) => c,
        Err(_) => return cr_err("chacha_open: bad key length"),
    };
    match cipher.decrypt(ChaChaNonce::from_slice(&f[1]), Payload { msg: &f[3], aad: &f[2] }) {
        Ok(pt) => cr_ok(b64e(&pt)),
        Err(_) => cr_err("chacha_open: authentication failed"),
    }
}

// ── 5b. AEAD: XChaCha20-Poly1305 (extended 24-byte nonce) ───────────
//
// The 192-bit nonce makes per-message RANDOM nonces safe: it removes the
// ~2^32-messages-per-key birthday limit of the 96-bit IETF variant.  This
// is the cipher for the direct file/op-body path where a fresh random
// nonce is generated per encryption (see CRYPTO.md).

/// `#native "n_crypto_xchacha_seal"` — packed `key|nonce|aad|plaintext` → ct||tag.
/// key = 32B, nonce = 24B (random per message is safe).
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_crypto_xchacha_seal(ptr: *const u8, len: usize) -> LoftStr {
    let f = match unpack(unsafe { packed_str(ptr, len) }, 4) {
        Ok(f) => f,
        Err(e) => return cr_err(&e),
    };
    if f[0].len() != 32 || f[1].len() != 24 {
        return cr_err("xchacha_seal: key=32B, nonce=24B");
    }
    let cipher = match XChaCha20Poly1305::new_from_slice(&f[0]) {
        Ok(c) => c,
        Err(_) => return cr_err("xchacha_seal: bad key length"),
    };
    match cipher.encrypt(XNonce::from_slice(&f[1]), Payload { msg: &f[3], aad: &f[2] }) {
        Ok(ct) => cr_ok(b64e(&ct)),
        Err(e) => cr_err(&format!("xchacha_seal: {e:?}")),
    }
}

/// `#native "n_crypto_xchacha_open"` — packed `key|nonce|aad|ciphertext` → plaintext.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_crypto_xchacha_open(ptr: *const u8, len: usize) -> LoftStr {
    let f = match unpack(unsafe { packed_str(ptr, len) }, 4) {
        Ok(f) => f,
        Err(e) => return cr_err(&e),
    };
    if f[0].len() != 32 || f[1].len() != 24 {
        return cr_err("xchacha_open: key=32B, nonce=24B");
    }
    let cipher = match XChaCha20Poly1305::new_from_slice(&f[0]) {
        Ok(c) => c,
        Err(_) => return cr_err("xchacha_open: bad key length"),
    };
    match cipher.decrypt(XNonce::from_slice(&f[1]), Payload { msg: &f[3], aad: &f[2] }) {
        Ok(pt) => cr_ok(b64e(&pt)),
        Err(_) => cr_err("xchacha_open: authentication failed"),
    }
}

// ── 6. AEAD: AES-256-GCM ────────────────────────────────────────────

/// `#native "n_crypto_aes_seal"` — packed `key|nonce|aad|plaintext` → ct||tag.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_crypto_aes_seal(ptr: *const u8, len: usize) -> LoftStr {
    let f = match unpack(unsafe { packed_str(ptr, len) }, 4) {
        Ok(f) => f,
        Err(e) => return cr_err(&e),
    };
    if f[0].len() != 32 || f[1].len() != 12 {
        return cr_err("aes_seal: key=32B, nonce=12B");
    }
    let cipher = match Aes256Gcm::new_from_slice(&f[0]) {
        Ok(c) => c,
        Err(_) => return cr_err("aes_seal: bad key length"),
    };
    match cipher.encrypt(GcmNonce::from_slice(&f[1]), Payload { msg: &f[3], aad: &f[2] }) {
        Ok(ct) => cr_ok(b64e(&ct)),
        Err(e) => cr_err(&format!("aes_seal: {e:?}")),
    }
}

/// `#native "n_crypto_aes_open"` — packed `key|nonce|aad|ciphertext` → plaintext.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_crypto_aes_open(ptr: *const u8, len: usize) -> LoftStr {
    let f = match unpack(unsafe { packed_str(ptr, len) }, 4) {
        Ok(f) => f,
        Err(e) => return cr_err(&e),
    };
    if f[0].len() != 32 || f[1].len() != 12 {
        return cr_err("aes_open: key=32B, nonce=12B");
    }
    let cipher = match Aes256Gcm::new_from_slice(&f[0]) {
        Ok(c) => c,
        Err(_) => return cr_err("aes_open: bad key length"),
    };
    match cipher.decrypt(GcmNonce::from_slice(&f[1]), Payload { msg: &f[3], aad: &f[2] }) {
        Ok(pt) => cr_ok(b64e(&pt)),
        Err(_) => cr_err("aes_open: authentication failed"),
    }
}

// ── 7. HKDF over SHA-256 ────────────────────────────────────────────

/// `#native "n_crypto_hkdf_extract"` — packed `salt|ikm` → 32-byte PRK. Salt may be empty.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_crypto_hkdf_extract(ptr: *const u8, len: usize) -> LoftStr {
    let f = match unpack(unsafe { packed_str(ptr, len) }, 2) {
        Ok(f) => f,
        Err(e) => return cr_err(&e),
    };
    let salt_opt = if f[0].is_empty() { None } else { Some(f[0].as_slice()) };
    let (prk, _hk) = Hkdf::<Sha256>::extract(salt_opt, &f[1]);
    cr_ok(b64e(prk.as_slice()))
}

/// `#native "n_crypto_hkdf_expand"` — packed `prk|info|<length>` → `length` bytes OKM.
/// `length` is a plain decimal (1..=8160); `prk`/`info` are base64.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_crypto_hkdf_expand(ptr: *const u8, len: usize) -> LoftStr {
    let packed = unsafe { packed_str(ptr, len) };
    let parts: Vec<&str> = packed.split('|').collect();
    if parts.len() != 3 {
        return cr_err("hkdf_expand: expected prk|info|length");
    }
    let prk = Zeroizing::new(base64::decode(parts[0]));
    let info = base64::decode(parts[1]);
    let length: usize = match parts[2].trim().parse() {
        Ok(n) => n,
        Err(_) => return cr_err("hkdf_expand: bad length"),
    };
    if length < 1 || length > 8160 {
        return cr_err("hkdf_expand: length must be 1..=8160");
    }
    let hk = match Hkdf::<Sha256>::from_prk(&prk) {
        Ok(h) => h,
        Err(_) => return cr_err("hkdf_expand: PRK shorter than HashLen"),
    };
    let mut okm = vec![0u8; length];
    if hk.expand(&info, &mut okm).is_err() {
        return cr_err("hkdf_expand: expand failed");
    }
    cr_ok(b64e(&okm))
}

// ── Diagnostics ─────────────────────────────────────────────────────

/// `#native "n_crypto_last_error"` — last error on this thread, or "".
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_crypto_last_error() -> LoftStr {
    CRYPTO_ERR.with(|e| {
        let r = e.borrow();
        loft_ffi::ret_ref(r.as_str())
    })
}

// @PLAN12 phase 2 final step (2026-05-24): the `loft_ffi::loft_register!`
// invocation is generated by `build.rs` from
// `lib/crypto/loft.toml::[native.functions]`, so the symbol list lives in
// exactly one place.  Adding a new crypto symbol is now a single edit to
// `loft.toml` (plus the `pub unsafe extern "C" fn` body above).
include!(concat!(env!("OUT_DIR"), "/loft_register_gen.rs"));
