// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later

//! AES-256-GCM authenticated encryption (AEAD) over the `aes-gcm` crate.
//!
//! Mirrors the library's text-only base64 convention: key, nonce, additional
//! authenticated data (AAD), and plaintext/ciphertext are base64 `text`.  The
//! key is 32 bytes (AES-256) and the nonce is 12 bytes (the standard 96-bit
//! GCM IV).  `seal` returns the ciphertext with the 16-byte authentication tag
//! APPENDED (the RustCrypto detached-tag-free convention), so `open` of the
//! same blob recovers the plaintext.
//!
//! Loft-safe: a wrong-length key/nonce, malformed ciphertext, or a failed
//! authentication tag never panics — `seal` and `open` return `""` (the
//! library's lenient convention).  An empty `open` result therefore means
//! "rejected", which the caller MUST treat as a failure, not as the empty
//! plaintext (a genuine empty plaintext seals to a 16-byte tag-only blob, so a
//! valid empty-plaintext decrypt returns `""` too — callers needing to encrypt
//! empty data should compare against the known tag length, or wrap a length
//! prefix).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};

/// Base64-decode `b64` into exactly `N` bytes, or `None` on any mismatch.
fn decode_fixed<const N: usize>(b64: &str) -> Option<[u8; N]> {
    let bytes = crate::base64::decode(b64);
    if bytes.len() != N {
        return None;
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

/// Encrypt + authenticate `plaintext` under a 32-byte `key` and 12-byte
/// `nonce`, binding `aad`.
///
/// Returns base64 of `ciphertext || tag` (the 16-byte GCM tag appended), or
/// `""` if the key is not 32 bytes or the nonce is not 12 bytes.  A nonce MUST
/// NOT be reused with the same key (GCM is catastrophically insecure under
/// nonce reuse) — derive a fresh nonce per message (e.g. `random_bytes(12)`).
#[must_use]
pub fn seal(key_b64: &str, nonce_b64: &str, aad_b64: &str, plaintext_b64: &str) -> String {
    let Some(key_bytes) = decode_fixed::<32>(key_b64) else {
        return String::new();
    };
    let Some(nonce_bytes) = decode_fixed::<12>(nonce_b64) else {
        return String::new();
    };
    let aad = crate::base64::decode(aad_b64);
    let plaintext = crate::base64::decode(plaintext_b64);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);
    match cipher.encrypt(
        nonce,
        Payload {
            msg: &plaintext,
            aad: &aad,
        },
    ) {
        // `encrypt` already appends the 16-byte tag to the ciphertext.
        Ok(ct_and_tag) => crate::base64::encode(&ct_and_tag),
        Err(_) => String::new(),
    }
}

/// Verify + decrypt `ciphertext` (base64 of `ciphertext || tag`) under a
/// 32-byte `key` and 12-byte `nonce`, binding `aad`.
///
/// Returns the base64 plaintext, or `""` if the key/nonce length is wrong, the
/// blob is too short to hold a tag, or — most importantly — the authentication
/// tag does not verify (a tampered ciphertext, tag, aad, key, or nonce).  An
/// empty result MUST be treated as authentication failure.
#[must_use]
pub fn open(key_b64: &str, nonce_b64: &str, aad_b64: &str, ciphertext_b64: &str) -> String {
    let Some(key_bytes) = decode_fixed::<32>(key_b64) else {
        return String::new();
    };
    let Some(nonce_bytes) = decode_fixed::<12>(nonce_b64) else {
        return String::new();
    };
    let aad = crate::base64::decode(aad_b64);
    let ct_and_tag = crate::base64::decode(ciphertext_b64);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);
    match cipher.decrypt(
        nonce,
        Payload {
            msg: &ct_and_tag,
            aad: &aad,
        },
    ) {
        Ok(plaintext) => crate::base64::encode(&plaintext),
        Err(_) => String::new(), // tag mismatch / too short — authentication failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Project Wycheproof `aes_gcm_test.json` tcId 91 (keySize 256, ivSize 96,
    // tagSize 128, result "valid").  All values hex → base64.
    //   key = 92ace3e348cd821092cd921aa3546374299ab46209691bc28b8752d17f123c20
    //   iv  = 00112233445566778899aabb
    //   aad = 00000000ffffffff
    //   msg = 00010203040506070809
    //   ct  = e27abdd2d2a53d2f136b
    //   tag = 9a4a2579529301bcfb71c78d4060f52c
    const KEY: &str = "kqzj40jNghCSzZIao1RjdCmatGIJaRvCi4dS0X8SPCA=";
    const NONCE: &str = "ABEiM0RVZneImaq7";
    const AAD: &str = "AAAAAP////8=";
    const PLAINTEXT: &str = "AAECAwQFBgcICQ==";
    // ct || tag, base64.
    const CT_AND_TAG: &str = "4nq90tKlPS8Ta5pKJXlSkwG8+3HHjUBg9Sw=";
    // Same blob with the final tag byte 0x2c flipped to 0x2d.
    const CT_AND_TAMPERED_TAG: &str = "4nq90tKlPS8Ta5pKJXlSkwG8+3HHjUBg9S0=";

    #[test]
    fn wycheproof_tc91_seal_matches_vector() {
        assert_eq!(seal(KEY, NONCE, AAD, PLAINTEXT), CT_AND_TAG);
    }

    #[test]
    fn wycheproof_tc91_open_round_trips() {
        assert_eq!(open(KEY, NONCE, AAD, CT_AND_TAG), PLAINTEXT);
    }

    #[test]
    fn open_rejects_tampered_tag() {
        assert_eq!(open(KEY, NONCE, AAD, CT_AND_TAMPERED_TAG), "");
    }

    #[test]
    fn open_rejects_wrong_aad() {
        // Authentic ciphertext, but AAD changed → tag must not verify.
        assert_eq!(open(KEY, NONCE, "AAAAAP////4=", CT_AND_TAG), "");
    }

    #[test]
    fn seal_open_round_trip_arbitrary() {
        let ct = seal(KEY, NONCE, AAD, "aGVsbG8gd29ybGQ="); // "hello world"
        assert!(!ct.is_empty());
        assert_eq!(open(KEY, NONCE, AAD, &ct), "aGVsbG8gd29ybGQ=");
    }

    #[test]
    fn rejects_bad_lengths_without_panic() {
        assert_eq!(seal("short-key", NONCE, AAD, PLAINTEXT), "");
        assert_eq!(seal(KEY, "short-nonce", AAD, PLAINTEXT), "");
        assert_eq!(open("short-key", NONCE, AAD, CT_AND_TAG), "");
        assert_eq!(open(KEY, NONCE, AAD, "AA=="), ""); // too short to hold a tag
    }
}
