// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Ed25519 signatures (RFC 8032) over the vetted `ed25519-dalek` crate.
//!
//! The loft-facing API keeps all bytes as standard base64 `text` (matching
//! the `sha256` / `base64` functions), so the FFI stays text-only — no raw
//! byte marshalling.  A loft `secret key` is the RFC 8032 32-byte seed; the
//! public key and signature are the dalek-canonical 32- and 64-byte encodings.
//!
//! Every entry point is loft-safe: malformed or wrong-length input never
//! panics.  `public_key` / `sign` return an empty string on failure;
//! `verify` returns `false`.  This mirrors `base64_decode`'s lenient
//! convention so a bad input degrades to a value the caller can test.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

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

/// Derive the 32-byte public key from a 32-byte secret seed.
///
/// Returns the base64 public key, or `""` if the seed is not 32 bytes.
#[must_use]
pub fn public_key(secret_b64: &str) -> String {
    let Some(seed) = decode_fixed::<32>(secret_b64) else {
        return String::new();
    };
    let sk = SigningKey::from_bytes(&seed);
    crate::base64::encode(sk.verifying_key().as_bytes())
}

/// Sign `message` (raw bytes, base64) with the 32-byte secret seed.
///
/// Returns the base64 of the 64-byte signature, or `""` if the seed is not
/// 32 bytes.
#[must_use]
pub fn sign(secret_b64: &str, message_b64: &str) -> String {
    let Some(seed) = decode_fixed::<32>(secret_b64) else {
        return String::new();
    };
    let sk = SigningKey::from_bytes(&seed);
    let msg = crate::base64::decode(message_b64);
    let sig: Signature = sk.sign(&msg);
    crate::base64::encode(&sig.to_bytes())
}

/// Verify `signature` over `message` (raw bytes, base64) under `public_key`.
///
/// Returns `true` only for a valid signature; any decode failure, wrong
/// length, off-curve key, or bad signature yields `false`.
#[must_use]
pub fn verify(public_b64: &str, message_b64: &str, signature_b64: &str) -> bool {
    let Some(pk_bytes) = decode_fixed::<32>(public_b64) else {
        return false;
    };
    let Some(sig_bytes) = decode_fixed::<64>(signature_b64) else {
        return false;
    };
    let Ok(pk) = VerifyingKey::from_bytes(&pk_bytes) else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_bytes);
    let msg = crate::base64::decode(message_b64);
    pk.verify(&msg, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8032 §7.1 TEST 1 (empty message).
    const T1_SK: &str = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=";
    const T1_PK: &str = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
    const T1_MSG: &str = ""; // empty
    const T1_SIG: &str =
        "5VZDAMNgrHKQhuLMgG6CioSHfx645dl02HPgZSJJAVVfuIIVkKM7rMYeOXAc+bRr0lv18FlbviRlUUFDjnoQCw==";

    #[test]
    fn rfc8032_test1_public_key() {
        assert_eq!(public_key(T1_SK), T1_PK);
    }

    #[test]
    fn rfc8032_test1_sign() {
        assert_eq!(sign(T1_SK, T1_MSG), T1_SIG);
    }

    #[test]
    fn rfc8032_test1_verify() {
        assert!(verify(T1_PK, T1_MSG, T1_SIG));
    }

    #[test]
    fn rejects_bad_inputs_without_panic() {
        assert_eq!(public_key("not-32-bytes"), "");
        assert_eq!(sign("short", T1_MSG), "");
        assert!(!verify(T1_PK, T1_MSG, "short-sig"));
        assert!(!verify("short-pk", T1_MSG, T1_SIG));
    }
}
