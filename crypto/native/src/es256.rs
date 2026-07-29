// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later

//! ES256 — ECDSA over NIST P-256 with SHA-256 (JOSE `alg: ES256`, RFC 7518 §3.4), over the
//! pure-Rust `p256` crate. This is the signature Let's Encrypt (and RFC 8555 ACME generally)
//! requires for the account key and CSR: it rejects Ed25519 account keys, so the byte-clean
//! Ed25519 path in `ed25519.rs` cannot be reused here.
//!
//! **Signatures are RAW `r || s` (64 bytes), not DER.** That is the JOSE encoding a JWS wants —
//! the ASN.1/DER form is for the X.509/PKCS#10 layer (a separate library), never for the JWS
//! signature. Keeping this module DER-free keeps the one hard ASN.1 problem in one place.
//!
//! Signing uses the `ecdsa` crate default: **deterministic RFC 6979** nonces. So signing needs no
//! RNG, is reproducible, and is checkable against a known-answer test. Only key GENERATION draws
//! from the OS CSPRNG.
//!
//! Byte conventions, all base64 `text` like the rest of `crypto`:
//! - a **secret key** is the 32-byte P-256 scalar `d`
//! - a **public key** is the 64-byte affine point `x || y` (the JWK coordinates back to back; the
//!   caller splits it into the `x` and `y` a JWK needs). Not the 0x04-prefixed SEC1 form — that
//!   prefix is an encoding detail the JWK does not carry.
//! - a **signature** is the 64-byte `r || s`.
//!
//! Loft-safe throughout: malformed / wrong-length input never panics. `generate` / `public_key` /
//! `sign` return `""` on failure; `verify` returns `false`.

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

fn decode_fixed<const N: usize>(b64: &str) -> Option<[u8; N]> {
    let bytes = crate::base64::decode(b64);
    if bytes.len() != N {
        return None;
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

/// Reduce 32 bytes of entropy into a valid non-zero P-256 scalar `d`, returned as the base64 of
/// its 32-byte big-endian encoding. `""` if `seed` is not 32 bytes.
///
/// This is the deterministic, RNG-free core of key generation, split out from `generate` so the
/// same reduction runs on the browser bridge (which draws its 32 entropy bytes through the host's
/// `crypto.getRandomValues`, not `getrandom`) — keeping one reduction with no second copy to drift.
/// `SigningKey::from_slice` rejects an out-of-range or zero scalar; on the ~2^-32 chance of that,
/// hash the seed once and retry, so a caller never has to loop.
#[must_use]
pub fn scalar_from_seed(seed: &[u8]) -> String {
    if seed.len() != 32 {
        return String::new();
    }
    match SigningKey::from_slice(seed) {
        Ok(sk) => crate::base64::encode(&sk.to_bytes()),
        Err(_) => {
            let h = crate::sha256::sha256(seed);
            match SigningKey::from_slice(&h) {
                Ok(sk) => crate::base64::encode(&sk.to_bytes()),
                Err(_) => String::new(),
            }
        }
    }
}

/// Generate a fresh ES256 key. Returns the base64 of the 32-byte secret scalar, drawn from the OS
/// CSPRNG. `""` only if the RNG is somehow unavailable (never on a normal host).
///
/// Available everywhere `getrandom` has a backend — native and wasm32-wasip2 (WASI). Only the
/// **browser** target (wasm32-unknown-unknown) lacks an entropy source at compile time, so it is
/// the one target gated out: the browser bridge draws its 32 entropy bytes through the host's
/// `crypto.getRandomValues` and calls `scalar_from_seed` directly instead.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[must_use]
pub fn generate() -> String {
    // Bridge the OS RNG through the same `getrandom` path `random.rs` uses, so there is one
    // entropy source in the crate; the reduction to a valid scalar lives in `scalar_from_seed`.
    let mut seed = [0u8; 32];
    if getrandom::getrandom(&mut seed).is_err() {
        return String::new();
    }
    scalar_from_seed(&seed)
}

/// The 64-byte public key `x || y` (base64) for a 32-byte secret scalar (base64). `""` on a bad
/// secret.
#[must_use]
pub fn public_key(secret_b64: &str) -> String {
    let Some(d) = decode_fixed::<32>(secret_b64) else {
        return String::new();
    };
    let Ok(sk) = SigningKey::from_slice(&d) else {
        return String::new();
    };
    let vk = sk.verifying_key();
    // Uncompressed SEC1 is 0x04 || x || y (65 bytes); strip the prefix to the 64-byte x||y.
    let pt = vk.to_encoded_point(false);
    let bytes = pt.as_bytes();
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return String::new();
    }
    crate::base64::encode(&bytes[1..])
}

/// Sign the base64 `message` bytes with the 32-byte secret scalar (base64). Returns the base64 of
/// the 64-byte `r || s` signature (ECDSA-P256-SHA256, deterministic), or `""` on a bad secret.
#[must_use]
pub fn sign(secret_b64: &str, message_b64: &str) -> String {
    let Some(d) = decode_fixed::<32>(secret_b64) else {
        return String::new();
    };
    let Ok(sk) = SigningKey::from_slice(&d) else {
        return String::new();
    };
    let msg = crate::base64::decode(message_b64);
    // `Signer::sign` on an ECDSA SigningKey hashes with SHA-256 (P-256's associated digest) and
    // uses RFC 6979 — i.e. exactly ES256. `to_bytes()` is the fixed 64-byte r||s.
    let sig: Signature = sk.sign(&msg);
    crate::base64::encode(&sig.to_bytes())
}

/// Verify the base64 `signature` (64-byte r||s) over the base64 `message` bytes under the 64-byte
/// public key `x || y` (base64). `true` only for a valid signature; any decode/length/curve
/// failure yields `false`.
#[must_use]
pub fn verify(public_b64: &str, message_b64: &str, signature_b64: &str) -> bool {
    let Some(xy) = decode_fixed::<64>(public_b64) else {
        return false;
    };
    let Some(sig_bytes) = decode_fixed::<64>(signature_b64) else {
        return false;
    };
    // Rebuild the uncompressed SEC1 point 0x04 || x || y for the verifying key.
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(&xy);
    let Ok(vk) = VerifyingKey::from_sec1_bytes(&sec1) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&sig_bytes) else {
        return false;
    };
    let msg = crate::base64::decode(message_b64);
    vk.verify(&msg, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // A generated key round-trips: sign then verify, and a tampered message / signature fails.
    #[test]
    fn generate_sign_verify_round_trip() {
        let sk = generate();
        assert_eq!(crate::base64::decode(&sk).len(), 32, "secret is a 32-byte scalar");
        let pk = public_key(&sk);
        assert_eq!(crate::base64::decode(&pk).len(), 64, "public key is 64-byte x||y");

        let msg = crate::base64::encode(b"ACME newOrder payload");
        let sig = sign(&sk, &msg);
        assert_eq!(crate::base64::decode(&sig).len(), 64, "signature is 64-byte r||s");
        assert!(verify(&pk, &msg, &sig), "a fresh signature verifies");

        let other = crate::base64::encode(b"a different payload");
        assert!(!verify(&pk, &other, &sig), "the signature does not verify a different message");
    }

    // Deterministic (RFC 6979): the SAME key + message signs to the SAME bytes every time. This is
    // the property that makes ES256 KAT-testable and is what we rely on for reproducible JWS.
    #[test]
    fn signing_is_deterministic() {
        let sk = generate();
        let msg = crate::base64::encode(b"determinism check");
        assert_eq!(sign(&sk, &msg), sign(&sk, &msg), "RFC 6979 — identical signatures");
    }

    // A known secret scalar produces a known public key, and its deterministic signature over a
    // known message verifies. The scalar is d = 1 (the base point G), whose affine coordinates are
    // the standard P-256 generator — a fixed, independently-checkable anchor.
    #[test]
    fn known_scalar_gives_the_generator_point() {
        // d = 1
        let d1 = crate::base64::encode(&{
            let mut b = [0u8; 32];
            b[31] = 1;
            b
        });
        let pk = public_key(&d1);
        let xy = crate::base64::decode(&pk);
        // NIST P-256 generator Gx / Gy (SEC 2), the public key for d = 1.
        let gx = hex::<32>("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
        let gy = hex::<32>("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
        assert_eq!(&xy[..32], &gx, "x coordinate is Gx for d=1");
        assert_eq!(&xy[32..], &gy, "y coordinate is Gy for d=1");

        let msg = crate::base64::encode(b"anchored");
        assert!(verify(&pk, &msg, &sign(&d1, &msg)), "d=1 signs and verifies");
    }

    #[test]
    fn rejects_bad_inputs_without_panic() {
        assert_eq!(public_key("not-32-bytes"), "");
        assert_eq!(sign("short", &crate::base64::encode(b"m")), "");
        assert!(!verify("short-pk", &crate::base64::encode(b"m"), "short-sig"));
    }

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, o) in out.iter_mut().enumerate() {
            *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }
}
