// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later

//! X25519 Diffie-Hellman key agreement (RFC 7748) over `x25519-dalek`.
//!
//! Mirrors the `ed25519` module's text-only base64 API so the FFI stays
//! text-only — no raw byte marshalling.  A loft secret key is a 32-byte
//! X25519 scalar (base64); a public key is the 32-byte u-coordinate (base64);
//! the shared secret is the raw 32-byte Diffie-Hellman output (base64).
//!
//! Every entry point is loft-safe: a wrong-length secret or public key never
//! panics — `dh` returns an empty string the caller can test (the same lenient
//! convention `base64_decode` and `ed25519` use).

use x25519_dalek::{PublicKey, StaticSecret};

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

/// Compute the 32-byte X25519 shared secret from our 32-byte secret scalar and
/// the peer's 32-byte public key.
///
/// Returns the base64 shared secret, or `""` if either input is not 32 bytes.
/// The raw shared secret is returned unmodified — callers SHOULD run it through
/// a KDF (e.g. `hkdf_sha256`) before using it as a key, per RFC 7748 §6.1.
#[must_use]
pub fn dh(secret_b64: &str, public_b64: &str) -> String {
    let Some(secret_bytes) = decode_fixed::<32>(secret_b64) else {
        return String::new();
    };
    let Some(public_bytes) = decode_fixed::<32>(public_b64) else {
        return String::new();
    };
    let secret = StaticSecret::from(secret_bytes);
    let public = PublicKey::from(public_bytes);
    let shared = secret.diffie_hellman(&public);
    crate::base64::encode(shared.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7748 §6.1 — Alice / Bob X25519 example.  The hex is verbatim from
    // the RFC, base64-encoded; both sides must derive the SAME shared secret.
    //   alice_priv = 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
    //   alice_pub  = 8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
    //   bob_priv   = 5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb
    //   bob_pub    = de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f
    //   shared K   = 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
    const ALICE_PRIV: &str = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=";
    const ALICE_PUB: &str = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";
    const BOB_PRIV: &str = "XasIfmJKikt54X+Lg4AO5m87sSkmGLb9HC+LJ/+I4Os=";
    const BOB_PUB: &str = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=";
    const SHARED: &str = "Sl2dW6TOLeFyjjv0gDUPJeB+IclH0Z4zdvCbPB4WF0I=";

    #[test]
    fn rfc7748_alice_derives_shared() {
        assert_eq!(dh(ALICE_PRIV, BOB_PUB), SHARED);
    }

    #[test]
    fn rfc7748_bob_derives_same_shared() {
        assert_eq!(dh(BOB_PRIV, ALICE_PUB), SHARED);
    }

    #[test]
    fn rfc7748_both_sides_agree() {
        // The core ECDH property: independent of who is "Alice".
        assert_eq!(dh(ALICE_PRIV, BOB_PUB), dh(BOB_PRIV, ALICE_PUB));
    }

    #[test]
    fn rejects_bad_inputs_without_panic() {
        assert_eq!(dh("not-32-bytes", BOB_PUB), "");
        assert_eq!(dh(ALICE_PRIV, "short-pub"), "");
        assert_eq!(dh("", ""), "");
    }
}
