// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later

//! HKDF key derivation (RFC 5869) with SHA-256, over the `hkdf` + `sha2`
//! crates.
//!
//! Mirrors the text-only base64 convention of the rest of the library: salt,
//! input keying material (IKM), and info are base64 `text`; the output keying
//! material (OKM) is base64.  An empty `salt` (base64 `""`) selects the
//! all-zero salt RFC 5869 §2.2 specifies, and empty `info` is the no-context
//! case.
//!
//! Loft-safe: the only failure HKDF-Expand can hit is `length` exceeding
//! `255 * 32 = 8160` bytes (the SHA-256 ceiling), which returns `""` rather
//! than panicking.  A negative `length` is treated as 0.

use hkdf::Hkdf;
use sha2::Sha256;

/// Derive `length` bytes of output keying material from `ikm`, `salt`, and
/// `info` using HKDF-SHA256 (extract-then-expand, RFC 5869).
///
/// All byte arguments are base64; the result is the base64 OKM.  Returns `""`
/// if `length` exceeds 8160 (the `255 * HashLen` HKDF ceiling) — the only
/// in-band failure — or if `length <= 0`.
#[must_use]
pub fn sha256(salt_b64: &str, ikm_b64: &str, info_b64: &str, length: i32) -> String {
    // A non-positive `length` (including the loft `integer` null sentinel
    // `i32::MIN`) yields "" rather than a panic — the lenient convention.
    if length <= 0 {
        return String::new();
    }
    let length = length as usize;
    let salt = crate::base64::decode(salt_b64);
    let ikm = crate::base64::decode(ikm_b64);
    let info = crate::base64::decode(info_b64);

    // An empty base64 salt means "no salt" — RFC 5869 §2.2 then uses a string
    // of HashLen zeros, which is exactly what `Hkdf::new(None, ..)` does.
    let salt_opt = if salt.is_empty() {
        None
    } else {
        Some(salt.as_slice())
    };
    let hk = Hkdf::<Sha256>::new(salt_opt, &ikm);

    let mut okm = vec![0u8; length];
    if hk.expand(&info, &mut okm).is_err() {
        return String::new(); // length > 255*32
    }
    crate::base64::encode(&okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 5869 Appendix A, Test Case 1 (basic, with salt + info), SHA-256.
    //   IKM  = 0b * 22
    //   salt = 000102030405060708090a0b0c
    //   info = f0f1f2f3f4f5f6f7f8f9
    //   L    = 42
    //   OKM  = 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db0
    //          2d56ecc4c5bf34007208d5b887185865
    const T1_IKM: &str = "CwsLCwsLCwsLCwsLCwsLCwsLCwsLCw==";
    const T1_SALT: &str = "AAECAwQFBgcICQoLDA==";
    const T1_INFO: &str = "8PHy8/T19vf4+Q==";
    const T1_OKM: &str = "PLJfJfqs1XqQQ09k0DYvKi0tCpDPGlpMXbAtVuzExb80AHII1biHGFhl";

    // RFC 5869 Appendix A, Test Case 3 (zero-length salt and info), SHA-256.
    //   IKM  = 0b * 22
    //   salt = (empty)
    //   info = (empty)
    //   L    = 42
    //   OKM  = 8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec345
    //          4e5f3c738d2d9d201395faa4b61a96c8
    const T3_IKM: &str = "CwsLCwsLCwsLCwsLCwsLCwsLCwsLCw==";
    const T3_OKM: &str = "jaTndaVjwY9xX4AqBjxaMbihH1xe4Yeew0VOXzxzjS2dIBOV+qS2GpbI";

    #[test]
    fn rfc5869_test_case_1() {
        assert_eq!(sha256(T1_SALT, T1_IKM, T1_INFO, 42), T1_OKM);
    }

    #[test]
    fn rfc5869_test_case_3_empty_salt_and_info() {
        assert_eq!(sha256("", T3_IKM, "", 42), T3_OKM);
    }

    #[test]
    fn rejects_excessive_length_without_panic() {
        // 255 * 32 = 8160 is the max; one more must fail cleanly.
        assert_eq!(sha256(T1_SALT, T1_IKM, T1_INFO, 8161), "");
    }

    #[test]
    fn zero_or_negative_length_is_empty() {
        assert_eq!(sha256(T1_SALT, T1_IKM, T1_INFO, 0), "");
        assert_eq!(sha256(T1_SALT, T1_IKM, T1_INFO, -5), "");
    }
}
