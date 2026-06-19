// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Cryptographically secure random bytes from the operating-system RNG.
//!
//! Backed by `getrandom`, which reads the OS CSPRNG (`getrandom(2)` /
//! `/dev/urandom` on Linux, `RtlGenRandom` on Windows, etc.) — suitable for
//! keys, nonces, and salts.  The result is base64, matching the rest of the
//! library's text-only convention.
//!
//! Loft-safe: a non-positive `length` returns `""`, and an OS RNG failure
//! (extremely rare — e.g. the entropy source is unavailable) also returns
//! `""` rather than panicking.

/// Return `length` cryptographically secure random bytes, base64-encoded.
///
/// Returns `""` for `length <= 0` or if the OS RNG cannot be read.  There is
/// no upper bound beyond available memory; for keys/nonces the caller picks
/// 32 (AES-256 key) or 12 (GCM nonce).
#[must_use]
pub fn bytes(length: i32) -> String {
    // A non-positive `length` (including the loft `integer` null sentinel
    // `i32::MIN`) yields "" rather than a panic.
    if length <= 0 {
        return String::new();
    }
    let mut buf = vec![0u8; length as usize];
    if getrandom::getrandom(&mut buf).is_err() {
        return String::new();
    }
    crate::base64::encode(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_requested_length() {
        // 32 raw bytes → base64-decode must give back exactly 32 bytes.
        let out = bytes(32);
        assert!(!out.is_empty());
        assert_eq!(crate::base64::decode(&out).len(), 32);
    }

    #[test]
    fn two_calls_differ() {
        // The probability of two 32-byte CSPRNG draws colliding is ~2^-256.
        assert_ne!(bytes(32), bytes(32));
    }

    #[test]
    fn zero_or_negative_is_empty() {
        assert_eq!(bytes(0), "");
        assert_eq!(bytes(-1), "");
    }

    #[test]
    fn small_lengths_exact() {
        assert_eq!(crate::base64::decode(&bytes(1)).len(), 1);
        assert_eq!(crate::base64::decode(&bytes(12)).len(), 12);
    }
}
