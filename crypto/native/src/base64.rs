// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Built-in base64 encode/decode. Always available — no external deps.

const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[must_use]
pub fn encode(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 {
            u32::from(chunk[1])
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            u32::from(chunk[2])
        } else {
            0
        };
        let n = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((n >> 18) & 63) as usize] as char);
        result.push(CHARS[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((n >> 6) & 63) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(n & 63) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

#[must_use]
pub fn encode_url(data: &[u8]) -> String {
    encode(data)
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string()
}

/// Decode standard or URL-safe base64, or `None` when `input` is not base64: a character
/// outside both alphabets, padding anywhere but the end, more than two `=`, or a length
/// no encoder produces.  Line breaks are skipped, so wrapped (PEM-style) input decodes.
///
/// Strict on purpose: every caller hands the bytes to a hash, a signature or a cipher, so
/// a typo must refuse rather than decode to other bytes — a lenient decoder read every
/// stray character as `A` and signed, hashed and sealed what the caller never sent.
#[must_use]
pub fn try_decode(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            _ => None,
        }
    }
    let stripped: Vec<u8> = input
        .bytes()
        .filter(|b| *b != b'\n' && *b != b'\r')
        .collect();
    let pad = stripped.iter().rev().take_while(|b| **b == b'=').count();
    let body = &stripped[..stripped.len() - pad];
    if pad > 2 || (pad > 0 && !stripped.len().is_multiple_of(4)) || body.len() % 4 == 1 {
        return None;
    }
    let mut vals = Vec::with_capacity(body.len());
    for b in body {
        vals.push(val(*b)?);
    }
    let mut result = Vec::with_capacity(body.len() * 3 / 4);
    for chunk in vals.chunks(4) {
        let n = u32::from(chunk[0]) << 18
            | u32::from(chunk[1]) << 12
            | chunk.get(2).map_or(0, |v| u32::from(*v) << 6)
            | chunk.get(3).map_or(0, |v| u32::from(*v));
        result.push((n >> 16) as u8);
        if chunk.len() > 2 {
            result.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            result.push(n as u8);
        }
    }
    Some(result)
}

/// [`try_decode`], with input that is not base64 decoding to no bytes.  For a caller whose
/// documented answer to malformed input is the empty one; a caller that would go on to
/// hash, sign or seal the bytes asks [`try_decode`] and refuses instead.
#[must_use]
pub fn decode(input: &str) -> Vec<u8> {
    try_decode(input).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_what_encode_writes() {
        for data in [&b""[..], b"h", b"hi", b"hi!", b"\xff\x00\x10"] {
            assert_eq!(try_decode(&encode(data)).as_deref(), Some(data));
        }
        assert_eq!(try_decode("aGk").as_deref(), Some(&b"hi"[..]), "unpadded");
        assert_eq!(
            try_decode("aG\nk=").as_deref(),
            Some(&b"hi"[..]),
            "a line break is skipped"
        );
        assert_eq!(try_decode("-_8="), try_decode("+/8="), "URL-safe letters");
    }

    #[test]
    fn refuses_what_is_not_base64() {
        for bad in ["!!!!", "aG k=", "a===", "aGk==x", "aGk=a", "aGkxa", "=aGk"] {
            assert_eq!(try_decode(bad), None, "{bad:?}");
            assert!(decode(bad).is_empty(), "{bad:?}");
        }
    }
}
