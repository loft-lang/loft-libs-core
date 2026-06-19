// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Raw-byte <-> base64 bridges for composing labeled byte strings in loft.
//!
//! HPKE (RFC 9180) builds labeled inputs like
//! `"HPKE-v1" || suite_id || label || ikm`, where `suite_id` carries the raw
//! bytes `00 20 00 01 00 02`.  loft `text` is UTF-8-validated — `text_from_bytes`
//! returns `""` for a non-UTF-8 sequence — so the labeled strings cannot ride as
//! `text`.  loft assembles them in a `vector<u8>` instead and crosses the base64
//! boundary here:
//!
//! - [`encode`] turns a loft `vector<u8>` into standard base64 `text`.
//! - [`decode`] turns standard base64 `text` into a loft `vector<u8>`.
//!
//! These are the inverse of each other for any byte sequence, including
//! non-UTF-8 — which is exactly why the existing text-only base64 functions
//! cannot stand in.

use loft_ffi::{LoftRef, LoftStore};

/// Read a loft `vector<u8>` into a `Vec<u8>`.
///
/// A loft `vector<u8>` stores one byte per element (element stride 1), packed
/// contiguously after the 8-byte vector header.  A null reference (rec 0) reads
/// as empty.
unsafe fn read_byte_vector(store: &LoftStore, vec: &LoftRef) -> Vec<u8> {
    if vec.rec == 0 {
        return Vec::new();
    }
    let len = unsafe { store.vector_len(vec) } as usize;
    if len == 0 {
        return Vec::new();
    }
    let ptr = unsafe { store.vector_data_ptr(vec) };
    unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec()
}

/// `vector<u8>` -> standard base64 `text`.
///
/// Empty / null vectors encode to `""`.
#[must_use]
pub unsafe fn encode(store: &LoftStore, vec: &LoftRef) -> String {
    let bytes = unsafe { read_byte_vector(store, vec) };
    crate::base64::encode(&bytes)
}

/// standard base64 `text` -> `vector<u8>`.
///
/// Allocates the result vector directly in the loft store (element stride 1).
/// A malformed or empty base64 string yields an empty vector — never a panic.
#[must_use]
pub unsafe fn decode(store: &mut LoftStore, b64: &str) -> LoftRef {
    let bytes = crate::base64::decode(b64);
    unsafe { store.alloc_vector_from_bytes(1, bytes.len() as u32, bytes.as_ptr(), bytes.len()) }
}

/// Concatenate the raw bytes behind two base64 strings: `base64(bytes(a) || bytes(b))`.
///
/// A pure text-in / text-out primitive — it never touches the loft store — so
/// labeled byte strings (`"HPKE-v1" || suite_id || label || ikm`) can be
/// assembled in loft *without* a `vector<u8>` accumulator, side-stepping the
/// store-reallocation hazard of appending onto a store-allocated byte vector.
#[must_use]
pub fn concat_b64(a_b64: &str, b_b64: &str) -> String {
    let mut bytes = crate::base64::decode(a_b64);
    bytes.extend_from_slice(&crate::base64::decode(b_b64));
    crate::base64::encode(&bytes)
}
