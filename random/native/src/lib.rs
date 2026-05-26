// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Native random number generator using loft-ffi for store allocation.
//! Export names match `#native` symbols — no registration function needed.
//!
//! @PLAN12 phase 3.5a (2026-05-24) — ABI aligned to i64 throughout
//! (was i32) and RNG state aligned to `Pcg64::seed_from_u64(12345)`
//! to match the previous compiler-crate `crate::ops::rand_*` initial
//! state.  Vector elements stored as i64 in 8-byte slots (matches
//! loft's `vector<integer>` layout per src/codegen_runtime.rs comments).
//! After this change, the cdylib is the SINGLE source of RNG state
//! for both interpreter (dlopen dispatch) and `--native` (codegen
//! via `loft::native_call::build_store`) — no more split state.

#![allow(clippy::missing_safety_doc)]

use loft_ffi::{LoftRef, LoftStore};
use rand_core::{RngCore, SeedableRng};
use rand_pcg::Pcg64;
use std::cell::RefCell;

thread_local! {
    // Initial seed 12345 matches the historical `crate::ops::rand_*`
    // behavior — programs that called `rand()` without seeding got
    // the same first-value pre/post drain.  `rand_seed(N)` below
    // replaces it.
    static RNG: RefCell<Pcg64> = RefCell::new(Pcg64::seed_from_u64(12345));
}

#[unsafe(no_mangle)]
pub extern "C" fn n_rand(lo: i64, hi: i64) -> i64 {
    // Null sentinel: i64::MIN.  Matches loft's `integer` null contract.
    if lo == i64::MIN || hi == i64::MIN || lo > hi {
        return i64::MIN;
    }
    let range = (hi - lo + 1) as u64;
    let r = RNG.with(|rng| rng.borrow_mut().next_u64());
    lo + (r % range) as i64
}

#[unsafe(no_mangle)]
pub extern "C" fn n_rand_seed(seed: i64) {
    RNG.with(|rng| *rng.borrow_mut() = Pcg64::seed_from_u64(seed as u64));
}

/// Returns a vector of `n` integers `[0, 1, ..., n-1]` in random order.
/// Allocates the vector directly in the loft store via the LoftStore handle.
/// Returns a null `LoftRef` when `n <= 0` or `n == i64::MIN`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_rand_indices(mut store: LoftStore, n: i64) -> LoftRef {
    let count = if n == i64::MIN || n <= 0 {
        0usize
    } else {
        n as usize
    };
    // Build shuffled indices via Fisher-Yates.
    let mut indices: Vec<i64> = (0..count as i64).collect();
    for i in (1..indices.len()).rev() {
        let j = RNG.with(|rng| rng.borrow_mut().next_u64()) as usize % (i + 1);
        indices.swap(i, j);
    }
    // Allocate as 8-byte (i64) slots — matches loft's `vector<integer>`
    // narrow-record layout (see the @P321f comment in the historical
    // src/codegen_runtime.rs::n_rand_indices impl).
    let mut vec = unsafe { store.alloc_vector(8, count as u32) };
    for &val in &indices {
        unsafe { store.vector_push_long(&mut vec, val) };
    }
    vec
}

// @PLAN12 — the `loft_ffi::loft_register! { … }` list is generated from
// the library's co-located `#native` annotations in `../src/*.loft` by
// `build.rs` (via `loft-ffi-build::generate_register_from_loft`) and
// `include!`d here, so adding a binding automatically registers it — no
// hand-maintained list, no manifest table.
include!(concat!(env!("OUT_DIR"), "/loft_register_gen.rs"));
