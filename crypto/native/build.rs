// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Drift-proof native registration.  `loft-ffi-build` scans the library's
//! loft source (`../src/**/*.loft`) for `#native` annotations — the SAME
//! co-located annotations the compiler binds against — and emits both the
//! `loft_register!` list and the `loft_register_bridges!` list (every `n_*`
//! impl carries `#[loft_native]`, so the interpreter dispatches through the
//! generated uniform marshal bridges).
//!
//! Generated file: `$OUT_DIR/loft_register_gen.rs` — `include!`d at module
//! scope by `src/lib.rs`.  Adding a symbol is a `#native` line in `../src`
//! plus the `#[loft_native]` body; no `[native.functions]` table to maintain.

fn main() {
    loft_ffi_build::generate_register_from_loft_with_bridges("../src");
}
