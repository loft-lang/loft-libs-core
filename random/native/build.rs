// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Drift-proof native registration.  `loft-ffi-build` scans the library's
//! loft source (`../src/**/*.loft`) for `#native` annotations — the SAME
//! co-located annotations the compiler binds against — and emits both the
//! `loft_register!` list and the `loft_register_bridges!` list (every `n_*`
//! impl carries `#[loft_native]`, so the interpreter dispatches through the
//! generated uniform marshal bridges).  Bare `#native` → `n_<fn>`;
//! `#native "sym"` → the override.  `include!`d by `src/lib.rs`.

fn main() {
    loft_ffi_build::generate_register_from_loft_with_bridges("../src");
}
