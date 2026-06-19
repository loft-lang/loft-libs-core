// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// Browser-WASM host imports for the `crypto` library's `--html` build.
// Concatenated into the generated HTML preamble by the `--html` driver
// (which reads `[wasm.bridge].host_js = "wasm/host.js"` from `loft.toml`).
//
// `crypto::sha256` is computed entirely in pure Rust inside the wasm binary
// (see `wasm/src/lib.rs`), so it imports NO host functions — this extension is
// a no-op placeholder kept so the bridge has a complete, self-documenting
// surface as more primitives (those that need host RNG / time) are added.

(globalThis.LOFT_WASM_EXTENSIONS = globalThis.LOFT_WASM_EXTENSIONS || []).push(
  function loftCryptoHostImports(_imports, _ctrl, _getMem) {
    // No host imports: sha256 runs in pure Rust.
  },
);
