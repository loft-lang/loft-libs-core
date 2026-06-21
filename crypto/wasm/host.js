// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// Browser-WASM host imports for the `crypto` library's `--html` build.
// Concatenated into the generated HTML preamble by the `--html` driver
// (which reads `[wasm.bridge].host_js = "wasm/host.js"` from `loft.toml`).
//
// Almost every crypto primitive is computed in pure Rust inside the wasm binary
// (the SHARED `#[path]` modules + the dalek/RustCrypto deps the build-extension
// compiles to wasm), so they import NO host functions.  The one exception is
// `random_bytes`: OS entropy must come from the host, and on the web that is the
// synchronous `crypto.getRandomValues` (the only Web Crypto call that is not a
// Promise) — exposed here as the `loft_crypto.random_fill` import declared by
// `wasm/src/lib.rs`.

(globalThis.LOFT_WASM_EXTENSIONS = globalThis.LOFT_WASM_EXTENSIONS || []).push(
  function loftCryptoHostImports(imports, _ctrl, getMem) {
    const ns = (imports.loft_crypto = imports.loft_crypto || {});
    // Fill wasm linear memory [ptr, ptr+len) with CSPRNG bytes.  getRandomValues
    // rejects requests over 65536 bytes, so chunk larger fills.
    ns.random_fill = function (ptr, len) {
      const mem = new Uint8Array(getMem().buffer, ptr, len);
      for (let off = 0; off < len; off += 65536) {
        crypto.getRandomValues(mem.subarray(off, Math.min(off + 65536, len)));
      }
    };
  },
);
