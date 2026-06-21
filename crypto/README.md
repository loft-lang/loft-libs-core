<!--
Copyright (c) 2026 Jurjen Stellingwerff
SPDX-License-Identifier: LGPL-3.0-or-later
-->

# crypto — cryptographic primitives for loft

SHA-256, HMAC-SHA-256, base64 / base64url encoding + decoding, and
Ed25519 (RFC 8032) signatures.  Pure-Rust implementations exported
through the loft FFI: the hashing / base64 primitives are
dependency-free; Ed25519 wraps the vetted `ed25519-dalek` crate (no
openssl / ring, so the cdylib cross-compiles without a C toolchain).

## Install

```sh
loft install crypto
```

Then in your `.loft` source:

```loft
use crypto;

fn main() {
    digest = sha256("hello world");
    print("{digest}\n");

    encoded = base64_encode("hello world");
    decoded = base64_decode(encoded);
    print("{encoded} -> {decoded}\n");
}
```

## API

| Function | Returns | Notes |
|---|---|---|
| `sha256(input: text) -> text` | 64-char lowercase hex digest | |
| `hmac_sha256(key: text, msg: text) -> text` | 64-char lowercase hex MAC | |
| `hmac_sha256_raw(key: text, msg: text) -> text` | 32 raw bytes (latin-1 packed) | For chaining into further hashing |
| `base64_encode(input: text) -> text` | RFC 4648 standard alphabet | |
| `base64_decode(input: text) -> text` | Inverse of `base64_encode` | Returns empty on invalid input |
| `base64url_encode(input: text) -> text` | RFC 4648 URL-safe alphabet, no padding | |
| `ed25519_public_key(secret_key_b64: text) -> text` | 32-byte public key, base64 | `""` if the seed is not 32 bytes |
| `ed25519_sign(secret_key_b64: text, message_b64: text) -> text` | 64-byte signature, base64 | secret key = RFC 8032 32-byte seed; `""` on bad seed |
| `ed25519_verify(public_key_b64: text, message_b64: text, signature_b64: text) -> boolean` | `true` iff valid | `false` on any malformed input |

Ed25519 keeps all bytes as standard base64 `text`.  A secret key is the
RFC 8032 32-byte seed; messages are the raw bytes to sign, base64-encoded.
Verified against the RFC 8032 §7.1 known-answer vectors (`tests/ed25519.loft`).

## Building from source

```sh
git clone https://github.com/loft-lang/loft-crypto
cd loft-crypto
loft test crypto         # run the test suite (uses your installed loft)
```

The cdylib in `native/` is built on demand by the test runner;
no separate `cargo build` step.

## Releasing

See [SUBMITTING.md](https://github.com/loft-lang/registry/blob/main/SUBMITTING.md)
in the registry repo for the full submit-to-registry flow.
Short version:

```sh
git tag v0.1.0 && git push --tags
loft package
gh release create v0.1.0 crypto-0.1.0.tar.gz
# open PR against loft-lang/registry adding the version row
```

## Provenance

This package was extracted from the loft monorepo's
`lib/crypto/` on 2026-05-24 as part of
[lib_plans/12-library-extraction](https://github.com/jjstwerff/loft/blob/main/doc/claude/lib_plans/12-library-extraction/README.md)
Phase 3.5.  The source history before that date lives in the
loft repo at the `audience2` branch (commit log under
`lib/crypto/`).
