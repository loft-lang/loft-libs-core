<!--
Copyright (c) 2026 Jurjen Stellingwerff
SPDX-License-Identifier: LGPL-3.0-or-later
-->

# crypto — cryptographic primitives for loft

Hashing (SHA-256, HMAC), base64 / base64url, and — since v0.3 — the
public-key + symmetric primitives an end-to-end-encrypted application
needs: **Ed25519** signatures, **X25519** key agreement, **HPKE**
(RFC 9180) key wrapping, **ChaCha20-Poly1305** / **AES-256-GCM** AEAD,
**HKDF**, and an **OS CSPRNG**.  All pure-Rust (RustCrypto / dalek), no
OpenSSL / `ring` / C toolchain — so the cdylib cross-compiles to native
targets and WASM.  No homegrown crypto.

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

### Hashing & encoding (v0.1+)

| Function | Returns | Notes |
|---|---|---|
| `sha256(input: text) -> text` | 64-char lowercase hex digest | |
| `hmac_sha256(key: text, msg: text) -> text` | 64-char lowercase hex MAC | |
| `base64_encode(input: text) -> text` | RFC 4648 standard alphabet | |
| `base64_decode(input: text) -> text` | Inverse of `base64_encode` | Returns empty on invalid input |
| `base64url_encode(input: text) -> text` | RFC 4648 URL-safe alphabet, no padding | |

### Public-key, AEAD, KDF, CSPRNG (v0.3+)

Binary values (keys, nonces, ciphertexts, plaintexts) cross the API as
**base64 text**.  On error a function returns `""` and sets `last_error()`.

| Function | Returns | Notes |
|---|---|---|
| `random_bytes_b64(n: integer) -> text` | base64 of `n` CSPRNG bytes | `n` in 0..=1048576 |
| `ed25519_keypair() -> Ed25519Keypair` | `{ sk, pk }` (base64, 32B each) | |
| `ed25519_sign(sk_b64, msg_b64) -> text` | 64-byte signature, base64 | |
| `ed25519_verify(pk_b64, msg_b64, sig_b64) -> boolean` | true iff valid | never errors |
| `x25519_keypair() -> X25519Keypair` | `{ sk, pk }` | for ECDH / HPKE |
| `x25519_dh(sk_b64, peer_pk_b64) -> text` | raw 32-byte shared secret | run through HKDF before use |
| `hpke_seal(recipient_pk_b64, info_b64, aad_b64, pt_b64) -> HpkeSealed` | `{ enc, ct }` | RFC 9180, X25519+HKDF-SHA256+ChaCha20Poly1305 |
| `hpke_open(recipient_sk_b64, info_b64, aad_b64, enc_b64, ct_b64) -> text` | plaintext, base64 | `""` on auth failure |
| `chacha20poly1305_seal(key_b64, nonce_b64, aad_b64, pt_b64) -> text` | `ct‖tag`, base64 | key 32B, nonce 12B; nonce unique per key |
| `chacha20poly1305_open(key_b64, nonce_b64, aad_b64, ct_b64) -> text` | plaintext, base64 | `""` on auth failure |
| `aes256gcm_seal(key_b64, nonce_b64, aad_b64, pt_b64) -> text` | `ct‖tag`, base64 | key 32B, nonce 12B |
| `aes256gcm_open(key_b64, nonce_b64, aad_b64, ct_b64) -> text` | plaintext, base64 | `""` on auth failure |
| `hkdf_extract_sha256(salt_b64, ikm_b64) -> text` | 32-byte PRK, base64 | salt may be empty |
| `hkdf_expand_sha256(prk_b64, info_b64, length: integer) -> text` | `length` bytes, base64 | `length` in 1..=8160 |
| `last_error() -> text` | last error on this thread, or `""` | reset on each call |

## Building from source

```sh
git clone https://github.com/loft-lang/loft-libs-core
cd loft-libs-core/crypto
loft test                # run the test suite (uses your installed loft)
```

The cdylib in `native/` is built on demand by the test runner.
After changing native code, force a rebuild with
`cargo build --release` in `native/` (the runner only auto-rebuilds
when `loft-ffi` changes).

## Releasing

See [SUBMITTING.md](https://github.com/loft-lang/registry/blob/main/SUBMITTING.md)
in the registry repo for the full submit-to-registry flow.
Short version:

```sh
git tag crypto-v0.3.0 && git push --tags
loft package
gh release create crypto-v0.3.0 crypto-0.3.0.tar.gz
# open PR against loft-lang/registry adding the version row
```

## Provenance

This package was extracted from the loft monorepo's
`lib/crypto/` on 2026-05-24 as part of
[lib_plans/12-library-extraction](https://github.com/jjstwerff/loft/blob/main/doc/claude/lib_plans/12-library-extraction/README.md)
Phase 3.5.  The source history before that date lives in the
loft repo at the `audience2` branch (commit log under
`lib/crypto/`).
