<!--
Copyright (c) 2026 Jurjen Stellingwerff
SPDX-License-Identifier: LGPL-3.0-or-later
-->

# crypto — cryptographic primitives for loft

SHA-256, HMAC-SHA-256, base64 / base64url, X25519 key agreement (RFC 7748),
Ed25519 signatures (RFC 8032), ES256 / ECDSA-P256 signatures (RFC 7518, the
JOSE / ACME signature), AES-256-GCM authenticated encryption, HKDF-SHA256
(RFC 5869), HPKE base mode (RFC 9180), and OS-CSPRNG random bytes.
Pure-Rust implementations exported through the loft FFI: the hashing / base64
primitives are dependency-free; the curve, AEAD, and KDF primitives wrap the
vetted dalek / RustCrypto crates (no openssl / ring, so the cdylib
cross-compiles without a C toolchain).  Every primitive also runs in the
**browser** through the `[wasm.bridge]` — `loft … --html` produces a
self-contained page with no server-side crypto.

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

Keys, nonces, messages, signatures, and ciphertexts cross the boundary as
standard base64 `text` (the `vector<u8>` byte helpers are the one exception).
Every function fails **soft**: malformed input returns `""` (or `false` for
`verify`), never a crash.

### Hashing & MAC

| Function | Returns |
|---|---|
| `sha256(data: text) -> text` | 64-char lowercase hex digest |
| `sha256_b64(data_b64: text) -> text` | hex digest of the base64-decoded bytes |
| `hmac_sha256(key: text, data: text) -> text` | 64-char lowercase hex MAC |

### Base64 & raw bytes

| Function | Returns |
|---|---|
| `base64_encode(data: text) -> text` | RFC 4648 standard alphabet |
| `base64_decode(data: text) -> text` | inverse; `""` on invalid input |
| `base64url_encode(data: text) -> text` | URL-safe alphabet, no padding |
| `bytes_to_base64(bytes: vector<u8>) -> text` | raw bytes → base64 |
| `base64_to_bytes(b64: text) -> vector<u8>` | base64 → raw bytes |

### Key agreement & signatures

| Function | Returns |
|---|---|
| `x25519_dh(secret_key_b64, public_key_b64) -> text` | 32-byte X25519 shared secret (RFC 7748) |
| `ed25519_public_key(secret_key_b64) -> text` | 32-byte public key; `""` if the seed ≠ 32 bytes |
| `ed25519_sign(secret_key_b64, message_b64) -> text` | 64-byte signature (RFC 8032; secret = 32-byte seed) |
| `ed25519_verify(public_key_b64, message_b64, signature_b64) -> boolean` | `true` iff valid; `false` on any malformed input |
| `ecdsa_p256_keygen() -> text` | fresh 32-byte P-256 secret scalar (OS-CSPRNG) |
| `ecdsa_p256_public_key(secret_key_b64) -> text` | 64-byte public key `x‖y` (JWK coordinates, no SEC1 prefix); `""` on a bad secret |
| `ecdsa_p256_sign(secret_key_b64, message_b64) -> text` | 64-byte raw `r‖s` ES256 signature (RFC 7518; deterministic RFC 6979 — the JOSE form, not DER) |
| `ecdsa_p256_verify(public_key_b64, message_b64, signature_b64) -> boolean` | `true` iff valid; `false` on any malformed input |

### Authenticated encryption — AES-256-GCM

| Function | Returns |
|---|---|
| `aes256gcm_seal(key_b64, nonce_b64, aad_b64, plaintext_b64) -> text` | ciphertext‖tag, base64 |
| `aes256gcm_open(key_b64, nonce_b64, aad_b64, ciphertext_b64) -> text` | plaintext; `""` on a tag / AAD mismatch |

### Key derivation — HKDF-SHA256 (RFC 5869)

| Function | Returns |
|---|---|
| `hkdf_sha256(salt_b64, ikm_b64, info_b64, length) -> text` | `length`-byte OKM, base64 (extract-then-expand) |
| `hkdf_extract(salt_b64, ikm_b64) -> text` | 32-byte PRK |
| `hkdf_expand(prk_b64, info_b64, length) -> text` | `length`-byte OKM from a PRK |

### HPKE base mode (RFC 9180 — DHKEM-X25519 · HKDF-SHA256 · AES-256-GCM)

| Function | Returns |
|---|---|
| `hpke_seal_base(pk_r_b64, info_b64, aad_b64, pt_b64) -> HpkeSealed` | `{ enc, ciphertext }` — encapsulated key + sealed ciphertext |
| `hpke_open_base(sk_r_b64, enc_b64, info_b64, aad_b64, ct_b64) -> text` | recovered plaintext; `""` on failure |

`HpkeSealed { enc: text, ciphertext: text }` — the encapsulated ephemeral public
key and the AEAD ciphertext, both base64.

### Random

| Function | Returns |
|---|---|
| `random_bytes(length: integer) -> text` | `length` OS-CSPRNG bytes, base64 (`""` for `length ≤ 0`) |

Every primitive is verified against the RFC 8032 / 7748 / 5869 / 9180 / 6979
known-answer vectors and the Wycheproof AES-GCM cases — see `tests/`, which the
parity gate runs identically on the interpreter and `--native` (ES256 is also
proven byte-identical on `--native-wasm` and `--html` via `tests/es256_parity.loft`).

## Building from source

```sh
git clone https://github.com/loft-lang/loft-libs-core
cd loft-libs-core/crypto
loft --interpret test    # run the suite on the interpreter
loft --native test       # and on compiled Rust — results must match
```

The cdylib in `native/` (and the `wasm/` bridge for `--html`) is built on demand
by the runner; no separate `cargo build` step.

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
[lib_plans/12-library-extraction](https://github.com/loft-lang/loft/blob/main/doc/claude/lib_plans/12-library-extraction/README.md)
Phase 3.5.  The source history before that date lives in the
loft repo under `lib/crypto/`.
