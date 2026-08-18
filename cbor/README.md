<!--
Copyright (c) 2026 Jurjen Stellingwerff
SPDX-License-Identifier: LGPL-3.0-or-later
-->

# cbor — canonical CBOR (RFC 8949) for loft

Compact binary serialisation — like JSON, but with native byte strings and a
**deterministic** form: the same value always encodes to byte-identical output.
That is the whole point of this library.  It targets the **signable record**: a
signature is over the bytes, so those bytes must not depend on how the value was
assembled, which target it ran on, or what order a later version of your code
adds fields in.

Pure loft by design ([plans#83](https://github.com/loft-lang/plans/issues/83)) —
no native crate, no FFI bridge, no external-crate trust surface, and identical
behaviour on every target by construction.

## Install

```sh
loft install cbor
```

## API

| Item | Notes |
|---|---|
| `CborValue` | `CNull`, `CBool`, `CInt`, `CBytes`, `CText`, `CArray`, `CMap` |
| `CborEntry { key, value }` | one pair of a `CMap` |
| `encode(v: CborValue) -> vector<u8>` | canonical bytes; **sorts map entries** by encoded key |
| `decode(bytes: vector<u8>) -> Decoded` | `{ value, next, ok }` — never crashes |

`CInt` folds CBOR's unsigned/negative split, so you do not choose a major type:
`23` encodes in one byte, `24` in two, `-1` as major 1.

## Three things worth knowing before you use it

- **The order you build a map in does not reach the wire.** `encode` sorts
  entries by their *encoded key bytes*, so two maps built in opposite orders are
  byte-identical — and a decoded map must be read **by key, never by position**.
- **`decode` refuses well-formed but NON-canonical input.** A permissive encoder
  elsewhere may write `1` as `18 01`; this decoder rejects it, because accepting
  it would mean two byte strings decode to one value.  `ok=false` is also what
  you get for truncated input, trailing bytes, and empty input — it says "these
  are not my bytes", not which problem it was.  Check `ok` before `value`.
- **Canonical is about order, not uniqueness.** A map with two entries under one
  key encodes and decodes without complaint.  Enforce uniqueness yourself.

## Worked examples

Those contracts are demonstrated by running tests (@PLN141):
[tests/worked-examples.loft](tests/worked-examples.loft) — `@CBR-001` map order,
`@CBR-002` `CBytes` vs `CText` as different wire types, `@CBR-003` what
`ok=false` covers, `@CBR-004` duplicate keys.
