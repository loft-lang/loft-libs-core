<!--
Copyright (c) 2026 Jurjen Stellingwerff
SPDX-License-Identifier: LGPL-3.0-or-later
-->

# loft-libs-core — core utility libraries for loft

This is a **multi-package chunk repo** hosting small, stable
utility libraries that don't depend on graphics, networking,
or the world primitives.  Each subdirectory is an independent
loft package published to the registry under its own name.

Per the chunked-repo design in
[loft's lib_plans/12-library-extraction/](https://github.com/loft-lang/loft/blob/main/doc/claude/lib_plans/12-library-extraction/README.md)
§ Chunk grouping.

## Packages

| Subdir | Package |
|---|---|
| [`arguments/`](arguments/) | `arguments` — GNU-style command-line argument parsing with generated `--help` |
| [`cbor/`](cbor/) | `cbor` — canonical CBOR (RFC 8949) encode/decode, pure loft |
| [`crypto/`](crypto/) | `crypto` — SHA-256/HMAC, base64, Ed25519, ES256, X25519, HKDF, AES-256-GCM, HPKE |
| [`random/`](random/) | `random` — PRNGs in two tiers: a shared global generator and owned `RandStream`s |
| [`regex/`](regex/) | `regex` — small-script regex (`matches` / `search` / `split_on`, cached patterns) |
| [`zttext/`](zttext/) | `zttext` — text engine: piece table, undoable edits, flow/justify/column layout, pagination, bidi, hit-testing |

Each package's version is the `version` in its `loft.toml`; the registry lists every
published one (`loft api --registry`).  Every package has a guide at
`docs/01-getting-started.loft`.

## Installing a package

```sh
loft install crypto       # installs the crypto package only
```

The registry resolves the package's `subpath` ("`crypto`") inside
this repo automatically.  Consumers never see the chunk
structure — they install per-package.

## Versioning + tags

Each package versions independently.  Git tags use the
**`<package>-v<version>`** convention to disambiguate sibling
packages in this multi-package repo (`crypto-v0.3.11`).

These packages are published by loft's maintainers through the signed registry
flow — [LIBRARY_PUBLISH.md](https://github.com/loft-lang/loft/blob/main/doc/claude/LIBRARY_PUBLISH.md)
in the loft repository.  An outside author publishing a package of their own follows
[SUBMITTING.md](https://github.com/loft-lang/registry/blob/main/SUBMITTING.md).

## License

LGPL-3.0-or-later — see [LICENSE](LICENSE).
