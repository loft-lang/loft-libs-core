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
[loft's lib_plans/12-library-extraction/](https://github.com/jjstwerff/loft/blob/main/doc/claude/lib_plans/12-library-extraction/README.md)
§ Chunk grouping.

## Packages

| Subdir | Package | Status |
|---|---|---|
| [`crypto/`](crypto/) | `crypto` — SHA-256, HMAC, base64 | v0.1.0 (extracted 2026-05-24) |
| [`arguments/`](arguments/) | `arguments` — CLI argument parsing | v0.1.0 (extracted 2026-05-24) |
| [`random/`](random/) | `random` — PRNG | v0.1.0 (extracted 2026-05-24, **showcase drain**: the LoftStore-forwarding codegen feature in loft 0.8.5+ ships here as its canonical example) |
| [`regex/`](regex/) | `regex` — small-script regex (`matches`/`find`/`split`, thread-local cache) | v0.1.0 (added 2026-06-01) |
| [`cbor/`](cbor/) | `cbor` — canonical CBOR (RFC 8949) encode/decode, pure loft | v0.1.0 (added 2026-06-20, [@PLN83]) |

Future drains from the loft stdlib (Phase 3.6 in
[plan-12](https://github.com/jjstwerff/loft/blob/main/doc/claude/lib_plans/12-library-extraction/README.md#phase-36--stdlib-drain-into-libs))
may add packages here — `html` for `escape_html` is the most
likely.

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
packages in this multi-package repo:

| Package + version | Git tag |
|---|---|
| crypto 0.1.0 | `crypto-v0.1.0` |
| arguments 0.1.0 (future) | `arguments-v0.1.0` |
| random 0.1.0 (future) | `random-v0.1.0` |
| regex 0.1.0 (future) | `regex-v0.1.0` |

A package's release flow (also documented in
[SUBMITTING.md](https://github.com/loft-lang/registry/blob/main/SUBMITTING.md)
in the registry repo):

```sh
cd <package>/
# bump version in loft.toml
git tag <package>-v<version>
git push --tags
loft package
gh release create <package>-v<version> <package>-<version>.tar.gz \
    --title "<package> <version>"
# Then open a PR against loft-lang/registry adding the version row.
```

## License

LGPL-3.0-or-later — see [LICENSE](LICENSE).
