<!--
Copyright (c) 2026 Jurjen Stellingwerff
SPDX-License-Identifier: LGPL-3.0-or-later
-->

# regex — regular expressions for loft

Compile-once regular expressions backed by the Rust
[`regex`](https://crates.io/crates/regex) crate: linear-time matching,
ReDoS-safe by construction (no catastrophic backtracking).

> **Phase 0** — a thin `#native` cdylib bridge.  The surface below is the
> stable target; a later phase swaps a pure-loft NFA engine underneath the
> *same* API, invisible to callers.

## Install

```sh
loft install regex
```

## API

Compile once with `regex::compile`, then call methods on the `Regex`:

| Call | Returns | Notes |
|---|---|---|
| `regex::compile(pattern: text) -> Regex` | a compiled regex | compile once, reuse; an invalid pattern yields a `Regex` whose ops fail safely |
| `re.is_match(input: text) -> boolean` | `true` if `re` matches anywhere in `input` | method on `Regex` |
| `re.find(input: text) -> integer` | byte offset of the first match | `null` when there is no match |

## Usage

```loft
use regex;

fn main() {
    digits = regex::compile("[0-9]+");
    if digits.is_match("order #123") {
        print("starts at {digits.find("order #123")}\n");  // 7
    }
}
```

## Roadmap

Phase 0 ships `regex` / `is_match` / `find`.  Capture groups, `find_all ->
vector<Match>`, `replace` / `replace_all`, `split`, and named groups are
the next increment — they return structs / vectors / 3-text-arg text, which
the interpreter's dlopen marshaller has no signature arm for yet.  That FFI
gap is tracked in the regex plan (jjstwerff/loft
`lib_plans/.../01-regex`), not worked around here.

## Provenance

Native crate `loft_regex` wraps the Rust `regex` crate, the same
shape as this chunk's `random` (wraps `rand_pcg`) and `crypto` (wraps
pure-Rust SHA/base64).  Built directly in `loft-libs-core` rather than
extracted from the monorepo — the monorepo `lib/` is draining, not growing.
