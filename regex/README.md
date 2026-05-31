<!--
Copyright (c) 2026 Jurjen Stellingwerff
SPDX-License-Identifier: LGPL-3.0-or-later
-->

# regex — regular expressions for loft

Inline regular expressions backed by the Rust
[`regex`](https://crates.io/crates/regex) crate: linear-time matching,
ReDoS-safe by construction (no catastrophic backtracking).

Deliberately minimal — this is the **small-script** text tool (log
scanning, CLI fields, quick extraction).  You pass the pattern inline;
there is no compile step and no handle to manage.  Compiled patterns are
cached in a thread-local table, so repeated calls with the same pattern
are cheap.

> Structured parsing — grammars, ASTs, recursion — is **not** this
> library's job.  That belongs to the match-pattern parser framework.

## Install

```sh
loft install regex
```

## API

| Call | Returns | Notes |
|---|---|---|
| `regex::matches(pattern: text, input: text) -> boolean` | `true` if `pattern` matches anywhere in `input` | invalid pattern → `false` (never raises) |
| `regex::find(pattern: text, input: text) -> integer` | byte offset of the first match | `null` when there is no match / invalid pattern |

## Usage

```loft
use regex;

fn main() {
    if regex::matches("[0-9]+", "order #123") {
        print("digits start at {regex::find("[0-9]+", "order #123")}\n");  // 7
    }
}
```

No compile call needed — the first use of a pattern compiles it, every
later use of the same pattern is a cache hit.

## Roadmap

Phase 0 ships `matches` / `find`.  `replace` / `replace_all`, `find_all ->
vector<Match>`, capture groups, and named groups are the next increment —
they return structs / vectors / 3-text-arg text, which the interpreter's
dlopen marshaller has no signature arm for yet.  That FFI gap is tracked
in the regex plan (jjstwerff/loft `lib_plans/.../01-regex`), not worked
around here.

## Provenance

Native crate `loft_regex` wraps the Rust `regex` crate — the same shape
as this chunk's `random` (wraps `rand_pcg`) and `crypto` (wraps pure-Rust
SHA/base64).  Built directly in `loft-libs-core` rather than extracted
from the monorepo.
