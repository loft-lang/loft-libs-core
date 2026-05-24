<!--
Copyright (c) 2026 Jurjen Stellingwerff
SPDX-License-Identifier: LGPL-3.0-or-later
-->

# random — PRNG for loft

PCG-64 thread-local random number generation.  Seeded with `12345`
at startup (matches the historical loft behavior); reseed via
`rand_seed(N)` for deterministic streams.

## Install

```sh
loft install random
```

## API

| Function | Returns | Notes |
|---|---|---|
| `rand(lo: integer, hi: integer) -> integer` | uniform integer in `[lo, hi]` (inclusive) | returns `null` if `lo > hi` or either bound is null |
| `rand_seed(seed: integer)` | — | reseed the thread-local PRNG deterministically |
| `rand_indices(n: integer) -> vector<integer>` | `[0..n)` in random order | Fisher-Yates shuffle; returns empty for `n <= 0` |

## Usage

```loft
use random;

fn main() {
    random::rand_seed(42);
    for i in 0..5 {
        print("{random::rand(0, 100)}\n");
    }
    perm = random::rand_indices(10);
}
```

## Provenance

Extracted from the loft monorepo's `lib/random/` 2026-05-24 as the
**showcase library extraction** for `LoftStore`-forwarding native
codegen (@PLAN12 phase 3.5a).  Native crate `loft_random` links
against `rand_pcg` + `rand_core`.  Single source of RNG state for
both interpreter (dlopen dispatch) and `--native` (codegen via
`loft::native_call::build_store`).
