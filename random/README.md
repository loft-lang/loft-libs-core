<!--
Copyright (c) 2026 Jurjen Stellingwerff
SPDX-License-Identifier: LGPL-3.0-or-later
-->

# random — PRNGs for loft, in two tiers

Two tiers, and choosing between them is the whole decision:

- **The global tier** (`rand` / `rand_seed` / `rand_indices`) — one PCG-64
  generator per thread, seeded with `12345` at startup.  Shared by every call
  site in the process, so `rand_seed(N)` fixes what the *generator* produces,
  not what *you* receive.  Right for casual randomness.
- **The value tier** (`RandStream`) — an independent, deterministic stream you
  own and carry as a plain struct, so it saves, replays and syncs with your
  data.  Reach for it the moment reproducibility is a requirement: a replay, a
  lockstep simulation, per-feature streams that must not disturb each other.
  Pure loft (L'Ecuyer's combined LCG, period ~2.3e18) — no native call.

## Install

```sh
loft install random
```

## API

| Function | Returns | Notes |
|---|---|---|
| `rand(lo: integer, hi: integer) -> integer?` | uniform integer in `[lo, hi]` (inclusive) | returns `null` if `lo > hi` or either bound is null |
| `rand_seed(seed: integer)` | — | reseed the thread-local PRNG deterministically |
| `rand_indices(n: integer) -> vector<integer>` | `[0..n)` in random order | Fisher-Yates shuffle; returns empty for `n <= 0` |
| `seed_stream(seed: integer) -> RandStream` | an owned stream | any seed is valid, negative and zero included |
| `r.get(lo, hi) -> integer?` | uniform integer in `[lo, hi]` from **this** stream | advances it; `null` if `lo > hi` |
| `r.indices(n) -> vector<integer>` | `[0..n)` in random order from **this** stream | advances it by exactly `n - 1` draws |

Two things about a `RandStream` that its type cannot tell you: **assigning one
copies it** (`r2 = r1` forks — both replay from that point), while **passing one
to a function links it** (the callee's draw advances the caller's stream).

## Usage

```loft
use random;

fn main() {
    // Casual: the shared generator.
    random::rand_seed(42);
    for i in 0..5 {
        print("{random::rand(0, 100)}\n");
    }
    perm = random::rand_indices(10);

    // Reproducible: a stream nothing else can reach.
    level = random::seed_stream(42);
    room_count = level.get(3, 9);
    deck = level.indices(52);
}
```

## Worked examples

The contracts a signature cannot state are demonstrated by running tests
(@PLN141): [tests/worked-examples.loft](tests/worked-examples.loft) —
`@RND-001` why seeding the global does not make the sequence yours, `@RND-002`
assignment forks a stream while a parameter shares it, `@RND-003` every draw
moves the stream, a shuffle of `n` included (exactly `n - 1` of them).

## Provenance

Extracted from the loft monorepo's `lib/random/` 2026-05-24 as the
**showcase library extraction** for `LoftStore`-forwarding native
codegen (@PLAN12 phase 3.5a).  Native crate `loft_random` links
against `rand_pcg` + `rand_core`.  Single source of RNG state for
both interpreter (dlopen dispatch) and `--native` (codegen via
`loft::native_call::build_store`).
