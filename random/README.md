<!--
Copyright (c) 2026 Jurjen Stellingwerff
SPDX-License-Identifier: LGPL-3.0-or-later
-->

# random — PRNGs for loft, in three tiers

Three tiers, and choosing between them is the whole decision:

- **The global tier** (`rand` / `rand_seed` / `rand_indices` / `rand_below`) — one
  PCG-64 generator per process, seeded with `12345` at startup.  Shared by every call
  site in the process, so `rand_seed(N)` fixes what the *generator* produces,
  not what *you* receive.  Right for casual randomness.
- **The value tier** (`RandStream`) — an independent, deterministic stream you
  own and carry as a plain struct, so it saves, replays and syncs with your
  data.  Reach for it the moment reproducibility is a requirement: a replay, a
  lockstep simulation, per-feature streams that must not disturb each other.
  Pure loft (L'Ecuyer's combined LCG, period ~2.3e18) — no native call.
- **The 32-bit tier** (`Rand32`, `rand32`) — for a 32-bit processor such as the
  Tanmatsu's ESP32-P4, and for a `#width 32` program: draws that are `i32` and
  `single` from the start, computed in 32-bit arithmetic (xoshiro128**, with
  Lemire's multiply-shift for a range: no 128-bit product and no 64-bit
  remainder, which the global tier pays per draw).  Owned streams and a shared
  one, as above.  Its own generator: a seed does not reproduce `rand`'s sequence.

## Install

```sh
loft install random
```

## API

| Function | Returns | Notes |
|---|---|---|
| `rand(lo: integer, hi: integer) -> integer?` | uniform integer in `[lo, hi]` (inclusive) | returns `null` if `lo > hi` or either bound is null |
| `rand_seed(seed: integer)` | — | reseed the shared PRNG deterministically |
| `rand_below(m: integer) -> integer` | the next draw in `[0, m)` | the shuffle's step; `0` for `m < 1` |
| `rand_indices(n: integer) -> vector<integer>` | `[0..n)` in random order | Fisher-Yates shuffle; returns empty for `n <= 0` |
| `seed_stream(seed: integer) -> RandStream` | an owned stream | any seed is valid, negative and zero included |
| `r.get(lo, hi) -> integer?` | uniform integer in `[lo, hi]` from **this** stream | advances it; `null` if `lo > hi` |
| `r.indices(n) -> vector<integer>` | `[0..n)` in random order from **this** stream | advances it by exactly `n - 1` draws |
| `seed32(seed: integer) -> Rand32` | an owned 32-bit stream | any seed is valid; SplitMix64 spreads it over the state |
| `r.get32(lo: i32, hi: i32) -> i32?` | uniform `i32` in `[lo, hi]` from **this** stream | unbiased; `null` if `lo > hi` |
| `r.bits31() -> i32` | 31 random bits, `[0, 2147483647]` | |
| `r.unit32() -> single` | uniform `single` in `[0, 1)` | 24 random bits, all a single holds |
| `r.indices32(n: i32) -> vector<i32>` | `[0..n)` in random order from **this** stream | advances it by exactly `n - 1` draws |
| `rand32(lo: i32, hi: i32) -> i32?` / `rand32_seed(seed)` / `rand32_unit()` | the shared 32-bit generator | seeded with `12345` at startup |
| `seed_hw() -> integer?` | a seed from the platform's entropy | the hardware generator on ESP-IDF, the OS elsewhere; `null` on the wasm builds — for a run that is **not** to be reproduced |

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

    // 32-bit: i32 and single draws, cheap on a 32-bit processor.
    sky = random::seed32(random::seed_hw() ?? 1);
    star_x = sky.get32(0, 799);
    twinkle = sky.unit32();
}
```

The 32-bit tier's C part has one platform-dependent section, `seed_hw`'s entropy
source; every draw is the same computation on every target, so a seed gives the
same sequence on the interpreter, the C backend, a 32-bit RISC-V and x86.

## Worked examples

The contracts a signature cannot state are demonstrated by running tests
(@PLN141): [tests/worked-examples.loft](tests/worked-examples.loft) —
`@RND-001` why seeding the global does not make the sequence yours, `@RND-002`
assignment forks a stream while a parameter shares it, `@RND-003` every draw
moves the stream, a shuffle of `n` included (exactly `n - 1` of them).

## Provenance

Extracted from the loft monorepo's `lib/random/` 2026-05-24 as the
**showcase library extraction** for `LoftStore`-forwarding native
codegen (@PLAN12 phase 3.5a).  Since 0.4.0 the native part is **C99**
(`c/random.c`, built by loft itself with `cc` as a `[c] shim` and bound by
`#c` declarations): PCG64 (XSL RR 128/64) seeded as `rand_core`'s
`seed_from_u64` seeds it, so a program seeded under 0.3 draws the same
sequence.  No Rust crate and no rustc; one source for the interpreter,
`--native` and the C backend.  C99 has no threads, so the generator is one
per process (0.3 kept one per thread): a `par` worker drawing from the
global tier shares it with the others.
