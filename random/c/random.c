/* Copyright (c) 2026 Jurjen Stellingwerff
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * The random library's native part, in C99: one PCG64 stream (PCG XSL RR 128/64, the
 * `Lcg128Xsl64` of rand_pcg 0.9), seeded as rand_core's `seed_from_u64` seeds it, so a
 * program seeded under the earlier Rust crate draws the same sequence here.  Built by loft
 * itself (`[c] shim`, with `cc`); bound by the `#c` declarations in src/random.loft.
 *
 * C99 has no threads, so the stream is one per process.  The Rust part kept one per thread,
 * each starting from the default seed; a `par` worker drawing here under `--native` shares
 * this stream with the others and the sequence it sees is not reproducible. */
#include <stdint.h>

typedef struct { uint64_t lo, hi; } lr_u128;

static lr_u128 lr_state;
static lr_u128 lr_incr;
static int lr_seeded = 0;

/* The low 128 bits of a * b. */
static lr_u128 lr_mul(lr_u128 a, lr_u128 b) {
    uint64_t a0 = a.lo & 0xFFFFFFFFu, a1 = a.lo >> 32;
    uint64_t b0 = b.lo & 0xFFFFFFFFu, b1 = b.lo >> 32;
    uint64_t p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
    uint64_t mid = (p00 >> 32) + (p01 & 0xFFFFFFFFu) + (p10 & 0xFFFFFFFFu);
    lr_u128 r;
    r.lo = (p00 & 0xFFFFFFFFu) | (mid << 32);
    r.hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
    r.hi += a.lo * b.hi + a.hi * b.lo;
    return r;
}

static lr_u128 lr_add(lr_u128 a, lr_u128 b) {
    lr_u128 r;
    r.lo = a.lo + b.lo;
    r.hi = a.hi + b.hi + (r.lo < a.lo ? 1u : 0u);
    return r;
}

/* Lcg128Xsl64::step: state = state * MULTIPLIER + increment. */
static void lr_step(void) {
    lr_u128 mul;
    mul.hi = UINT64_C(0x2360ED051FC65DA4);
    mul.lo = UINT64_C(0x4385DF649FCCF645);
    lr_state = lr_add(lr_mul(lr_state, mul), lr_incr);
}

static uint64_t lr_rotr64(uint64_t x, unsigned r) {
    r &= 63u;
    return r ? (x >> r) | (x << (64u - r)) : x;
}

static uint32_t lr_rotr32(uint32_t x, unsigned r) {
    r &= 31u;
    return r ? (x >> r) | (x << (32u - r)) : x;
}

/* Lcg128Xsl64::from_state_incr. */
static void lr_from_state_incr(lr_u128 state, lr_u128 incr) {
    lr_state = state;
    lr_incr = incr;
    lr_state = lr_add(lr_state, lr_incr);
    lr_step();
}

/* SeedableRng::seed_from_u64 (rand_core 0.9): the 32 seed bytes from a PCG32 over the seed,
 * then Lcg128Xsl64::from_seed — state the first 16 bytes little-endian, increment the next
 * 16 with its low bit set. */
static void lr_seed_u64(uint64_t seed) {
    uint64_t words[8];
    uint64_t s = seed;
    int i;
    for (i = 0; i < 8; i++) {
        uint32_t xorshifted, rot;
        s = s * UINT64_C(6364136223846793005) + UINT64_C(11634580027462260723);
        xorshifted = (uint32_t) (((s >> 18) ^ s) >> 27);
        rot = (uint32_t) (s >> 59);
        words[i] = lr_rotr32(xorshifted, rot);
    }
    {
        lr_u128 state, incr;
        state.lo = words[0] | (words[1] << 32);
        state.hi = words[2] | (words[3] << 32);
        incr.lo = (words[4] | (words[5] << 32)) | 1u;
        incr.hi = words[6] | (words[7] << 32);
        lr_from_state_incr(state, incr);
    }
    lr_seeded = 1;
}

/* RngCore::next_u64 (rand_pcg's Lcg128Xsl64): the step, then XSL RR over the new state. */
static uint64_t lr_next_u64(void) {
    unsigned rot;
    uint64_t xsl;
    if (!lr_seeded) lr_seed_u64(12345u);
    lr_step();
    rot = (unsigned) (lr_state.hi >> 58);
    xsl = lr_state.hi ^ lr_state.lo;
    return lr_rotr64(xsl, rot);
}

int64_t lr_rand(int64_t lo, int64_t hi);
void lr_rand_seed(int64_t seed);
int64_t lr_rand_below(int64_t m);

/* rand(lo, hi): a draw in [lo, hi]; null (INT64_MIN) for an empty range. */
int64_t lr_rand(int64_t lo, int64_t hi) {
    uint64_t range, r;
    if (lo == INT64_MIN || hi == INT64_MIN || lo > hi) return INT64_MIN;
    range = (uint64_t) hi - (uint64_t) lo + 1u;
    r = lr_next_u64();
    if (range == 0) return (int64_t) r;
    return (int64_t) ((uint64_t) lo + r % range);
}

void lr_rand_seed(int64_t seed) {
    lr_seed_u64((uint64_t) seed);
}

/* The next draw reduced modulo m — the shuffle's step; 0 for m < 1. */
int64_t lr_rand_below(int64_t m) {
    uint64_t r = lr_next_u64();
    if (m <= 0) return 0;
    return (int64_t) (r % (uint64_t) m);
}

/* ---- The 32-bit tier: xoshiro128** (Blackman and Vigna, 2018) ----
 *
 * For a 32-bit processor (the Tanmatsu's RV32IMAFC): 128 bits of state as four 32-bit words,
 * stepped with shifts, xors and one rotate — the multiplies by 5 and 9 are a shift and an add
 * — and a range drawn with Lemire's multiply-shift (one 32x32->64 product, no division on the
 * common path, no bias), where the 64-bit tier above takes a 128-bit product and a 64-bit
 * remainder, a library call on RV32.  An owned stream's state is a loft `vector<u8>` of 16
 * bytes, the four words little-endian, read and written here through the element pointer; the
 * shared stream is one static state, as the 64-bit tier's is.  The same C runs on every
 * target, so a seed draws the same sequence on the interpreter, on the C backend and on the
 * device. */

static uint32_t x32_load(const uint8_t *p) {
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) |
           ((uint32_t) p[3] << 24);
}

static void x32_store(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t) v;
    p[1] = (uint8_t) (v >> 8);
    p[2] = (uint8_t) (v >> 16);
    p[3] = (uint8_t) (v >> 24);
}

static uint32_t x32_rotl(uint32_t x, unsigned k) {
    return (x << k) | (x >> (32u - k));
}

/* One step of xoshiro128**: the output of the current state, then the state advanced. */
static uint32_t x32_step(uint32_t *s) {
    uint32_t result = x32_rotl(s[1] * 5u, 7u) * 9u;
    uint32_t t = s[1] << 9;
    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];
    s[2] ^= t;
    s[3] = x32_rotl(s[3], 11u);
    return result;
}

/* The four words from a 64-bit seed, by two SplitMix64 outputs (the seeding the xoshiro
 * authors recommend); an all-zero state, which xoshiro never leaves, takes a 1. */
static void x32_seed_words(uint32_t *s, uint64_t seed) {
    int i;
    for (i = 0; i < 2; i++) {
        uint64_t z;
        seed += UINT64_C(0x9E3779B97F4A7C15);
        z = seed;
        z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
        z ^= z >> 31;
        s[2 * i] = (uint32_t) z;
        s[2 * i + 1] = (uint32_t) (z >> 32);
    }
    if ((s[0] | s[1] | s[2] | s[3]) == 0u) s[0] = 1u;
}

/* A draw in [0, range), range >= 1, by Lemire's nearly divisionless method. */
static uint32_t x32_below(uint32_t *s, uint32_t range) {
    uint64_t m = (uint64_t) x32_step(s) * range;
    uint32_t low = (uint32_t) m;
    if (low < range) {
        uint32_t floor = (0u - range) % range;
        while (low < floor) {
            m = (uint64_t) x32_step(s) * range;
            low = (uint32_t) m;
        }
    }
    return (uint32_t) (m >> 32);
}

/* A draw in [lo, hi]; the caller has answered lo > hi.  hi - lo + 1 is at most 2^32 - 1,
 * because INT32_MIN is loft's null and never arrives as a bound. */
static int32_t x32_range(uint32_t *s, int32_t lo, int32_t hi) {
    uint32_t range = (uint32_t) hi - (uint32_t) lo + 1u;
    return (int32_t) ((uint32_t) lo + x32_below(s, range));
}

/* A single in [0, 1): the top 24 bits, which a single holds exactly. */
static float x32_unit(uint32_t *s) {
    return (float) (x32_step(s) >> 8) * (1.0f / 16777216.0f);
}

static uint32_t x32_shared[4];
static int x32_shared_seeded = 0;

static uint32_t *x32_global(void) {
    if (!x32_shared_seeded) {
        x32_seed_words(x32_shared, 12345u);
        x32_shared_seeded = 1;
    }
    return x32_shared;
}

void lr32_seed(uint8_t *st, int64_t seed);
int32_t lr32_range(uint8_t *st, int32_t lo, int32_t hi);
int32_t lr32_bits31(uint8_t *st);
float lr32_unit(uint8_t *st);
void lr32g_seed(int64_t seed);
int32_t lr32g_range(int32_t lo, int32_t hi);
float lr32g_unit(void);
int64_t lr32_hw_seed(void);

void lr32_seed(uint8_t *st, int64_t seed) {
    uint32_t s[4];
    int i;
    x32_seed_words(s, (uint64_t) seed);
    for (i = 0; i < 4; i++) x32_store(st + 4 * i, s[i]);
}

/* Each owned-stream draw loads the four words, steps, and stores them back. */
#define X32_WITH(st, expr_type, expr)                                                \
    uint32_t s[4];                                                                     \
    expr_type r;                                                                       \
    int i;                                                                             \
    for (i = 0; i < 4; i++) s[i] = x32_load(st + 4 * i);                               \
    r = expr;                                                                          \
    for (i = 0; i < 4; i++) x32_store(st + 4 * i, s[i]);                               \
    return r

int32_t lr32_range(uint8_t *st, int32_t lo, int32_t hi) {
    X32_WITH(st, int32_t, x32_range(s, lo, hi));
}

int32_t lr32_bits31(uint8_t *st) {
    X32_WITH(st, int32_t, (int32_t) (x32_step(s) >> 1));
}

float lr32_unit(uint8_t *st) {
    X32_WITH(st, float, x32_unit(s));
}

void lr32g_seed(int64_t seed) {
    x32_seed_words(x32_shared, (uint64_t) seed);
    x32_shared_seeded = 1;
}

int32_t lr32g_range(int32_t lo, int32_t hi) {
    return x32_range(x32_global(), lo, hi);
}

float lr32g_unit(void) {
    return x32_unit(x32_global());
}

/* ---- A seed from the platform's entropy, for a run that is NOT to be reproduced ----
 *
 * The one platform-dependent section of the library, and only here, in the C: the ESP32's
 * hardware random number generator on ESP-IDF, the OS's /dev/urandom on Unix, rand_s on
 * Windows.  A target with no source (the wasm builds, which this library keeps pure
 * computation) answers -1, which the loft side reads as null.  A non-negative 63-bit value
 * otherwise. */
#if defined(ESP_PLATFORM)
#include "esp_random.h"
#elif defined(_WIN32)
#define _CRT_RAND_S
#include <stdlib.h>
#elif !defined(__wasm__) && (defined(__unix__) || defined(__APPLE__))
#include <stdio.h>
#endif

int64_t lr32_hw_seed(void) {
    uint64_t v = 0;
#if defined(ESP_PLATFORM)
    esp_fill_random(&v, sizeof v);
#elif defined(_WIN32)
    unsigned int a, b;
    if (rand_s(&a) != 0 || rand_s(&b) != 0) return -1;
    v = ((uint64_t) a << 32) | b;
#elif !defined(__wasm__) && (defined(__unix__) || defined(__APPLE__))
    FILE *f = fopen("/dev/urandom", "rb");
    size_t got;
    if (!f) return -1;
    got = fread(&v, 1, sizeof v, f);
    fclose(f);
    if (got != sizeof v) return -1;
#else
    return -1;
#endif
    return (int64_t) (v >> 1);
}
