/* Copyright (c) 2026 Jurjen Stellingwerff
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * The crypto library's native part: one-call C99 entry points over two vendored, audited
 * libraries — BearSSL (c/vendor/bearssl, MIT: SHA-256, HMAC, HKDF, AES-256-GCM, P-256 ECDSA,
 * X25519, all constant-time) and Monocypher (c/vendor/monocypher, BSD-2 / CC0: Ed25519) —
 * built by loft itself as the package's `[c] shim` for the host and for both wasm targets.
 * Bytes cross as `vector<u8>` buffers the loft side sizes; base64 and hex are loft's.
 * Every function answers 1 for success and 0 for a refusal, writing nothing on refusal.
 * Entropy is the one OS call (`cr_random`): /dev/urandom, `rand_s` on Windows, none on wasm. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "vendor/bearssl/bearssl.h"
#include "vendor/monocypher/monocypher.h"
#include "vendor/monocypher/monocypher-ed25519.h"

#if !defined(__wasm__)
#include <stdio.h>
#if defined(_WIN32)
#define _CRT_RAND_S
#include <stdlib.h>
#endif
#endif

int cr_sha256(const void *data, int64_t n, void *out32);
int cr_sha256_text(const char *data, void *out32);
int cr_hmac_sha256(const void *key, int64_t klen, const void *data, int64_t n, void *out32);
int cr_hmac_sha256_text(const char *key, const char *data, void *out32);
int cr_hkdf_extract(const void *salt, int64_t slen, const void *ikm, int64_t ilen, void *out32);
int cr_hkdf_expand(const void *prk, int64_t plen, const void *info, int64_t ilen, void *out, int64_t olen);
int cr_hkdf(const void *salt, int64_t slen, const void *ikm, int64_t ilen, const void *info, int64_t inlen, void *out, int64_t olen);
int cr_aes256gcm(int encrypt, const void *key, const void *nonce, const void *aad, int64_t alen, void *buf, int64_t n, void *tag16);
int cr_x25519(const void *secret32, const void *public32, void *out32);
int cr_ed25519_public_key(const void *seed32, void *out32);
int cr_ed25519_sign(const void *seed32, const void *msg, int64_t n, void *out64);
int cr_ed25519_verify(const void *public32, const void *msg, int64_t n, const void *sig64);
int cr_p256_scalar_ok(const void *d32);
int cr_p256_public_key(const void *d32, void *out64);
int cr_p256_sign(const void *d32, const void *msg, int64_t n, void *out64);
int cr_p256_verify(const void *xy64, const void *msg, int64_t n, const void *sig64);
int cr_random(void *out, int64_t n);

static size_t cr_len(int64_t n) { return n < 0 ? 0 : (size_t) n; }

int cr_sha256(const void *data, int64_t n, void *out32) {
    br_sha256_context c;
    br_sha256_init(&c);
    if (n > 0) br_sha256_update(&c, data, cr_len(n));
    br_sha256_out(&c, out32);
    return 1;
}

/* A text's bytes, as the `#c` boundary hands a text: NUL-terminated. */
int cr_sha256_text(const char *data, void *out32) {
    return cr_sha256(data, (int64_t) strlen(data), out32);
}

int cr_hmac_sha256(const void *key, int64_t klen, const void *data, int64_t n, void *out32) {
    br_hmac_key_context kc;
    br_hmac_context hc;
    br_hmac_key_init(&kc, &br_sha256_vtable, key, cr_len(klen));
    br_hmac_init(&hc, &kc, 0);
    if (n > 0) br_hmac_update(&hc, data, cr_len(n));
    br_hmac_out(&hc, out32);
    return 1;
}

int cr_hmac_sha256_text(const char *key, const char *data, void *out32) {
    return cr_hmac_sha256(key, (int64_t) strlen(key), data, (int64_t) strlen(data), out32);
}

/* HKDF-Extract (RFC 5869 § 2.2): an empty salt is a hash-length of zeros, as the RFC says —
 * and as an HMAC key of length zero already is. */
int cr_hkdf_extract(const void *salt, int64_t slen, const void *ikm, int64_t ilen, void *out32) {
    return cr_hmac_sha256(salt, slen, ikm, ilen, out32);
}

/* HKDF-Expand (RFC 5869 § 2.3) from a PRK of at least the hash length, at most 255 * 32
 * bytes: T(i) = HMAC(PRK, T(i-1) | info | i).  Written out, because BearSSL's HKDF context
 * always runs the extract step first (its "no salt" is a zero salt). */
int cr_hkdf_expand(const void *prk, int64_t plen, const void *info, int64_t ilen, void *out, int64_t olen) {
    br_hmac_key_context kc;
    unsigned char t[32];
    size_t tlen = 0, done = 0, want = cr_len(olen);
    unsigned char counter = 1;
    if (plen < 32 || olen <= 0 || olen > 255 * 32) return 0;
    br_hmac_key_init(&kc, &br_sha256_vtable, prk, cr_len(plen));
    while (done < want) {
        br_hmac_context hc;
        size_t take;
        br_hmac_init(&hc, &kc, 0);
        if (tlen) br_hmac_update(&hc, t, tlen);
        if (ilen > 0) br_hmac_update(&hc, info, cr_len(ilen));
        br_hmac_update(&hc, &counter, 1);
        br_hmac_out(&hc, t);
        tlen = 32;
        take = want - done < 32 ? want - done : 32;
        memcpy((unsigned char *) out + done, t, take);
        done += take;
        counter++;
    }
    return 1;
}

int cr_hkdf(const void *salt, int64_t slen, const void *ikm, int64_t ilen, const void *info, int64_t inlen, void *out, int64_t olen) {
    unsigned char prk[32];
    if (!cr_hkdf_extract(salt, slen, ikm, ilen, prk)) return 0;
    return cr_hkdf_expand(prk, 32, info, inlen, out, olen);
}

/* AES-256-GCM over `buf` in place (`n` bytes): encrypting writes the tag, decrypting checks it
 * and answers 0 on a mismatch (the plaintext is then not to be used). */
int cr_aes256gcm(int encrypt, const void *key, const void *nonce, const void *aad, int64_t alen, void *buf, int64_t n, void *tag16) {
    br_aes_ct_ctr_keys bc;
    br_gcm_context gc;
    br_aes_ct_ctr_init(&bc, key, 32);
    br_gcm_init(&gc, &bc.vtable, br_ghash_ctmul32);
    br_gcm_reset(&gc, nonce, 12);
    if (alen > 0) br_gcm_aad_inject(&gc, aad, cr_len(alen));
    br_gcm_flip(&gc);
    if (n > 0) br_gcm_run(&gc, encrypt ? 1 : 0, buf, cr_len(n));
    if (encrypt) {
        br_gcm_get_tag(&gc, tag16);
        return 1;
    }
    return br_gcm_check_tag(&gc, tag16) == 1;
}

/* X25519 (RFC 7748): the scalar and the point little-endian as the RFC spells them; BearSSL
 * takes its scalar big-endian, so it is reversed on the way in. */
int cr_x25519(const void *secret32, const void *public32, void *out32) {
    unsigned char k[32], p[32];
    int i;
    for (i = 0; i < 32; i++) k[i] = ((const unsigned char *) secret32)[31 - i];
    memcpy(p, public32, 32);
    if (br_ec_c25519_m31.mul(p, 32, k, 32, BR_EC_curve25519) != 1) return 0;
    memcpy(out32, p, 32);
    return 1;
}

/* Ed25519 (RFC 8032) over Monocypher, from the 32-byte seed (which its key schedule wipes,
 * so it works on a copy). */
int cr_ed25519_public_key(const void *seed32, void *out32) {
    uint8_t seed[32], sk[64];
    memcpy(seed, seed32, 32);
    crypto_ed25519_key_pair(sk, (uint8_t *) out32, seed);
    crypto_wipe(sk, sizeof sk);
    return 1;
}

int cr_ed25519_sign(const void *seed32, const void *msg, int64_t n, void *out64) {
    uint8_t seed[32], sk[64], pk[32];
    memcpy(seed, seed32, 32);
    crypto_ed25519_key_pair(sk, pk, seed);
    crypto_ed25519_sign((uint8_t *) out64, sk, (const uint8_t *) msg, cr_len(n));
    crypto_wipe(sk, sizeof sk);
    return 1;
}

int cr_ed25519_verify(const void *public32, const void *msg, int64_t n, const void *sig64) {
    return crypto_ed25519_check((const uint8_t *) sig64, (const uint8_t *) public32, (const uint8_t *) msg, cr_len(n)) == 0;
}

/* The order of P-256, for the scalar check `0 < d < n` the Rust part made. */
static const unsigned char cr_p256_n[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
};

int cr_p256_scalar_ok(const void *d32) {
    const unsigned char *d = (const unsigned char *) d32;
    int i, zero = 1;
    for (i = 0; i < 32; i++) if (d[i]) zero = 0;
    if (zero) return 0;
    for (i = 0; i < 32; i++) {
        if (d[i] < cr_p256_n[i]) return 1;
        if (d[i] > cr_p256_n[i]) return 0;
    }
    return 0;
}

/* The public point as X || Y (64 bytes, the SEC1 uncompressed form without its 0x04). */
int cr_p256_public_key(const void *d32, void *out64) {
    unsigned char q[65];
    if (!cr_p256_scalar_ok(d32)) return 0;
    if (br_ec_p256_m31.mulgen(q, (const unsigned char *) d32, 32, BR_EC_secp256r1) != 65 || q[0] != 0x04) return 0;
    memcpy(out64, q + 1, 64);
    return 1;
}

/* ECDSA over SHA-256 with the deterministic nonce of RFC 6979 (BearSSL's HMAC-DRBG), as the
 * p256 crate signs: the same key and message give the same r || s (64 bytes). */
int cr_p256_sign(const void *d32, const void *msg, int64_t n, void *out64) {
    br_ec_private_key sk;
    unsigned char hash[32];
    if (!cr_p256_scalar_ok(d32)) return 0;
    cr_sha256(msg, n, hash);
    sk.curve = BR_EC_secp256r1;
    sk.x = (unsigned char *) d32;
    sk.xlen = 32;
    return br_ecdsa_i31_sign_raw(&br_ec_p256_m31, &br_sha256_vtable, hash, &sk, out64) == 64;
}

int cr_p256_verify(const void *xy64, const void *msg, int64_t n, const void *sig64) {
    br_ec_public_key pk;
    unsigned char q[65], hash[32];
    q[0] = 0x04;
    memcpy(q + 1, xy64, 64);
    pk.curve = BR_EC_secp256r1;
    pk.q = q;
    pk.qlen = 65;
    cr_sha256(msg, n, hash);
    return br_ecdsa_i31_vrfy_raw(&br_ec_p256_m31, hash, 32, &pk, sig64, 64) == 1;
}

/* `n` bytes of OS entropy; 0 where there is none (a wasm module). */
int cr_random(void *out, int64_t n) {
#if defined(__wasm__)
    (void) out;
    (void) n;
    return 0;
#elif defined(_WIN32)
    unsigned char *p = (unsigned char *) out;
    size_t left = cr_len(n);
    while (left) {
        unsigned v;
        size_t k = left < 4 ? left : 4;
        if (rand_s(&v) != 0) return 0;
        memcpy(p, &v, k);
        p += k;
        left -= k;
    }
    return 1;
#else
    FILE *f = fopen("/dev/urandom", "rb");
    size_t got;
    if (!f) return 0;
    got = fread(out, 1, cr_len(n), f);
    fclose(f);
    return got == cr_len(n);
#endif
}
