/* cc_internal.h — cursed-crypto's internal macros: compiler attributes, the ISA target regions, the
 * per-architecture switches and the resolve-once dispatch helpers.  Part of cursed-jwt, MIT licence (see
 * LICENSE).  Not a public header: the JWT layer (src/jwt.c) shares it for its own SIMD code (base64url). */
#ifndef CC_INTERNAL_H
#define CC_INTERNAL_H

#include "../include/cursed_crypto.h"

/* Build flags: inside crypto/ they are CC_*; the JWT_* spellings that cursed-jwt's Makefile, CI and contrib builds
 * pass are accepted too, so no command line has to change. */
#if defined(JWT_S2N) && !defined(CC_S2N)
#define CC_S2N 1
#endif
#if defined(JWT_OPENSSL) && !defined(CC_OPENSSL)
#define CC_OPENSSL 1
#endif
#if defined(JWT_RSAZ) && !defined(CC_RSAZ)
#define CC_RSAZ 1
#endif
#if defined(JWT_RSAZ8) && !defined(CC_RSAZ8)
#define CC_RSAZ8 1
#endif
#if defined(JWT_ES8) && !defined(CC_ES8)
#define CC_ES8 1
#endif
#if defined(JWT_CRYPTO_MB) && !defined(CC_CRYPTO_MB)
#define CC_CRYPTO_MB 1
#endif
#if defined(JWT_OSSL_SHA256) && !defined(CC_OSSL_SHA256)
#define CC_OSSL_SHA256 1
#endif
#if defined(JWT_SHANI_MB) && !defined(CC_SHANI_MB)
#define CC_SHANI_MB 1
#endif
#if defined(JWT_OSSL_SHA512) && !defined(CC_OSSL_SHA512)
#define CC_OSSL_SHA512 1
#endif
#if defined(JWT_ED25519_ASM) && !defined(CC_ED25519_ASM)
#define CC_ED25519_ASM 1
#endif
#if defined(JWT_ES256_ASM) && !defined(CC_ES256_ASM)
#define CC_ES256_ASM 1
#endif
#if defined(JWT_NO_ES256_ASM) && !defined(CC_NO_ES256_ASM)
#define CC_NO_ES256_ASM 1
#endif
#if defined(JWT_NO_ED25519_ASM) && !defined(CC_NO_ED25519_ASM)
#define CC_NO_ED25519_ASM 1
#endif
#if defined(JWT_OSSL_MONT) && !defined(CC_OSSL_MONT)
#define CC_OSSL_MONT 1
#endif
#if defined(JWT_RSA_SCREEN) && !defined(CC_RSA_SCREEN)
#define CC_RSA_SCREEN 1
#endif
#if defined(JWT_NO_PK) && !defined(CC_NO_PK)
#define CC_NO_PK 1
#endif
#if defined(JWT_INPUT_PADDED) && !defined(CC_INPUT_PADDED)
#define CC_INPUT_PADDED 1
#endif
/* tuning knobs with a value */
#if defined(JWT_P256_W) && !defined(CC_P256_W)
#define CC_P256_W JWT_P256_W
#endif
#if defined(JWT_ED_W) && !defined(CC_ED_W)
#define CC_ED_W JWT_ED_W
#endif
#if defined(JWT_ES_ILV) && !defined(CC_ES_ILV)
#define CC_ES_ILV JWT_ES_ILV
#endif
#if defined(JWT_ES8_MIN) && !defined(CC_ES8_MIN)
#define CC_ES8_MIN JWT_ES8_MIN
#endif
#if defined(JWT_X16_MIN) && !defined(CC_X16_MIN)
#define CC_X16_MIN JWT_X16_MIN
#endif
#if defined(JWT_AVX2X_MIN_LANES) && !defined(CC_AVX2X_MIN_LANES)
#define CC_AVX2X_MIN_LANES JWT_AVX2X_MIN_LANES
#endif

#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#if defined(__aarch64__) || defined(_M_ARM64)
#include <arm_neon.h>
#define CC_HAVE_NEON 1
#endif
#if defined(__x86_64__) || defined(__AVX2__)
#include <immintrin.h>
#endif

#define CC_INLINE static inline __attribute__((always_inline))

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#define CC_X86 1
#if defined(__clang__)
#define CC_BEGIN_AVX2 _Pragma("clang attribute push (__attribute__((target(\"avx2,bmi,bmi2\"))), apply_to = function)")
/* tune=skylake-avx512 carries "prefer 256-bit vectors": without it the compiler auto-vectorises copies and memsets in
 * this region with zmm, and one zmm instruction drops the core's frequency licence (19% slower for 0.5-1 ms on a
 * Cascade Lake; measured 29% slower full verify) -- exactly what the ymm-only design avoids. */
#define CC_BEGIN_AVX512                                                                                                \
    _Pragma(                                                                                                           \
        "clang attribute push (__attribute__((target(\"avx512f,avx512vl,avx512bw,avx512dq,avx512cd,avx2,bmi,bmi2,tune=skylake-avx512\"))), apply_to = function)")
#define CC_END_TARGET _Pragma("clang attribute pop")
#else
#define CC_BEGIN_AVX2 _Pragma("GCC push_options") _Pragma("GCC target(\"avx2,bmi,bmi2\")")
#define CC_BEGIN_AVX512                                                                                                \
    _Pragma("GCC push_options") _Pragma(                                                                               \
        "GCC target(\"avx512f,avx512vl,avx512bw,avx512dq,avx512cd,avx2,bmi,bmi2,tune=skylake-avx512,prefer-vector-width=256\")")
#define CC_END_TARGET _Pragma("GCC pop_options")
#endif
#endif
#if defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))
#define CC_ARM_SHA2 1 /* the SHA2-instruction engine is always compiled on AArch64 */
#if defined(__ARM_FEATURE_SHA2)
#define CC_BEGIN_SHA2
#define CC_END_SHA2
#elif defined(__clang__)
#define CC_BEGIN_SHA2 _Pragma("clang attribute push (__attribute__((target(\"sha2\"))), apply_to = function)")
#define CC_END_SHA2   _Pragma("clang attribute pop")
#else
#define CC_BEGIN_SHA2 _Pragma("GCC push_options") _Pragma("GCC target(\"+crypto\")")
#define CC_END_SHA2   _Pragma("GCC pop_options")
#endif
#if defined(__APPLE__)
#include <sys/sysctl.h>
#elif defined(__linux__)
#include <sys/auxv.h>
#endif
#endif

/* Resolve-once dispatch: each entry point calls through a pointer that starts at a resolver stub.  A constructor
 * (cc_sha256.c's, or jwt.c's for base64url), or the first call if it comes earlier, replaces it with the chosen engine, so a call
 * is one indirect call with no feature tests.  Relaxed atomics: racing resolvers all store the same pointer. */
#define CC_LOAD_FN(p)     __atomic_load_n(&(p), __ATOMIC_RELAXED)
#define CC_STORE_FN(p, f) __atomic_store_n(&(p), (f), __ATOMIC_RELAXED)

/* hidden: shared between cursed-crypto's objects and the JWT layer, never exported from a shared library */
#define CC_HIDDEN __attribute__((visibility("hidden")))
/* the dispatched HMAC engine (cc_sha256.c): the JWT layer's HS256 front end calls through it directly, so a separate
 * libcursedcrypto.a costs it no extra call */
extern CC_HIDDEN cc_hmac_fn *cc__hmac_impl;

CC_INLINE uint32_t be32(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return __builtin_bswap32(v);
}
/* constant-time helpers (the MAC compares): the value goes through an empty asm, so the optimiser can neither see
 * which bits are set nor turn the accumulation into an early exit; only the caller's verdict may branch on it */
CC_INLINE uint32_t cc_opaque32(uint32_t x) {
#if defined(__GNUC__)
    __asm__("" : "+r"(x));
#endif
    return x;
}
/* OR of the XORs of two MACs held as 8 state words: 0 iff equal */
CC_INLINE uint32_t cc_mac_diff8(const uint32_t a[8], const uint32_t b[8]) {
    uint32_t d = 0;
    for (int w = 0; w < 8; w++) d |= a[w] ^ b[w];
    return cc_opaque32(d);
}
/* 1 if x == 0 else 0, without a branch */
CC_INLINE int cc_is_zero32(uint32_t x) { return (int)(((uint64_t)x - 1) >> 63); }

#endif /* CC_INTERNAL_H */
