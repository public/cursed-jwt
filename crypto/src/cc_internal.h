/* cc_internal.h — cursed-crypto's internal macros: compiler attributes, the ISA target regions, the
 * per-architecture switches and the resolve-once dispatch helpers.  Part of cursed-jwt, MIT licence (see
 * LICENSE).  Not a public header: the JWT layer (src/jwt.c) shares it for its own SIMD code (base64url). */
#ifndef CC_INTERNAL_H
#define CC_INTERNAL_H

#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#if defined(__aarch64__) || defined(_M_ARM64)
#include <arm_neon.h>
#define JWT_HAVE_NEON 1
#endif
#if defined(__x86_64__) || defined(__AVX2__)
#include <immintrin.h>
#endif

#define JWT_INLINE static inline __attribute__((always_inline))

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#define JWT_X86 1
#if defined(__clang__)
#define JWT_BEGIN_AVX2 _Pragma("clang attribute push (__attribute__((target(\"avx2,bmi,bmi2\"))), apply_to = function)")
/* tune=skylake-avx512 carries "prefer 256-bit vectors": without it the compiler auto-vectorises copies and memsets in
 * this region with zmm, and one zmm instruction drops the core's frequency licence (19% slower for 0.5-1 ms on a
 * Cascade Lake; measured 29% slower full verify) -- exactly what the ymm-only design avoids. */
#define JWT_BEGIN_AVX512                                                                                               \
    _Pragma(                                                                                                           \
        "clang attribute push (__attribute__((target(\"avx512f,avx512vl,avx512bw,avx512dq,avx512cd,avx2,bmi,bmi2,tune=skylake-avx512\"))), apply_to = function)")
#define JWT_END_TARGET _Pragma("clang attribute pop")
#else
#define JWT_BEGIN_AVX2 _Pragma("GCC push_options") _Pragma("GCC target(\"avx2,bmi,bmi2\")")
#define JWT_BEGIN_AVX512                                                                                               \
    _Pragma("GCC push_options") _Pragma(                                                                               \
        "GCC target(\"avx512f,avx512vl,avx512bw,avx512dq,avx512cd,avx2,bmi,bmi2,tune=skylake-avx512,prefer-vector-width=256\")")
#define JWT_END_TARGET _Pragma("GCC pop_options")
#endif
#endif
#if defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))
#define JWT_ARM_SHA2 1 /* the SHA2-instruction engine is always compiled on AArch64 */
#if defined(__ARM_FEATURE_SHA2)
#define JWT_BEGIN_SHA2
#define JWT_END_SHA2
#elif defined(__clang__)
#define JWT_BEGIN_SHA2 _Pragma("clang attribute push (__attribute__((target(\"sha2\"))), apply_to = function)")
#define JWT_END_SHA2   _Pragma("clang attribute pop")
#else
#define JWT_BEGIN_SHA2 _Pragma("GCC push_options") _Pragma("GCC target(\"+crypto\")")
#define JWT_END_SHA2   _Pragma("GCC pop_options")
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
#define JWT_LOAD_FN(p)     __atomic_load_n(&(p), __ATOMIC_RELAXED)
#define JWT_STORE_FN(p, f) __atomic_store_n(&(p), (f), __ATOMIC_RELAXED)

#endif /* CC_INTERNAL_H */
