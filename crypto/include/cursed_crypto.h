/* cursed_crypto.h — cursed-crypto: batched SHA-256 / HMAC-SHA256 and RS256 / ES256 / Ed25519 signature
 * verification, with the engine picked at run time from the CPU.  Part of cursed-jwt, MIT licence (see LICENSE).
 *
 * Build: compile crypto/src/cursed_crypto.c (one translation unit) for the baseline ISA, no -march needed, or link
 * the Makefile's build/libcursedcrypto.a.  On x86-64 Linux the Makefile also assembles the .S kernels in crypto/src
 * (and crypto/src/s2n) and builds with -DCC_OSSL_SHA256 -DCC_OSSL_SHA512 -DCC_SHANI_MB -DCC_OSSL_MONT
 * -DCC_ED25519_ASM (README.md, Building, lists every option; the JWT_ spellings of the build flags are accepted as
 * well).
 *
 * Every call takes a batch: n messages, verified or hashed together, so the cost of a call is per batch.
 *
 * Timing contract, per function:
 *   constant time       everything that touches an HMAC key: cc_hmac_key_init, every cc_hmac_sha256_* engine,
 *                       cc_tag_eq32 and cc_hmac_sha256_verify (no key- or MAC-dependent branch or memory address;
 *                       checked by `make test-ct`, `test-ct-sde` and `test-ct-qemu`)
 *                       cc_sha512_* and cc_sha512 (no data-dependent operation at all; checked by `make test-ct`)
 *                       signing: cc_skey_ed25519, cc_skey_es256, cc_sign_batch and cc_skey_free (no branch or memory
 *                       address depends on the private key, Ed25519's expanded scalar and nonce prefix, or the
 *                       per-signature nonce (ES256: k, k^-1, the RFC 6979 state; only its ~2^-32 retries branch, on
 *                       a declassified bit); checked by `make test-ct`, `test-ct-sde`, `test-ct-qemu` and `make
 *                       dudect-sign`).  Signing shares no code with verification beyond fiat-crypto's field and scalar
 *                       operations and the hashes (verify-after-sign calls the verifier on the public result).
 *   variable time       signature verification (cc_pkey_*, cc_verify_batch): its inputs, the public key, the
 *                       message and the signature, are all public, as in every other library's verify
 */
#ifndef CURSED_CRYPTO_H
#define CURSED_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- CPU features ----
 * The engines are chosen from these bits.  Call an engine-specific entry point only if cc_cpu_features() has its
 * bit.  Env CC_CPU_MASK=0x.. (or JWT_CPU_MASK) masks bits away; CC_CPU_FORCE_ZMM=1 (or JWT_CPU_FORCE_ZMM) claims
 * FAST_ZMM on any AVX-512 CPU.  Both are for tests and benchmarks. */
enum {
    CC_CPU_AVX2 = 1,
    CC_CPU_AVX512VL = 2,
    CC_CPU_BMI2_ADX = 4,
    CC_CPU_SHANI = 8,
    CC_CPU_IFMA = 16,
    CC_CPU_SHA2 = 32,
    CC_CPU_SHA512 = 64,
    CC_CPU_FAST_ZMM = 128,   /* 512-bit vectors cost no clock speed (AMD Zen 4 / 5): the 16-lane zmm engine */
    CC_CPU_FAST_SHANI = 256, /* SHA-NI that beats the vector engines (AMD Zen): the 4-stream SHA-NI engine */
    CC_CPU_FULL_ZMM = 512,   /* full-width 512-bit execution (Zen 5 server/desktop): zmm for groups of 11+ */
    CC_CPU_VBMI = 1024,      /* AVX-512 VBMI (vpermi2b / vpermb) */
    CC_CPU_ZMM_HMAC = 2048   /* Intel AVX-512 without SHA-NI: zmm (x16) HMAC for groups of 9+; mask it to stay on ymm */
};
unsigned cc_cpu_features(void); /* CC_CPU_* bits */
const char *cc_engine(void);    /* the engine cc_hmac_sha256_batch uses: "shani", "zmm", "avx512vl", "avx2", ... */

/* ---- SHA-256 ----
 * dig[i] receives the 8 big-endian-interpreted state words (word j = digest bytes 4j..4j+3); the _bytes form writes
 * the 32-byte digest.  len[i] >= 0; msg[i] need not be aligned or padded. */
typedef void cc_sha256_fn(int n, const uint8_t *const *msg, const int *len, uint32_t (*dig)[8]);
cc_sha256_fn cc_sha256_batch; /* the default engine for this CPU */
void cc_sha256_bytes(int n, const uint8_t *const *msg, const int *len, uint8_t (*dig)[32]);

/* ---- HMAC-SHA256 (constant time in the key) ---- */
typedef struct {
    uint32_t ih[8]; /* SHA-256 state after compressing (key ^ ipad) */
    uint32_t oh[8]; /* SHA-256 state after compressing (key ^ opad) */
} cc_hmac_key_t;
/* A key of any length (> 64 bytes is hashed first, per RFC 2104). */
void cc_hmac_key_init(cc_hmac_key_t *k, const void *key, size_t len);
/* MACs of n messages under one key, as state words (see SHA-256 above), or as 32 bytes. */
typedef void cc_hmac_fn(const cc_hmac_key_t *k, int n, const uint8_t *const *msg, const int *len, uint32_t (*mac)[8]);
cc_hmac_fn cc_hmac_sha256_batch; /* the default engine for this CPU */
void cc_hmac_sha256_bytes(const cc_hmac_key_t *k, int n, const uint8_t *const *msg, const int *len, uint8_t (*mac)[32]);
/* ok[i] = 1 iff tag[i] is the MAC of msg[i], else 0; returns the number of 1s.  The compare is constant time: no
 * branch or address depends on the MACs or the tags (only the returned count and ok[] do). */
int cc_hmac_sha256_verify(const cc_hmac_key_t *k, int n, const uint8_t *const *msg, const int *len,
                          const uint8_t (*tag)[32], uint8_t *ok);
/* 1 iff the 32 bytes at a and b are equal, in constant time. */
int cc_tag_eq32(const void *a, const void *b);

/* ---- SHA-512 (FIPS 180-4; constant time: no branch or address depends on the data, only on its length) ----
 * Streaming: init, update any number of times, final (which wipes the context).  Used for Ed25519. */
typedef struct {
    uint64_t h[8];
    uint64_t total; /* bytes hashed so far */
    uint8_t buf[128];
    unsigned fill; /* bytes waiting in buf */
} cc_sha512_ctx;
/* constant time (tests: test_ct sign; the sign_ed traces of test-ct-sde / test-ct-qemu) */
void cc_sha512_init(cc_sha512_ctx *c);
void cc_sha512_update(cc_sha512_ctx *c, const void *data, size_t len); /* constant time */
void cc_sha512_final(cc_sha512_ctx *c, uint8_t out[64]);               /* constant time; wipes the context */
void cc_sha512(const void *data, size_t len, uint8_t out[64]);         /* constant time */

/* Overwrite len bytes with zeros in a way the compiler can't drop (for secrets about to go out of scope).
 * constant time */
void cc_wipe(void *p, size_t len);

/* ---- engine-specific entry points (same contracts), for tests and benchmarks ---- */
cc_sha256_fn cc_sha256_scalar;
cc_hmac_fn cc_hmac_sha256_scalar;
#if defined(__aarch64__) || defined(_M_ARM64)
cc_sha256_fn cc_sha256_neon;
cc_hmac_fn cc_hmac_sha256_neon;
#endif
#if defined(__aarch64__)
cc_sha256_fn cc_sha256_sha2;
cc_hmac_fn cc_hmac_sha256_sha2, cc_hmac_sha256_sha2_1, cc_hmac_sha256_sha2_2; /* 4 interleaved streams, 1, 2 */
#endif
#if defined(__x86_64__)
cc_sha256_fn cc_sha256_avx2, cc_sha256_avx512;
cc_hmac_fn cc_hmac_sha256_avx2;
cc_hmac_fn cc_hmac_sha256_shani_1, cc_hmac_sha256_shani_2, cc_hmac_sha256_shani_4; /* SHA-NI, 1 / 2 / 4 streams */
cc_hmac_fn cc_hmac_sha256_avx512, cc_hmac_sha256_zmm; /* zmm: 16 lanes in 512-bit registers */
#endif
#if (defined(CC_OSSL_SHA256) || defined(JWT_OSSL_SHA256)) && defined(__x86_64__) && defined(__ELF__)
cc_hmac_fn cc_hmac_sha256_ossl; /* one message at a time, OpenSSL's extracted x86-64 block function */
#endif
#if (defined(CC_SHANI_MB) || defined(JWT_SHANI_MB)) && defined(__x86_64__) && defined(__ELF__)
/* in assembly (crypto/src/sha256_shani_mb.S, sha256_x16_avx512.S): shani_4r = 4 hand-scheduled SHA-NI streams;
 * x16 = 16 lanes of zmm (needs CC_CPU_AVX512VL); shani_x16 = x16 for groups of 11+, shani_4r for the rest */
cc_hmac_fn cc_hmac_sha256_shani_4r, cc_hmac_sha256_x16, cc_hmac_sha256_shani_x16;
#endif

/* ---- signature verification (variable time: public inputs only) ----
 * Key setup does the expensive per-key work once (ES256: comb tables of 528 KB; EdDSA: 568 KB; RS256: Montgomery
 * constants).  A key fixes its algorithm.  Built by default; -DCC_NO_PK (or -DJWT_NO_PK) leaves it out. */
typedef struct cc_pkey cc_pkey_t;
enum { CC_PK_RS256 = 1, CC_PK_ES256 = 2, CC_PK_ED25519 = 3 };
/* ES256 (ECDSA P-256, SHA-256): the public point's affine coordinates, big-endian.  NULL if not on the curve. */
cc_pkey_t *cc_pkey_es256(const uint8_t x[32], const uint8_t y[32]);
/* RS256 (RSASSA-PKCS1-v1_5, SHA-256): modulus and public exponent, big-endian; 2048..4096-bit odd n, odd e in
 * [3, 2^64).  NULL otherwise. */
cc_pkey_t *cc_pkey_rs256(const uint8_t *n, size_t nlen, const uint8_t *e, size_t elen);
/* Ed25519 (RFC 8032): the 32-byte public key.  NULL if it does not decode to a point. */
cc_pkey_t *cc_pkey_ed25519(const uint8_t pub[32]);
void cc_pkey_free(cc_pkey_t *k);
int cc_pkey_alg(const cc_pkey_t *k);       /* CC_PK_* */
int cc_pkey_sig_bytes(const cc_pkey_t *k); /* the signature length the key takes: 64, or the modulus' bytes */
/* ok[i] = 1 iff sig[i] (slen[i] bytes) is a valid signature of msg[i] (len[i] bytes; hashed inside, batched).
 * Signatures are raw: ES256 r || s (64 bytes, as in JWS), RS256 the k-byte integer, Ed25519 R || S. */
void cc_verify_batch(const cc_pkey_t *k, int n, const uint8_t *const *msg, const int *len, const uint8_t *const *sig,
                     const int *slen, uint8_t *ok);

/* ---- signing (constant time in the private key) ----
 * A signing key never shares code with the verify side's key (cc_pkey_t): its scalar multiplication reads its table
 * only through constant-time selects, uses complete formulas, and inverts with a fixed addition chain.
 * Ed25519 (RFC 8032, deterministic: no random numbers): the 32-byte private key (the seed); the public key is derived
 * from it.  NULL only if out of memory.  cc_skey_free wipes the key before freeing it. */
typedef struct cc_skey cc_skey_t;
/* constant time (tests: test_ct sign, the sign_ed traces of test-ct-sde / test-ct-qemu, dudect_sign edkey) */
cc_skey_t *cc_skey_ed25519(const uint8_t seed[32]);
void cc_skey_free(cc_skey_t *k);                          /* constant time; wipes the key */
int cc_skey_alg(const cc_skey_t *k);                      /* CC_PK_* */
int cc_skey_sig_bytes(const cc_skey_t *k);                /* 64 for Ed25519 */
void cc_skey_public(const cc_skey_t *k, uint8_t pub[32]); /* the public key, as cc_pkey_ed25519 takes it */
/* sig[i] receives the signature of msg[i] (len[i] bytes): Ed25519 R || S, 64 bytes; ES256 r || s.  Returns the number
 * of signatures verify-after-sign rejected (zeroed), 0 without it.
 * constant time (tests: test_ct sign, the sign_ed traces of test-ct-sde / test-ct-qemu, dudect_sign ed) */
int cc_sign_batch(const cc_skey_t *k, int n, const uint8_t *const *msg, const int *len, uint8_t *const *sig);
/* ES256 (ECDSA P-256 with SHA-256; RFC 6979 deterministic nonces, so no random numbers): the private key d, 32 bytes
 * big-endian, 1 <= d < n (NULL otherwise, or if out of memory); the public point is derived.  Signatures are r || s,
 * 32 bytes big-endian each (JWS).  constant time (tests: test_ct sign, the sign_es traces of test-ct-sde /
 * test-ct-qemu, dudect_sign es) */
cc_skey_t *cc_skey_es256(const uint8_t d[32]);
void cc_skey_es256_public(const cc_skey_t *k, uint8_t x[32], uint8_t y[32]); /* as cc_pkey_es256 takes it */
/* Verify-after-sign (ES256 only; -1 for Ed25519 or out of memory): every signature is checked with the public key
 * (cc_verify_batch, about 1x the cost of signing; the key grows by the verifier's 528 KB tables) before it is released.
 * A signature that fails (a computation fault) is zeroed, and cc_sign_batch returns how many did; 0 otherwise. */
int cc_skey_verify_after_sign(cc_skey_t *k, int on);

#ifdef __cplusplus
}
#endif
#endif
