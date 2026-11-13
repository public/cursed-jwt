/* jwt.c — see jwt.h.  Part of cursed-jwt, MIT licence (see LICENSE).  The JWT layer over cursed-crypto (crypto/):
 *   3. base64url decode: scalar / NEON (vld4 de-interleave + vqtbl4) / AVX2 / AVX-512 VBMI; the encoder
 *   4. strict JSON for the header and payload; 4b. the shape-matched fast path for the payload
 *   5. the batch front ends (HS256, and RS256 / ES256 / EdDSA)
 *   6. signing (HS256, EdDSA)
 * Sections 1 and 2 (SHA-256 / HMAC, CPU dispatch) are crypto/src/cc_sha256.c, the public-key algorithms
 * crypto/src/cc_pk.c, Ed25519 signing crypto/src/cc_sign.c. */
#include "jwt.h"

#ifndef JWT_EXTERNAL_CRYPTO
/* cursed-crypto, compiled into this translation unit: a one-file build inlines exactly as before */
#include "../crypto/src/cursed_crypto.c"
/* cursed-jwt's internal names from before cursed-crypto had its own, for code that #includes this file and reaches
 * into it (contrib/envoy's filter does); -DJWT_NO_OLD_INTERNALS leaves them out */
#ifndef JWT_NO_OLD_INTERNALS
#define JWT_INLINE   CC_INLINE
#define JWT_LOAD_FN  CC_LOAD_FN
#define JWT_STORE_FN CC_STORE_FN
#define JWT_TL_XOR3  CC_TL_XOR3
#define JWT_TL_CH    CC_TL_CH
#define JWT_TL_MAJ   CC_TL_MAJ
#define hmac_impl    cc__hmac_impl
#define jwt_cpu      cc_cpu
#if defined(CC_X86)
#define JWT_X86          1
#define JWT_BEGIN_AVX2   CC_BEGIN_AVX2
#define JWT_BEGIN_AVX512 CC_BEGIN_AVX512
#define JWT_END_TARGET   CC_END_TARGET
#endif
#if defined(CC_HAVE_NEON)
#define JWT_HAVE_NEON 1
#endif
#if defined(CC_ARM_SHA2)
#define JWT_ARM_SHA2   1
#define JWT_BEGIN_SHA2 CC_BEGIN_SHA2
#define JWT_END_SHA2   CC_END_SHA2
#endif
#endif
#else
/* -DJWT_EXTERNAL_CRYPTO: the JWT layer alone (the Makefile's libcursedjwt.a), linked against cursed-crypto built as
 * its own unit (crypto/src/cursed_crypto.c, libcursedcrypto.a).  Only per-batch calls cross that boundary. */
#include "../crypto/src/cc_internal.h"
#define cc_cpu cc_cpu_features
#endif
#include "jwt_crypto_names.inc" /* jwt_key_init, jwt_hmac_*, jwt_sha256_*, jwt_cpu_features, jwt_engine */

/* ======================================================================================
 * 3. base64url
 * ====================================================================================== */

/* sextet value for the 64 base64url characters, 0xFF for everything else */
#define B64U_ROW(c)                                                                                                    \
    (((c) >= 'A' && (c) <= 'Z')   ? (c) - 'A'                                                                          \
     : ((c) >= 'a' && (c) <= 'z') ? (c) - 'a' + 26                                                                     \
     : ((c) >= '0' && (c) <= '9') ? (c) - '0' + 52                                                                     \
     : (c) == '-'                 ? 62                                                                                 \
     : (c) == '_'                 ? 63                                                                                 \
                                  : 0xFF)
#define B4(c)  (uint8_t) B64U_ROW(c), (uint8_t)B64U_ROW(c + 1), (uint8_t)B64U_ROW(c + 2), (uint8_t)B64U_ROW(c + 3)
#define B16(c) B4(c), B4(c + 4), B4(c + 8), B4(c + 12)
static const uint8_t b64u_tab[256]
    __attribute__((aligned(64))) = { B16(0),   B16(16),  B16(32),  B16(48),  B16(64),  B16(80),  B16(96),  B16(112),
                                     B16(128), B16(144), B16(160), B16(176), B16(192), B16(208), B16(224), B16(240) };

/* checks the length class and the canonical-zero trailing bits; decodes the final < 4 chars */
CC_INLINE int b64u_tail(uint8_t *dst, const char *src, int r) {
    const uint8_t *s = (const uint8_t *)src;
    uint32_t a, b, c;
    switch (r) {
        case 0: return 0;
        case 2:
            a = b64u_tab[s[0]], b = b64u_tab[s[1]];
            if ((a | b) & 0xC0 || b & 15) return -1;
            dst[0] = (uint8_t)(a << 2 | b >> 4);
            return 1;
        case 3:
            a = b64u_tab[s[0]], b = b64u_tab[s[1]], c = b64u_tab[s[2]];
            if ((a | b | c) & 0xC0 || c & 3) return -1;
            dst[0] = (uint8_t)(a << 2 | b >> 4), dst[1] = (uint8_t)(b << 4 | c >> 2);
            return 2;
        default: return -1;
    }
}

int jwt_b64url_decode_scalar(uint8_t *dst, const char *src, int n) {
    const uint8_t *s = (const uint8_t *)src;
    int q = n >> 2, o = 0;
    uint32_t bad = 0;
    for (int i = 0; i < q; i++, s += 4) {
        uint32_t a = b64u_tab[s[0]], b = b64u_tab[s[1]], c = b64u_tab[s[2]], d = b64u_tab[s[3]];
        bad |= a | b | c | d;
        uint32_t v = a << 18 | b << 12 | c << 6 | d;
        dst[o] = (uint8_t)(v >> 16), dst[o + 1] = (uint8_t)(v >> 8), dst[o + 2] = (uint8_t)v;
        o += 3;
    }
    if (bad & 0xC0) return -1;
    int t = b64u_tail(dst + o, (const char *)s, n & 3);
    return t < 0 ? -1 : o + t;
}

#if defined(CC_HAVE_NEON)
/* 64 chars -> 48 bytes: vld4 de-interleaves the 4 sextets of every quantum into 4 registers,
 * vqtbl4/vqtbx4 translate through a 128-byte table, vst3 re-interleaves the 3 output bytes.
 * Table misses give 0xFF; bytes >= 0x80 index nothing and are caught by OR-ing in the input. */
CC_INLINE uint8x16_t neon_b64_64(const uint8_t *src, uint8_t *dst, uint8x16x4_t lo, uint8x16x4_t hi) {
    const uint8x16_t x40 = vdupq_n_u8(0x40);
#define NEON_XLAT(v) vqtbx4q_u8(vqtbl4q_u8(lo, v), hi, veorq_u8(v, x40))
    uint8x16x4_t c = vld4q_u8(src);
    uint8x16_t a = NEON_XLAT(c.val[0]), b = NEON_XLAT(c.val[1]);
    uint8x16_t cc = NEON_XLAT(c.val[2]), d = NEON_XLAT(c.val[3]);
#undef NEON_XLAT
    uint8x16_t err = vorrq_u8(vorrq_u8(vorrq_u8(a, b), vorrq_u8(cc, d)),
                              vorrq_u8(vorrq_u8(c.val[0], c.val[1]), vorrq_u8(c.val[2], c.val[3])));
    uint8x16x3_t out;
    out.val[0] = vorrq_u8(vshlq_n_u8(a, 2), vshrq_n_u8(b, 4));
    out.val[1] = vorrq_u8(vshlq_n_u8(b, 4), vshrq_n_u8(cc, 2));
    out.val[2] = vorrq_u8(vshlq_n_u8(cc, 6), d);
    vst3q_u8(dst, out);
    return err;
}
int jwt_b64url_decode(uint8_t *dst, const char *src, int n) {
    const uint8x16x4_t lo = vld1q_u8_x4(b64u_tab), hi = vld1q_u8_x4(b64u_tab + 64);
    uint8x16_t err = vdupq_n_u8(0);
    int i = 0, o = 0;
    for (; i + 64 <= n; i += 64, o += 48) err = vorrq_u8(err, neon_b64_64((const uint8_t *)src + i, dst + o, lo, hi));
    int q = (n - i) & ~3;
    if (q) { /* whole quanta of the tail: one more SIMD block over an 'A'-padded copy */
        uint8_t buf[64], tmp[48];
        memset(buf, 'A', 64);
        memcpy(buf, src + i, q);
        err = vorrq_u8(err, neon_b64_64(buf, tmp, lo, hi));
        memcpy(dst + o, tmp, q / 4 * 3);
        i += q, o += q / 4 * 3;
    }
    if (vmaxvq_u8(err) & 0x80) return -1;
    int r = b64u_tail(dst + o, src + i, n - i);
    return r < 0 ? -1 : o + r;
}
#elif defined(CC_X86)
CC_BEGIN_AVX2
/* 32 chars -> 24 bytes (Muła/Lemire packing; base64url translation via range compares).
 * Stores 32 bytes per block: dst needs the 32 bytes of slack jwt.h asks for. */
CC_INLINE __m256i avx2_b64_32(const char *src, uint8_t *dst) {
#define RNG(v, lo, hi)                                                                                                 \
    _mm256_and_si256(_mm256_cmpgt_epi8(v, _mm256_set1_epi8((lo) - 1)), _mm256_cmpgt_epi8(_mm256_set1_epi8((hi) + 1), v))
    __m256i v = _mm256_loadu_si256((const __m256i *)src);
    __m256i up = RNG(v, 'A', 'Z'), lw = RNG(v, 'a', 'z'), dg = RNG(v, '0', '9');
#undef RNG
    __m256i da = _mm256_cmpeq_epi8(v, _mm256_set1_epi8('-')), us = _mm256_cmpeq_epi8(v, _mm256_set1_epi8('_'));
    __m256i off = _mm256_or_si256(
        _mm256_or_si256(_mm256_and_si256(up, _mm256_set1_epi8(-65)), _mm256_and_si256(lw, _mm256_set1_epi8(-71))),
        _mm256_or_si256(
            _mm256_and_si256(dg, _mm256_set1_epi8(4)),
            _mm256_or_si256(_mm256_and_si256(da, _mm256_set1_epi8(17)), _mm256_and_si256(us, _mm256_set1_epi8(-32)))));
    __m256i ok = _mm256_or_si256(_mm256_or_si256(up, lw), _mm256_or_si256(dg, _mm256_or_si256(da, us)));
    __m256i x = _mm256_add_epi8(v, off);
    x = _mm256_maddubs_epi16(x, _mm256_set1_epi32(0x01400140));
    x = _mm256_madd_epi16(x, _mm256_set1_epi32(0x00011000));
    x = _mm256_shuffle_epi8(x, _mm256_setr_epi8(2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1, 2, 1, 0, 6, 5,
                                                4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1));
    x = _mm256_permutevar8x32_epi32(x, _mm256_setr_epi32(0, 1, 2, 4, 5, 6, 7, 7));
    _mm256_storeu_si256((__m256i *)dst, x);
    return _mm256_xor_si256(ok, _mm256_set1_epi8(-1)); /* 0xFF where invalid */
}
static int b64url_decode_avx2(uint8_t *dst, const char *src, int n) {
    int i = 0, o = 0;
    __m256i bad = _mm256_setzero_si256();
    for (; i + 32 <= n; i += 32, o += 24) bad = _mm256_or_si256(bad, avx2_b64_32(src + i, dst + o));
    int q = (n - i) & ~3;
    if (q) { /* whole quanta of the tail: one more SIMD block over an 'A'-padded copy */
        char buf[32];
        memset(buf, 'A', 32);
        memcpy(buf, src + i, q);
        bad = _mm256_or_si256(bad, avx2_b64_32(buf, dst + o));
        i += q, o += q / 4 * 3;
    }
    if (!_mm256_testz_si256(bad, bad)) return -1;
    int r = b64u_tail(dst + o, src + i, n - i);
    return r < 0 ? -1 : o + r;
}
CC_END_TARGET
/* AVX-512 VBMI, 64 chars -> 48 bytes per step (the approach of Muła and Lemire, "Base64 encoding and decoding at
 * almost the speed of a memory copy", SPE 2020; the packing as in simdutf's icelake kernel).  Used only on CPUs
 * where 512-bit vectors cost no clock speed (FAST_ZMM, i.e. AMD Zen 4 / 5).
 *  - every load is masked to the input, every store to the output: no slack is read or written;
 *  - translation: one vpermi2b through b64u_tab's first 128 entries (invalid ones have bit 7 set), OR'd with the
 *    input so a byte >= 0x80 is caught as well, tested under the load mask;
 *  - the final partial quantum (2 or 3 chars) decodes to 3 bytes with the unused low bits in the bytes past the
 *    output: they must be zero (the canonical-trailing-bits rule), checked by one masked test;
 *  - n % 4 == 1 is never valid. */
__attribute__((target("avx512f,avx512bw,avx512vl,avx512vbmi"))) static int b64url_decode_vbmi(uint8_t *dst,
                                                                                              const char *src, int n) {
    if ((n & 3) == 1) return -1;
    const __m512i lo = _mm512_load_si512((const void *)b64u_tab), hi = _mm512_load_si512((const void *)(b64u_tab + 64));
    const __m512i m1 = _mm512_set1_epi32(0x01400140), m2 = _mm512_set1_epi32(0x00011000);
    /* output byte 3j + r = byte 2 - r of 32-bit lane j (a << 18 | b << 12 | c << 6 | d, little-endian) */
    const __m512i pk = _mm512_set_epi8(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 60, 61, 62, 56, 57, 58, 52, 53,
                                       54, 48, 49, 50, 44, 45, 46, 40, 41, 42, 36, 37, 38, 32, 33, 34, 28, 29, 30, 24,
                                       25, 26, 20, 21, 22, 16, 17, 18, 12, 13, 14, 8, 9, 10, 4, 5, 6, 0, 1, 2);
    const __m512i hb = _mm512_set1_epi8((char)0x80);
    __mmask64 bad = 0;
    int i = 0, o = 0;
    for (; i + 64 <= n; i += 64, o += 48) {
        __m512i v = _mm512_loadu_si512((const void *)(src + i));
        __m512i t = _mm512_permutex2var_epi8(lo, v, hi);
        bad |= _mm512_test_epi8_mask(_mm512_or_si512(t, v), hb);
        __m512i x = _mm512_madd_epi16(_mm512_maddubs_epi16(t, m1), m2);
        _mm512_mask_storeu_epi8(dst + o, (__mmask64)0xFFFFFFFFFFFFull, _mm512_permutexvar_epi8(pk, x));
    }
    int m = n - i;
    if (m) {
        __mmask64 k = ((__mmask64)1 << m) - 1;
        __m512i v = _mm512_maskz_loadu_epi8(k, src + i);
        __m512i t = _mm512_maskz_mov_epi8(k, _mm512_permutex2var_epi8(lo, v, hi)); /* lanes past the input: 0 */
        bad |= _mm512_mask_test_epi8_mask(k, _mm512_or_si512(t, v), hb);
        __m512i y = _mm512_permutexvar_epi8(pk, _mm512_madd_epi16(_mm512_maddubs_epi16(t, m1), m2));
        int out = m / 4 * 3 + (m & 3 ? (m & 3) - 1 : 0), full = (m + 3) / 4 * 3;
        __mmask64 spare = (((__mmask64)1 << full) - 1) & ~(((__mmask64)1 << out) - 1);
        bad |= _mm512_mask_test_epi8_mask(spare, y, y); /* leftover bits of a partial quantum must be zero */
        _mm512_mask_storeu_epi8(dst + o, ((__mmask64)1 << out) - 1, y);
        o += out;
    }
    return bad ? -1 : o;
}
static int b64url_decode_resolve(uint8_t *dst, const char *src, int n);
static int (*b64url_impl)(uint8_t *, const char *, int) = b64url_decode_resolve;
static int b64u_pick_vbmi(void) {
    /* AVX512VL as well, so that JWT_CPU_MASK can take AVX-512 away on its own */
    const unsigned need = CC_CPU_VBMI | CC_CPU_FAST_ZMM | CC_CPU_AVX512VL;
    return (cc_cpu() & need) == need;
}
static int b64url_decode_resolve(uint8_t *dst, const char *src, int n) {
    int (*f)(uint8_t *, const char *, int) = b64u_pick_vbmi()         ? b64url_decode_vbmi
                                             : cc_cpu() & CC_CPU_AVX2 ? b64url_decode_avx2
                                                                      : jwt_b64url_decode_scalar;
    CC_STORE_FN(b64url_impl, f);
    return f(dst, src, n);
}
int jwt_b64url_decode(uint8_t *dst, const char *src, int n) { return CC_LOAD_FN(b64url_impl)(dst, src, n); }
#else
int jwt_b64url_decode(uint8_t *dst, const char *src, int n) { return jwt_b64url_decode_scalar(dst, src, n); }
#endif

/* base64url encode, unpadded.  Branch-free and table-free (the MAC and signature bytes go through it): each sextet v
 * maps to v + 'A', then masks derived from v by subtraction move it to 'a'..'z', '0'..'9', '-' or '_'.  x86-64 with
 * AVX2 runs the body 24 bytes at a time (below); the branches there depend on the length only. */
CC_INLINE char b64u_char(uint32_t v) {
#define B64U_GE(x) (0u - ((uint32_t)((x) - v) >> 31)) /* all ones iff v > x */
    uint32_t c = v + 'A';
    c += B64U_GE(25) & 6;  /* 26..51 -> 'a'..'z' */
    c -= B64U_GE(51) & 75; /* 52..61 -> '0'..'9' */
    c -= B64U_GE(61) & 13; /* 62 -> '-' */
    c += B64U_GE(62) & 49; /* 63 -> '_' */
#undef B64U_GE
    return (char)c;
}
int jwt_b64url_encode_scalar(char *dst, const uint8_t *src, int n) {
    int o = 0, i = 0;
    for (; i + 3 <= n; i += 3, o += 4) {
        uint32_t v = (uint32_t)src[i] << 16 | (uint32_t)src[i + 1] << 8 | src[i + 2];
        dst[o] = b64u_char(v >> 18), dst[o + 1] = b64u_char(v >> 12 & 63);
        dst[o + 2] = b64u_char(v >> 6 & 63), dst[o + 3] = b64u_char(v & 63);
    }
    if (n - i == 1) {
        uint32_t v = (uint32_t)src[i] << 16;
        dst[o++] = b64u_char(v >> 18), dst[o++] = b64u_char(v >> 12 & 63);
    } else if (n - i == 2) {
        uint32_t v = (uint32_t)src[i] << 16 | (uint32_t)src[i + 1] << 8;
        dst[o++] = b64u_char(v >> 18), dst[o++] = b64u_char(v >> 12 & 63), dst[o++] = b64u_char(v >> 6 & 63);
    }
    return o;
}
#if defined(CC_X86)
CC_BEGIN_AVX2
/* AVX2, 24 bytes -> 32 characters per step (Mula and Lemire, "Faster Base64 Encoding and Decoding using AVX2
 * Instructions", ACM TOW 2018): the sextets are unpacked with shuffles and multiplies, and translated with a vpshufb
 * of a register-held table of offsets (no memory lookup, so no data-dependent address).  The whole groups left over
 * go through a zero-padded copy; a final 1- or 2-byte group through the scalar code. */
CC_INLINE void avx2_b64e_24(char *dst, const uint8_t *src) { /* reads 28 bytes, writes 32 characters */
    const __m256i shuf = _mm256_setr_epi8(1, 0, 2, 1, 4, 3, 5, 4, 7, 6, 8, 7, 10, 9, 11, 10, 1, 0, 2, 1, 4, 3, 5, 4, 7,
                                          6, 8, 7, 10, 9, 11, 10);
    /* offsets: 0..25 +'A', 26..51 +('a' - 26), 52..61 +('0' - 52), 62 -> '-', 63 -> '_' */
    const __m256i lut = _mm256_setr_epi8(65, 71, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4, -17, 32, 0, 0, 65, 71, -4, -4,
                                         -4, -4, -4, -4, -4, -4, -4, -4, -17, 32, 0, 0);
    /* each 128-bit lane reads 16 bytes and uses the first 12 */
    __m256i in = _mm256_inserti128_si256(_mm256_castsi128_si256(_mm_loadu_si128((const __m128i *)src)),
                                         _mm_loadu_si128((const __m128i *)(src + 12)), 1);
    in = _mm256_shuffle_epi8(in, shuf); /* per 32-bit lane: bytes b1 b0 b2 b1 of a 3-byte group */
    __m256i t0 = _mm256_and_si256(in, _mm256_set1_epi32(0x0fc0fc00));
    __m256i t1 = _mm256_mulhi_epu16(t0, _mm256_set1_epi32(0x04000040));
    __m256i t2 = _mm256_and_si256(in, _mm256_set1_epi32(0x003f03f0));
    __m256i t3 = _mm256_mullo_epi16(t2, _mm256_set1_epi32(0x01000010));
    __m256i v = _mm256_or_si256(t1, t3); /* one sextet per byte */
    __m256i idx = _mm256_subs_epu8(v, _mm256_set1_epi8(51));
    idx = _mm256_sub_epi8(idx, _mm256_cmpgt_epi8(v, _mm256_set1_epi8(25)));
    _mm256_storeu_si256((__m256i *)dst, _mm256_add_epi8(v, _mm256_shuffle_epi8(lut, idx)));
}
static int b64url_encode_avx2(char *dst, const uint8_t *src, int n) {
    int i = 0, o = 0;
    for (; i + 28 <= n; i += 24, o += 32) avx2_b64e_24(dst + o, src + i);
    int g = (n - i) / 3 * 3; /* the remaining whole 3-byte groups (< 28 bytes): through a zero-padded copy */
    if (g) {
        uint8_t buf[56] = { 0 };
        char tmp[64];
        memcpy(buf, src + i, (size_t)g);
        avx2_b64e_24(tmp, buf);
        if (g > 24) avx2_b64e_24(tmp + 32, buf + 24);
        memcpy(dst + o, tmp, (size_t)(g / 3 * 4));
        i += g, o += g / 3 * 4;
    }
    return o + jwt_b64url_encode_scalar(dst + o, src + i, n - i); /* the last 1 or 2 bytes */
}
CC_END_TARGET
static int b64url_encode_resolve(char *dst, const uint8_t *src, int n);
static int (*b64url_enc_impl)(char *, const uint8_t *, int) = b64url_encode_resolve;
static int b64url_encode_resolve(char *dst, const uint8_t *src, int n) {
    int (*f)(char *, const uint8_t *, int) = cc_cpu() & CC_CPU_AVX2 ? b64url_encode_avx2 : jwt_b64url_encode_scalar;
    CC_STORE_FN(b64url_enc_impl, f);
    return f(dst, src, n);
}
int jwt_b64url_encode(char *dst, const uint8_t *src, int n) { return CC_LOAD_FN(b64url_enc_impl)(dst, src, n); }
#else
int jwt_b64url_encode(char *dst, const uint8_t *src, int n) { return jwt_b64url_encode_scalar(dst, src, n); }
#endif

/* ======================================================================================
 * 4. strict JSON
 *
 * Grammar is RFC 8259 exactly (no comments, no trailing commas, no NaN, UTF-8 validated
 * inside strings, nesting depth <= 32).  Choices for claims (see README.md):
 *   - a repeated sub / username / exp / nbf (or alg in the header) -> INVALID (JSON.parse would
 *     silently take the last one; we refuse to guess)
 *   - keys are compared after unescaping, so "sub" is "sub"
 *   - lone surrogate escapes in username decode to U+FFFD
 * ====================================================================================== */

typedef struct {
    const uint8_t *p, *e;
} jcur_t;

CC_INLINE void jws(jcur_t *c) {
    while (c->p < c->e && (*c->p == ' ' || *c->p == '\t' || *c->p == '\n' || *c->p == '\r')) c->p++;
}

static int hex4(const uint8_t *p, uint32_t *v) {
    uint32_t r = 0;
    for (int i = 0; i < 4; i++) {
        uint8_t ch = p[i];
        uint32_t d;
        if (ch >= '0' && ch <= '9') d = ch - '0';
        else if ((ch | 0x20) >= 'a' && (ch | 0x20) <= 'f') d = (ch | 0x20) - 'a' + 10;
        else return 0;
        r = r << 4 | d;
    }
    *v = r;
    return 1;
}

/* Validates a string at c->p (which must be at '"'); returns its raw contents and whether it has
 * escapes.  0 on any grammar or UTF-8 error. */
/* 1 for bytes that end the fast path inside a string: '"', '\\', < 0x20, >= 0x80 */
#define JC4(c)                                                                                                         \
    (c) < 0x20 || (c) >= 0x80 || (c) == '"' || (c) == '\\',                                                            \
        (c) + 1 < 0x20 || (c) + 1 >= 0x80 || (c) + 1 == '"' || (c) + 1 == '\\',                                        \
        (c) + 2 < 0x20 || (c) + 2 >= 0x80 || (c) + 2 == '"' || (c) + 2 == '\\',                                        \
        (c) + 3 < 0x20 || (c) + 3 >= 0x80 || (c) + 3 == '"' || (c) + 3 == '\\'
#define JC16(c) JC4(c), JC4(c + 4), JC4(c + 8), JC4(c + 12)
static const uint8_t jstop[256] = { JC16(0),   JC16(16),  JC16(32),  JC16(48),  JC16(64),  JC16(80),
                                    JC16(96),  JC16(112), JC16(128), JC16(144), JC16(160), JC16(176),
                                    JC16(192), JC16(208), JC16(224), JC16(240) };

CC_INLINE int jstr(jcur_t *c, const uint8_t **s, int *n, int *esc) {
    const uint8_t *p = c->p, *e = c->e;
    if (p >= e || *p != '"') return 0;
    *s = ++p;
    *esc = 0;
    for (;;) {
        while (p < e && !jstop[*p]) p++;
        if (p >= e) return 0;
        uint8_t ch = *p;
        if (ch == '"') break;
        if (ch < 0x20) return 0;
        if (ch == '\\') {
            *esc = 1;
            if (p + 1 >= e) return 0;
            uint8_t x = p[1];
            if (x == 'u') {
                uint32_t v;
                if (p + 6 > e || !hex4(p + 2, &v)) return 0;
                p += 6;
            } else if (x == '"' || x == '\\' || x == '/' || x == 'b' || x == 'f' || x == 'n' || x == 'r' || x == 't') {
                p += 2;
            } else {
                return 0;
            }
            continue;
        }
        if (ch < 0x80) {
            p++;
            continue;
        }
        /* UTF-8: reject overlongs, surrogates, > U+10FFFF */
        int len;
        uint32_t cp;
        if (ch >= 0xC2 && ch <= 0xDF) len = 2, cp = ch & 0x1F;
        else if (ch >= 0xE0 && ch <= 0xEF) len = 3, cp = ch & 0x0F;
        else if (ch >= 0xF0 && ch <= 0xF4) len = 4, cp = ch & 0x07;
        else return 0;
        if (p + len > e) return 0;
        for (int i = 1; i < len; i++) {
            if ((p[i] & 0xC0) != 0x80) return 0;
            cp = cp << 6 | (p[i] & 0x3F);
        }
        if ((len == 3 && (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF))) ||
            (len == 4 && (cp < 0x10000 || cp > 0x10FFFF)))
            return 0;
        p += len;
    }
    *n = (int)(p - *s);
    c->p = p + 1;
    return 1;
}

/* Unescape a validated raw string into dst (cap bytes).  Returns length, or -1 if it won't fit. */
static int junescape(uint8_t *dst, int cap, const uint8_t *s, int n) {
    int o = 0;
    for (int i = 0; i < n;) {
        uint32_t cp = 0;
        if (s[i] != '\\') {
            if (o >= cap) return -1;
            dst[o++] = s[i++];
            continue;
        }
        uint8_t x = s[i + 1];
        i += 2;
        switch (x) {
            case 'b': cp = 8; break;
            case 'f': cp = 12; break;
            case 'n': cp = 10; break;
            case 'r': cp = 13; break;
            case 't': cp = 9; break;
            case 'u':
                hex4(s + i, &cp);
                i += 4;
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    uint32_t lo;
                    if (i + 6 <= n && s[i] == '\\' && s[i + 1] == 'u' && hex4(s + i + 2, &lo) && lo >= 0xDC00 &&
                        lo <= 0xDFFF) {
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        i += 6;
                    } else {
                        cp = 0xFFFD;
                    }
                } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                    cp = 0xFFFD;
                }
                break;
            default: cp = x; break; /* " \ / */
        }
        int need = cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
        if (o + need > cap) return -1;
        if (need == 1) dst[o++] = (uint8_t)cp;
        else if (need == 2) dst[o++] = (uint8_t)(0xC0 | cp >> 6), dst[o++] = (uint8_t)(0x80 | (cp & 0x3F));
        else if (need == 3)
            dst[o++] = (uint8_t)(0xE0 | cp >> 12), dst[o++] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F)),
            dst[o++] = (uint8_t)(0x80 | (cp & 0x3F));
        else
            dst[o++] = (uint8_t)(0xF0 | cp >> 18), dst[o++] = (uint8_t)(0x80 | ((cp >> 12) & 0x3F)),
            dst[o++] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F)), dst[o++] = (uint8_t)(0x80 | (cp & 0x3F));
    }
    return o;
}

/* A JSON number at c->p: validates the grammar and returns its span.  *isint is set when it is a
 * plain integer of <= 18 digits (value via jint); nothing is computed for numbers we skip. */
CC_INLINE int jnum(jcur_t *c, const uint8_t **s, int *n, int *isint) {
    const uint8_t *p = c->p, *e = c->e, *d;
    int simple = 1;
    *s = p;
    if (p < e && *p == '-') p++;
    if (p >= e) return 0;
    d = p;
    if (*p == '0') p++;
    else if (*p >= '1' && *p <= '9')
        while (p < e && *p >= '0' && *p <= '9') p++;
    else return 0;
    int digits = (int)(p - d);
    if (p < e && *p == '.') {
        simple = 0, p++;
        if (p >= e || *p < '0' || *p > '9') return 0;
        while (p < e && *p >= '0' && *p <= '9') p++;
    }
    if (p < e && (*p == 'e' || *p == 'E')) {
        simple = 0, p++;
        if (p < e && (*p == '+' || *p == '-')) p++;
        if (p >= e || *p < '0' || *p > '9') return 0;
        while (p < e && *p >= '0' && *p <= '9') p++;
    }
    *n = (int)(p - *s);
    *isint = simple && digits <= 18;
    c->p = p;
    return 1;
}

/* 8 ASCII digits -> value, SWAR (three multiplies instead of an 8-long multiply-add chain) */
CC_INLINE uint64_t swar8(uint64_t x) { /* x = 8 digits, first digit in the low byte */
    x -= 0x3030303030303030ull;
    x = x * 10 + (x >> 8);
    x = ((x & 0x000000FF000000FFull) * (100 + (1000000ull << 32)) +
         ((x >> 16) & 0x000000FF000000FFull) * (1 + (10000ull << 32))) >>
        32;
    return x;
}
/* value of a validated integer span of <= 18 digits (optional '-') */
static int64_t jint(const uint8_t *s, int n) {
    int neg = *s == '-';
    s += neg, n -= neg;
    uint64_t v = 0;
    while (n >= 8) {
        uint64_t x;
        memcpy(&x, s, 8);
        v = v * 100000000u + swar8(x), s += 8, n -= 8;
    }
    if (n) {
        uint64_t x = 0x3030303030303030ull, y = 0;
        memcpy(&y, s, n); /* little-endian: digits go to the high bytes, '0's pad the low ones */
        x = (x & ~(~0ull << (8 * (8 - n)))) | (y << (8 * (8 - n)));
        uint64_t p10 = 1;
        for (int i = 0; i < n; i++) p10 *= 10;
        v = v * p10 + swar8(x);
    }
    return neg ? -(int64_t)v : (int64_t)v;
}

/* Compare a JSON number with now: returns -1 / 0 / +1 for num < / == / > now. */
/* "now", formatted once per batch: an all-digit JSON integer (no leading zeros by grammar) compares
 * with it by digit count, then bytewise, with no number conversion at all. */
typedef struct {
    int64_t t;
    int len;
    uint8_t s[24];
} jnow_t;
static void jnow_init(jnow_t *jn, int64_t now) {
    uint8_t tmp[24];
    int l = 0;
    uint64_t u = now > 0 ? (uint64_t)now : 0;
    do tmp[l++] = (uint8_t)('0' + u % 10), u /= 10;
    while (u);
    for (int i = 0; i < l; i++) jn->s[i] = tmp[l - 1 - i];
    jn->len = now > 0 ? l : 0, jn->t = now;
}

/* Compare a JSON number with now: returns -1 / 0 / +1 for num < / == / > now. */
static int jnum_cmp(const uint8_t *s, int n, int isint, const jnow_t *now) {
    if (isint && now->len && s[0] != '-') {
        if (n != now->len) return n < now->len ? -1 : 1;
        for (int i = 0; i < n; i++)
            if (s[i] != now->s[i]) return s[i] < now->s[i] ? -1 : 1;
        return 0;
    }
    if (isint) {
        int64_t iv = jint(s, n);
        return iv < now->t ? -1 : iv > now->t;
    }
    char buf[64];
    if (n >= (int)sizeof buf) { /* absurdly long number: strtod on a heap copy */
        char *big = malloc(n + 1);
        if (!big) return -1;
        memcpy(big, s, n), big[n] = 0;
        double d = strtod(big, NULL);
        free(big);
        return d < (double)now->t ? -1 : d > (double)now->t;
    }
    memcpy(buf, s, n), buf[n] = 0;
    double d = strtod(buf, NULL);
    return d < (double)now->t ? -1 : d > (double)now->t;
}

static int jskip(jcur_t *c, int depth) {
    jws(c);
    if (c->p >= c->e) return 0;
    const uint8_t *s;
    int n, esc, isint;
    switch (*c->p) {
        case '"': return jstr(c, &s, &n, &esc);
        case '{':
        case '[': {
            uint8_t close = *c->p == '{' ? '}' : ']';
            int obj = close == '}';
            if (depth >= 32) return 0;
            c->p++;
            jws(c);
            if (c->p < c->e && *c->p == close) return c->p++, 1;
            for (;;) {
                if (obj) {
                    jws(c);
                    if (!jstr(c, &s, &n, &esc)) return 0;
                    jws(c);
                    if (c->p >= c->e || *c->p++ != ':') return 0;
                }
                if (!jskip(c, depth + 1)) return 0;
                jws(c);
                if (c->p >= c->e) return 0;
                if (*c->p == ',') {
                    c->p++;
                    continue;
                }
                if (*c->p == close) return c->p++, 1;
                return 0;
            }
        }
        case 't':
            if (c->e - c->p >= 4 && !memcmp(c->p, "true", 4)) return c->p += 4, 1;
            return 0;
        case 'f':
            if (c->e - c->p >= 5 && !memcmp(c->p, "false", 5)) return c->p += 5, 1;
            return 0;
        case 'n':
            if (c->e - c->p >= 4 && !memcmp(c->p, "null", 4)) return c->p += 4, 1;
            return 0;
        default: return jnum(c, &s, &n, &isint);
    }
}

/* key -> small id; keys are unescaped first when needed */
enum { K_OTHER, K_SUB, K_USERNAME, K_EXP, K_NBF, K_ALG };
CC_INLINE int jkey(const uint8_t *s, int n, int esc) {
    uint8_t buf[16];
    if (esc) {
        n = junescape(buf, sizeof buf, s, n);
        if (n < 0) return K_OTHER;
        s = buf;
    }
    switch (n) {
        case 3:
            if (!memcmp(s, "sub", 3)) return K_SUB;
            if (!memcmp(s, "exp", 3)) return K_EXP;
            if (!memcmp(s, "nbf", 3)) return K_NBF;
            if (!memcmp(s, "alg", 3)) return K_ALG;
            return K_OTHER;
        case 8: return memcmp(s, "username", 8) ? K_OTHER : K_USERNAME;
        default: return K_OTHER;
    }
}

/* Header: an object whose "alg" is exactly `want` (5 characters, e.g. "HS256").  Inlined: the RS256 / ES256 path
 * shares it, and as a called function it would cost HS256 a call per token. */
CC_INLINE int header_ok(const uint8_t *h, int n, const char *want) {
    jcur_t c = { h, h + n };
    const uint8_t *s;
    int len, esc, alg = 0;
    jws(&c);
    if (c.p >= c.e || *c.p++ != '{') return 0;
    jws(&c);
    if (c.p < c.e && *c.p == '}') return 0; /* {} has no alg */
    for (;;) {
        jws(&c);
        if (!jstr(&c, &s, &len, &esc)) return 0;
        int key = jkey(s, len, esc);
        jws(&c);
        if (c.p >= c.e || *c.p++ != ':') return 0;
        jws(&c);
        if (key == K_ALG) {
            uint8_t v[8];
            if (alg++ || !jstr(&c, &s, &len, &esc)) return 0;
            if (esc) {
                len = junescape(v, sizeof v, s, len);
                s = v;
            }
            if (len != 5 || memcmp(s, want, 5)) return 0;
        } else if (!jskip(&c, 1)) {
            return 0;
        }
        jws(&c);
        if (c.p >= c.e) return 0;
        if (*c.p == ',') {
            c.p++;
            continue;
        }
        if (*c.p++ != '}') return 0;
        break;
    }
    jws(&c);
    return c.p == c.e && alg == 1;
}

/* "sub": digits only (leading zeros allowed), 1 <= value <= INT64_MAX */
CC_INLINE int sub_value(const uint8_t *s, int len, int64_t *uid) {
    int64_t v = 0;
    if (len <= 0) return 0;
    for (int i = 0; i < len; i++) {
        if (s[i] < '0' || s[i] > '9' || v > (INT64_MAX - (s[i] - '0')) / 10) return 0;
        v = v * 10 + (s[i] - '0');
    }
    if (v <= 0) return 0;
    *uid = v;
    return 1;
}

/* Payload claims -> result.  Precedence: malformed/expired/not-yet-valid -> INVALID, then
 * sub/username problems -> BAD_PAYLOAD. */
CC_INLINE int payload_check(const uint8_t *pl, int n, const jnow_t *now, jwt_result_t *r) {
    jcur_t c = { pl, pl + n };
    const uint8_t *s;
    int len, esc, seen = 0, bad = 0, isint;
    jws(&c);
    if (c.p >= c.e || *c.p++ != '{') return JWT_INVALID;
    jws(&c);
    if (c.p < c.e && *c.p == '}') return JWT_INVALID; /* no exp */
    for (;;) {
        jws(&c);
        if (!jstr(&c, &s, &len, &esc)) return JWT_INVALID;
        int key = jkey(s, len, esc);
        jws(&c);
        if (c.p >= c.e || *c.p++ != ':') return JWT_INVALID;
        jws(&c);
        if (key != K_OTHER && key != K_ALG) {
            if (seen & (1 << key)) return JWT_INVALID;
            seen |= 1 << key;
        }
        if (c.p >= c.e) return JWT_INVALID;
        if (key == K_EXP || key == K_NBF) {
            if (*c.p != '-' && (*c.p < '0' || *c.p > '9')) return JWT_INVALID; /* must be a number */
            if (!jnum(&c, &s, &len, &isint)) return JWT_INVALID;
            int cmp = jnum_cmp(s, len, isint, now);
            if (key == K_EXP ? cmp <= 0 : cmp > 0) return JWT_INVALID;
        } else if (key == K_SUB) {
            if (*c.p != '"') {
                bad = 1;
                if (!jskip(&c, 1)) return JWT_INVALID;
            } else {
                if (!jstr(&c, &s, &len, &esc)) return JWT_INVALID;
                uint8_t buf[32];
                if (esc) {
                    len = junescape(buf, sizeof buf, s, len);
                    s = buf;
                }
                if (!sub_value(s, len, &r->uid)) bad = 1;
            }
        } else if (key == K_USERNAME) {
            if (*c.p != '"') {
                bad = 1;
                if (!jskip(&c, 1)) return JWT_INVALID;
            } else {
                if (!jstr(&c, &s, &len, &esc)) return JWT_INVALID;
                if (!esc) {
                    /* raw JSON string content without escapes cannot contain '"', '\' or < 0x20 */
                    if (len > JWT_USERNAME_MAX) bad = 1;
                    else memcpy(r->ubuf, s, len), r->username_len = (uint16_t)len, r->username_escape = 0;
                } else {
                    int m = junescape((uint8_t *)r->ubuf, JWT_USERNAME_MAX, s, len);
                    if (m < 0) {
                        bad = 1;
                    } else {
                        int x = 0;
                        for (int i = 0; i < m; i++) {
                            uint8_t ch = (uint8_t)r->ubuf[i];
                            x |= ch < 0x20 || ch == '"' || ch == '\\';
                        }
                        r->username_len = (uint16_t)m, r->username_escape = (uint8_t)x;
                    }
                }
            }
        } else if (!jskip(&c, 1)) {
            return JWT_INVALID;
        }
        jws(&c);
        if (c.p >= c.e) return JWT_INVALID;
        if (*c.p == ',') {
            c.p++;
            continue;
        }
        if (*c.p++ != '}') return JWT_INVALID;
        break;
    }
    jws(&c);
    if (c.p != c.e) return JWT_INVALID;
    if (!(seen & (1 << K_EXP))) return JWT_INVALID;
    if (bad || !(seen & (1 << K_SUB)) || !(seen & (1 << K_USERNAME))) return JWT_BAD_PAYLOAD;
    r->ubuf[r->username_len] = 0;
    return JWT_OK;
}

/* ======================================================================================
 * 4b. shape-matched fast path (default; -DJWT_NO_SHAPE_JSON turns it off)
 *
 * The common payload is {"sub":"<id>","username":"<name>","iat":<n>,"exp":<n>}, and minting code
 * (JSON.stringify, Python's json.dumps with compact separators, ...) emits exactly that order with
 * no whitespace.  This matcher accepts only that exact byte shape: literal separators,
 * ASCII digits, a username with no '"', '\\', control or non-ASCII bytes, integers without leading
 * zeros.  Anything else, a reordered or extra claim included, returns -1 and the strict parser
 * decides, so results are identical for every input (tests/test_jwt.c fuzzes the two against each other).
 * Needs 16 readable bytes past n (padded decode buffers).
 * ====================================================================================== */

/* leading ASCII digits in p[0..7] (SWAR: borrows/carries only travel towards later bytes) */
CC_INLINE int jdigits8(const uint8_t *p) {
    uint64_t x;
    memcpy(&x, p, 8);
    uint64_t nd = ((x - 0x3030303030303030ull) | (x + 0x4646464646464646ull)) & 0x8080808080808080ull;
    return nd ? __builtin_ctzll(nd) >> 3 : 8;
}
CC_INLINE int jdigits(const uint8_t *p, int max) {
    int n = 0, d;
    do n += d = jdigits8(p + n);
    while (d == 8 && n < max);
    return n;
}
/* offset of the first '"', '\\', control or non-ASCII byte */
CC_INLINE int jstrspan(const uint8_t *p, int max) {
    int i = 0;
#if defined(__SSE2__)
    for (; i < max; i += 16) {
        __m128i v = _mm_loadu_si128((const __m128i *)(p + i));
        __m128i st =
            _mm_or_si128(_mm_or_si128(_mm_cmpeq_epi8(v, _mm_set1_epi8('"')), _mm_cmpeq_epi8(v, _mm_set1_epi8('\\'))),
                         _mm_cmplt_epi8(v, _mm_set1_epi8(0x20))); /* signed: also >= 0x80 */
        int m = _mm_movemask_epi8(st);
        if (m) return i + __builtin_ctz(m);
    }
#elif defined(CC_HAVE_NEON)
    for (; i < max; i += 16) {
        uint8x16_t v = vld1q_u8(p + i);
        uint8x16_t st = vorrq_u8(vorrq_u8(vceqq_u8(v, vdupq_n_u8('"')), vceqq_u8(v, vdupq_n_u8('\\'))),
                                 vcgeq_u8(vsubq_u8(v, vdupq_n_u8(0x20)), vdupq_n_u8(0x60)));
        uint64_t m = vget_lane_u64(vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_u8(st), 4)), 0);
        if (m) return i + (__builtin_ctzll(m) >> 2);
    }
#else
    for (; i < max; i++)
        if (jstop[p[i]]) return i;
#endif
    return max;
}
#define JLIT(p, s) (!memcmp((p), (s), sizeof(s) - 1))

CC_INLINE int payload_shape(const uint8_t *pl, int n, const jnow_t *now, jwt_result_t *r) {
    const uint8_t *p = pl, *e = pl + n;
    if (n < 44 || !JLIT(p, "{\"sub\":\"")) return -1;
    p += 8;
    const uint8_t *sub = p;
    int subl = jdigits(p, 24);
    p += subl;
    if (subl == 0 || subl > 20 || e - p < 14 || !JLIT(p, "\",\"username\":\"")) return -1;
    p += 14;
    const uint8_t *user = p;
    int ul = jstrspan(p, (int)(e - p));
    p += ul;
    if (p >= e || *p != '"' || ul > JWT_USERNAME_MAX || e - p < 9 || !JLIT(p, "\",\"iat\":")) return -1;
    p += 8;
    int il = jdigits(p, 24);
    if (il == 0 || il > 18 || (*p == '0' && il > 1)) return -1;
    p += il;
    if (e - p < 8 || !JLIT(p, ",\"exp\":")) return -1;
    p += 7;
    const uint8_t *exp = p;
    int el = jdigits(p, 24);
    if (el == 0 || el > 18 || (*p == '0' && el > 1) || p + el + 1 != e || p[el] != '}') return -1;
    if (jnum_cmp(exp, el, 1, now) <= 0) return JWT_INVALID;
    if (!sub_value(sub, subl, &r->uid)) return JWT_BAD_PAYLOAD;
    memcpy(r->ubuf, user, ul);
    r->ubuf[ul] = 0, r->username_len = (uint16_t)ul, r->username_escape = 0;
    return JWT_OK;
}

/* ======================================================================================
 * 5. batch front end
 * ====================================================================================== */

static const char canon_hdr[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"; /* {"alg":"HS256","typ":"JWT"} */

/* Payload of a token whose signature checked out: base64url-decode, JSON, claims -> r->status.  Inlined for the
 * same reason as header_ok. */
CC_INLINE void claims_one(jwt_result_t *r, const uint8_t *p64, int n64, const jnow_t *jn) {
    uint8_t pb[JWT_TOKEN_MAX * 3 / 4 + 64];
    int pn = jwt_b64url_decode(pb, (const char *)p64, n64);
    if (pn < 0) return;
#if !defined(JWT_NO_SHAPE_JSON) /* default: JSON 131 -> 37 ns/token on a Xeon Platinum 8260 */
    int st = payload_shape(pb, pn, jn, r);
#else
    int st = -1;
#endif
    if (st < 0) st = payload_check(pb, pn, jn, r);
    r->status = (uint8_t)st;
    if (r->status != JWT_OK) r->uid = 0, r->username_len = 0, r->ubuf[0] = 0;
}

static void verify_impl(const jwt_key_t *k, int n, const char *const *tok, const int *len, int64_t now,
                        jwt_result_t *out, jwt_hmac_fn *hmac) {
    enum { CH = 64 };
    const uint8_t *msg[CH];
    int mlen[CH], idx[CH], poff[CH];
    uint32_t want[CH][8], mac[CH][8];
    jnow_t jn;
    jnow_init(&jn, now);
    for (int base = 0; base < n; base += CH) {
        int m = n - base < CH ? n - base : CH, c = 0;
        for (int i = 0; i < m; i++) {
            jwt_result_t *r = &out[base + i];
            const char *t = tok[base + i];
            int L = len[base + i];
            r->status = JWT_INVALID, r->username_escape = 0, r->username_len = 0, r->uid = 0;
            r->username = r->ubuf, r->ubuf[0] = 0;
            if (L <= 0 || L > JWT_TOKEN_MAX) continue;
            const char *d1 = memchr(t, '.', L);
            if (!d1) continue;
            const char *d2 = memchr(d1 + 1, '.', L - (d1 + 1 - t));
            if (!d2 || t + L - (d2 + 1) != 43) continue; /* 32-byte MAC = 43 base64url chars */
            int hl = (int)(d1 - t), pl = (int)(d2 - d1 - 1);
            if (hl == 0 || pl == 0) continue;
            if (!(hl == 36 && !memcmp(t, canon_hdr, 36))) {
                uint8_t hb[JWT_TOKEN_MAX * 3 / 4 + 64];
                int hn = jwt_b64url_decode(hb, t, hl);
                if (hn < 0 || !header_ok(hb, hn, "HS256")) continue;
            }
            uint8_t sb[64];
            if (jwt_b64url_decode(sb, d2 + 1, 43) != 32) continue;
            for (int j = 0; j < 8; j++) want[c][j] = be32(sb + 4 * j);
            msg[c] = (const uint8_t *)t, mlen[c] = (int)(d2 - t), idx[c] = i, poff[c] = hl + 1;
            c++;
        }
        hmac(k, c, msg, mlen, mac);
        int good[CH], ng = 0;
        for (int j = 0; j < c; j++) {
            /* constant time over the 32 bytes: no early exit, only the verdict branches */
            if (!cc_mac_diff8(mac[j], want[j])) good[ng++] = j;
        }
        for (int g = 0; g < ng; g++) {
            int j = good[g];
            claims_one(&out[base + idx[j]], msg[j] + poff[j], mlen[j] - poff[j], &jn);
        }
    }
}

void jwt_verify_batch_scalar(const jwt_key_t *k, int n, const char *const *tok, const int *len, int64_t now,
                             jwt_result_t *out) {
    verify_impl(k, n, tok, len, now, out, cc_hmac_sha256_scalar);
}
#ifdef CC_HAVE_NEON
void jwt_verify_batch_neon(const jwt_key_t *k, int n, const char *const *tok, const int *len, int64_t now,
                           jwt_result_t *out) {
    verify_impl(k, n, tok, len, now, out, cc_hmac_sha256_neon);
}
#endif
#if defined(CC_ARM_SHA2)
void jwt_verify_batch_sha2(const jwt_key_t *k, int n, const char *const *tok, const int *len, int64_t now,
                           jwt_result_t *out) {
    verify_impl(k, n, tok, len, now, out, cc_hmac_sha256_sha2);
}
#endif
#if defined(CC_X86)
void jwt_verify_batch_avx2(const jwt_key_t *k, int n, const char *const *tok, const int *len, int64_t now,
                           jwt_result_t *out) {
    verify_impl(k, n, tok, len, now, out, cc_hmac_sha256_avx2);
}
void jwt_verify_batch_avx512(const jwt_key_t *k, int n, const char *const *tok, const int *len, int64_t now,
                             jwt_result_t *out) {
    verify_impl(k, n, tok, len, now, out, cc_hmac_sha256_avx512);
}
#endif

/* at load time: pick the base64url decoder once, before any call */
__attribute__((constructor)) static void jwt_b64_resolve(void) {
#if defined(CC_X86)
    CC_STORE_FN(b64url_impl, b64u_pick_vbmi()         ? b64url_decode_vbmi
                             : cc_cpu() & CC_CPU_AVX2 ? b64url_decode_avx2
                                                      : jwt_b64url_decode_scalar);
    CC_STORE_FN(b64url_enc_impl, cc_cpu() & CC_CPU_AVX2 ? b64url_encode_avx2 : jwt_b64url_encode_scalar);
#endif
}

void jwt_verify_batch(const jwt_key_t *k, int n, const char *const *tok, const int *len, int64_t now,
                      jwt_result_t *out) {
    verify_impl(k, n, tok, len, now, out, CC_LOAD_FN(cc__hmac_impl));
}

#ifndef CC_NO_PK /* RS256 / ES256 / EdDSA; -DJWT_NO_PK (or -DCC_NO_PK) leaves them out */
/* a JWS public key: cursed-crypto's key plus what the token format needs (the "alg" name, the canonical header, the
 * signature's length in bytes and in base64url characters) */
struct jwt_pkey {
    cc_pkey_t *cc;
    const char *name, *canon;
    int sig_bytes, sig_chars;
};
static jwt_pkey_t *jwt_pkey_wrap(cc_pkey_t *c) {
    if (!c) return NULL;
    jwt_pkey_t *k = calloc(1, sizeof *k);
    if (!k) {
        cc_pkey_free(c);
        return NULL;
    }
    k->cc = c;
    switch (cc_pkey_alg(c)) {
        case CC_PK_ES256: k->name = "ES256", k->canon = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9"; break;
        case CC_PK_ED25519: k->name = "EdDSA", k->canon = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9"; break;
        default: k->name = "RS256", k->canon = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"; break;
    } /* the canonical headers are {"alg":"<name>","typ":"JWT"} */
    k->sig_bytes = cc_pkey_sig_bytes(c), k->sig_chars = (k->sig_bytes * 4 + 2) / 3;
    return k;
}
jwt_pkey_t *jwt_pkey_es256(const uint8_t x[32], const uint8_t y[32]) { return jwt_pkey_wrap(cc_pkey_es256(x, y)); }
jwt_pkey_t *jwt_pkey_rs256(const uint8_t *n, size_t nlen, const uint8_t *e, size_t elen) {
    return jwt_pkey_wrap(cc_pkey_rs256(n, nlen, e, elen));
}
jwt_pkey_t *jwt_pkey_ed25519(const uint8_t pub[32]) { return jwt_pkey_wrap(cc_pkey_ed25519(pub)); }
void jwt_pkey_free(jwt_pkey_t *k) {
    if (!k) return;
    cc_pkey_free(k->cc);
    free(k);
}
void jwt_pk_verify_raw(const jwt_pkey_t *k, int n, const uint8_t *const *msg, const int *len, const uint8_t *const *sig,
                       const int *slen, uint8_t *ok) {
    cc_verify_batch(k->cc, n, msg, len, sig, slen, ok);
}

void jwt_verify_batch_pk(const jwt_pkey_t *k, int n, const char *const *tok, const int *len, int64_t now,
                         jwt_result_t *out) {
    enum { CH = 16 };
    const uint8_t *msg[CH], *sp[CH];
    int mlen[CH], idx[CH], poff[CH], sl[CH];
    uint8_t sb[CH][512 + 64], ok[CH];
    jnow_t jn;
    jnow_init(&jn, now);
    for (int base = 0; base < n; base += CH) {
        int m = n - base < CH ? n - base : CH, c = 0;
        for (int i = 0; i < m; i++) {
            jwt_result_t *r = &out[base + i];
            const char *t = tok[base + i];
            int L = len[base + i];
            r->status = JWT_INVALID, r->username_escape = 0, r->username_len = 0, r->uid = 0;
            r->username = r->ubuf, r->ubuf[0] = 0;
            if (L <= 0 || L > JWT_TOKEN_MAX) continue;
            const char *d1 = memchr(t, '.', L);
            if (!d1) continue;
            const char *d2 = memchr(d1 + 1, '.', L - (d1 + 1 - t));
            if (!d2 || t + L - (d2 + 1) != k->sig_chars) continue;
            int hl = (int)(d1 - t), pl = (int)(d2 - d1 - 1);
            if (hl == 0 || pl == 0) continue;
            if (!(hl == 36 && !memcmp(t, k->canon, 36))) {
                uint8_t hb[JWT_TOKEN_MAX * 3 / 4 + 64];
                int hn = jwt_b64url_decode(hb, t, hl);
                if (hn < 0 || !header_ok(hb, hn, k->name)) continue;
            }
            if (jwt_b64url_decode(sb[c], d2 + 1, k->sig_chars) != k->sig_bytes) continue;
            sp[c] = sb[c], sl[c] = k->sig_bytes;
            msg[c] = (const uint8_t *)t, mlen[c] = (int)(d2 - t), idx[c] = i, poff[c] = hl + 1;
            c++;
        }
        cc_verify_batch(k->cc, c, msg, mlen, sp, sl, ok);
        for (int j = 0; j < c; j++)
            if (ok[j]) claims_one(&out[base + idx[j]], msg[j] + poff[j], mlen[j] - poff[j], &jn);
    }
}
#endif

/* ======================================================================================
 * 6. signing: HS256 through the multi-buffer HMAC engines, EdDSA through cursed-crypto's constant-time signer
 * ====================================================================================== */

/* A payload this library's verifier would accept, short of the claim profile and the clock (jwt.h, jwt_sign_batch):
 * one JSON object, strict grammar, "exp" present, "exp" / "nbf" numbers, no repeated sub / username / exp / nbf. */
static int payload_sign_ok(const uint8_t *pl, int n) {
    jcur_t c = { pl, pl + n };
    const uint8_t *s;
    int len, esc, seen = 0, isint;
    jws(&c);
    if (c.p >= c.e || *c.p++ != '{') return 0;
    jws(&c);
    if (c.p < c.e && *c.p == '}') return 0; /* no exp */
    for (;;) {
        jws(&c);
        if (!jstr(&c, &s, &len, &esc)) return 0;
        int key = jkey(s, len, esc);
        jws(&c);
        if (c.p >= c.e || *c.p++ != ':') return 0;
        jws(&c);
        if (key != K_OTHER && key != K_ALG) {
            if (seen & (1 << key)) return 0;
            seen |= 1 << key;
        }
        if (c.p >= c.e) return 0;
        if (key == K_EXP || key == K_NBF) {
            if (*c.p != '-' && (*c.p < '0' || *c.p > '9')) return 0;
            if (!jnum(&c, &s, &len, &isint)) return 0;
        } else if (!jskip(&c, 1)) {
            return 0;
        }
        jws(&c);
        if (c.p >= c.e) return 0;
        if (*c.p == ',') {
            c.p++;
            continue;
        }
        if (*c.p++ != '}') return 0;
        break;
    }
    jws(&c);
    return c.p == c.e && (seen & (1 << K_EXP));
}

/* header (36 chars) '.' payload '.' signature */
static int sign_token_len(int payload_len, int sig_bytes) {
    if (payload_len < 0 || payload_len > JWT_TOKEN_MAX) return -1;
    int t = 36 + 1 + (payload_len * 4 + 2) / 3 + 1 + (sig_bytes * 4 + 2) / 3;
    return t > JWT_TOKEN_MAX ? -1 : t;
}
int jwt_sign_size(int payload_len) {
    int t = sign_token_len(payload_len, 32);
    return t < 0 ? -1 : t + 1 + JWT_SIGN_SLACK;
}

/* checks payload i and writes "<header>.<payload>" into out[i]; returns the signing input's length, or -1 (and
 * out[i] is not touched: it may be NULL for a payload whose jwt_sign_size is -1) */
static int sign_input(const char *canon, const char *pl, int pn, int sig_bytes, char *out) {
    if (sign_token_len(pn, sig_bytes) < 0 || !payload_sign_ok((const uint8_t *)pl, pn)) return -1;
    memcpy(out, canon, 36);
    out[36] = '.';
    return 37 + jwt_b64url_encode(out + 37, (const uint8_t *)pl, pn);
}

static int sign_impl(const jwt_key_t *k, int n, const char *const *payload, const int *payload_len, char *const *out,
                     int *out_len, jwt_hmac_fn *hmac) {
    enum { CH = 64 };
    const uint8_t *msg[CH];
    int mlen[CH], idx[CH], issued = 0;
    uint32_t mac[CH][8];
    for (int base = 0; base < n; base += CH) {
        int m = n - base < CH ? n - base : CH, c = 0;
        for (int i = 0; i < m; i++) {
            int t = base + i, L = sign_input(canon_hdr, payload[t], payload_len[t], 32, out[t]);
            out_len[t] = -1;
            if (L < 0) continue;
            msg[c] = (const uint8_t *)out[t], mlen[c] = L, idx[c++] = t;
        }
        hmac(k, c, msg, mlen, mac);
        for (int j = 0; j < c; j++) {
            uint8_t tag[32];
            for (int w = 0; w < 8; w++) {
                uint32_t v = mac[j][w];
                tag[4 * w] = (uint8_t)(v >> 24), tag[4 * w + 1] = (uint8_t)(v >> 16);
                tag[4 * w + 2] = (uint8_t)(v >> 8), tag[4 * w + 3] = (uint8_t)v;
            }
            char *o = out[idx[j]] + mlen[j];
            *o++ = '.';
            o += jwt_b64url_encode(o, tag, 32);
            *o = 0;
            out_len[idx[j]] = (int)(o - out[idx[j]]);
            issued++;
        }
    }
    return issued;
}
int jwt_sign_batch(const jwt_key_t *k, int n, const char *const *payload, const int *payload_len, char *const *out,
                   int *out_len) {
    return sign_impl(k, n, payload, payload_len, out, out_len, CC_LOAD_FN(cc__hmac_impl));
}

#ifndef CC_NO_PK
struct jwt_skey {
    cc_skey_t *cc;
    const char *canon;
    int sig_bytes;
};
jwt_skey_t *jwt_skey_ed25519(const uint8_t seed[32]) {
    jwt_skey_t *k = calloc(1, sizeof *k);
    if (!k) return NULL;
    if (!(k->cc = cc_skey_ed25519(seed))) {
        free(k);
        return NULL;
    }
    k->canon = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9", k->sig_bytes = 64; /* {"alg":"EdDSA","typ":"JWT"} */
    return k;
}
jwt_skey_t *jwt_skey_es256(const uint8_t d[32]) {
    jwt_skey_t *k = calloc(1, sizeof *k);
    if (!k) return NULL;
    if (!(k->cc = cc_skey_es256(d))) {
        free(k);
        return NULL;
    }
    k->canon = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9", k->sig_bytes = 64; /* {"alg":"ES256","typ":"JWT"} */
    return k;
}
void jwt_skey_public(const jwt_skey_t *k, uint8_t pub[32]) { cc_skey_public(k->cc, pub); }
void jwt_skey_es256_public(const jwt_skey_t *k, uint8_t x[32], uint8_t y[32]) { cc_skey_es256_public(k->cc, x, y); }
jwt_skey_t *jwt_skey_rs256(const uint8_t *key, size_t len) {
    cc_skey_t *c = cc_skey_rs256(key, len);
    if (!c) return NULL;
    jwt_skey_t *k = calloc(1, sizeof *k);
    if (!k) {
        cc_skey_free(c);
        return NULL;
    }
    k->cc = c, k->canon = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9", k->sig_bytes = cc_skey_sig_bytes(c); /* RS256 */
    return k;
}
int jwt_skey_rs256_public(const jwt_skey_t *k, uint8_t *n, size_t ncap, uint8_t *e, size_t ecap, size_t *elen) {
    return cc_skey_rs256_public(k->cc, n, ncap, e, ecap, elen);
}
int jwt_skey_verify_after_sign(jwt_skey_t *k, int on) { return cc_skey_verify_after_sign(k->cc, on); }
void jwt_skey_free(jwt_skey_t *k) {
    if (!k) return;
    cc_skey_free(k->cc);
    free(k);
}
int jwt_sign_size_pk(const jwt_skey_t *k, int payload_len) {
    int t = sign_token_len(payload_len, k->sig_bytes);
    return t < 0 ? -1 : t + 1;
}
int jwt_sign_batch_pk(const jwt_skey_t *k, int n, const char *const *payload, const int *payload_len, char *const *out,
                      int *out_len) {
    enum { CH = 16 };
    const uint8_t *msg[CH];
    uint8_t sb[CH][512], *sp[CH]; /* up to RSA-4096 */
    int mlen[CH], idx[CH], issued = 0;
    for (int base = 0; base < n; base += CH) {
        int m = n - base < CH ? n - base : CH, c = 0;
        for (int i = 0; i < m; i++) {
            int t = base + i, L = sign_input(k->canon, payload[t], payload_len[t], k->sig_bytes, out[t]);
            out_len[t] = -1;
            if (L < 0) continue;
            msg[c] = (const uint8_t *)out[t], mlen[c] = L, sp[c] = sb[c], idx[c++] = t;
        }
        int faults = c ? cc_sign_batch(k->cc, c, msg, mlen, sp) : 0;
        for (int j = 0; j < c; j++) {
            if (faults) { /* verify-after-sign zeroed this signature: no token */
                uint8_t z = 0;
                for (int b = 0; b < k->sig_bytes; b++) z |= sb[j][b];
                if (!z) {
                    out[idx[j]][0] = 0;
                    continue;
                }
            }
            char *o = out[idx[j]] + mlen[j];
            *o++ = '.';
            o += jwt_b64url_encode(o, sb[j], k->sig_bytes);
            *o = 0;
            out_len[idx[j]] = (int)(o - out[idx[j]]);
            issued++;
        }
    }
    return issued;
}
#endif
