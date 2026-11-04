/* jwt.c — see jwt.h.  Part of cursed-jwt, MIT licence (see LICENSE).  Sections:
 *   1. SHA-256 constants, HMAC message plans, key setup
 *   2. SHA-256 engines: scalar / NEON 4-lane / AVX2 8-lane / AVX-512VL 8-lane (all from jwt_mb.inc),
 *      ARMv8 SHA2 instructions with 1/2/4 interleaved streams
 *   3. base64url decode: scalar / NEON (vld4 de-interleave + vqtbl4) / AVX2
 *   4. strict JSON for the header and payload; 4b. the shape-matched fast path for the payload
 *   5. the batch front end
 */
#include "jwt.h"

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

/* ---- run-time CPU dispatch ----
 * The library is compiled for the baseline ISA (x86-64, ARMv8-A) and carries every engine the architecture can
 * have: the AVX2 and AVX-512VL engines are compiled inside target regions on x86-64, the SHA2 engine inside one on
 * AArch64.  jwt_cpu (filled by a constructor from CPUID + XGETBV, or HWCAP / sysctl) picks the best one the
 * machine has at every entry point, falling back down to scalar.  Building with -march=native still works: the
 * regions are then no-ops, and dispatch still checks the CPU. */
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

#define JWT_CPU_DETECTED (1u << 31) /* the JWT_CPU_* bits are in jwt.h */
static unsigned jwt_cpu_bits;
#if defined(JWT_X86)
#include <cpuid.h>
#endif
__attribute__((constructor)) static void jwt_cpu_init(void) {
    unsigned f = JWT_CPU_DETECTED;
#if defined(JWT_X86)
    unsigned a = 0, b = 0, c = 0, d = 0, ecx1 = 0, ebx7 = 0;
    if (__get_cpuid(1, &a, &b, &c, &d)) ecx1 = c;
    if (__get_cpuid_count(7, 0, &a, &b, &c, &d)) ebx7 = b;
    unsigned xcr0 = 0;
    if (ecx1 & (1u << 27)) { /* OSXSAVE: the OS manages the vector state that XCR0 lists */
        unsigned hi;
        __asm__("xgetbv" : "=a"(xcr0), "=d"(hi) : "c"(0));
    }
    int ymm = (xcr0 & 6) == 6, zmm = ymm && (xcr0 & 0xE0) == 0xE0;
    if (ymm && (ebx7 & (1u << 5)) && (ebx7 & (1u << 3)) && (ebx7 & (1u << 8))) f |= JWT_CPU_AVX2; /* + BMI1, BMI2 */
    if ((f & JWT_CPU_AVX2) && zmm && (ebx7 & (1u << 16)) && (ebx7 & (1u << 31)) && (ebx7 & (1u << 30)) &&
        (ebx7 & (1u << 17)) && (ebx7 & (1u << 28)))
        f |= JWT_CPU_AVX512VL; /* F, VL, BW, DQ, CD */
    if ((f & JWT_CPU_AVX512VL) && (ebx7 & (1u << 21))) f |= JWT_CPU_IFMA;
    if ((ebx7 & (1u << 8)) && (ebx7 & (1u << 19))) f |= JWT_CPU_BMI2_ADX;
    if (ebx7 & (1u << 29)) f |= JWT_CPU_SHANI;
    unsigned vb = 0, vc = 0, vd = 0, fam;
    __get_cpuid(0, &a, &vb, &vc, &vd);
    int amd = vb == 0x68747541 && vd == 0x69746e65 && vc == 0x444d4163; /* "AuthenticAMD" */
    __get_cpuid(1, &a, &b, &c, &d);
    fam = ((a >> 8) & 0xF) == 0xF ? ((a >> 8) & 0xF) + ((a >> 20) & 0xFF) : (a >> 8) & 0xF;
    /* AMD's AVX-512 parts (Zen 4 = family 19h, Zen 5 = 1Ah) run 512-bit integer work without the frequency-licence
     * drop Intel's do, so there the 16-lane zmm engine beats the 8-lane ymm one.  Intel always keeps the ymm engine. */
    if ((f & JWT_CPU_AVX512VL) && amd && fam >= 0x19) f |= JWT_CPU_FAST_ZMM;
    /* 4 interleaved SHA-NI streams beat every vector engine at every batch size on Zen 2, 3 and 4 (measured), and are
     * expected to on the other SHA-NI CPUs too: Zen 1 and Intel (Ice Lake and later, the Atom cores).  The exception is
     * Zen 5 (family 1Ah), whose full-width 512-bit units may let the 16-lane zmm engine win big batches: there
     * jwt_hmac_shani_zmm splits the work. */
    if ((f & JWT_CPU_SHANI) && !(amd && fam >= 0x1A && (f & JWT_CPU_AVX512VL))) f |= JWT_CPU_FAST_SHANI;
    /* tests: JWT_CPU_FORCE_ZMM=1 claims FAST_ZMM on any AVX-512 CPU, to exercise that dispatch on Intel hardware */
    if ((f & JWT_CPU_AVX512VL) && getenv("JWT_CPU_FORCE_ZMM") && *getenv("JWT_CPU_FORCE_ZMM") == '1')
        f |= JWT_CPU_FAST_ZMM;
#elif defined(JWT_ARM_SHA2)
#if defined(__APPLE__)
    int v = 0;
    size_t vl = sizeof v;
    if (!sysctlbyname("hw.optional.arm.FEAT_SHA256", &v, &vl, NULL, 0) && v) f |= JWT_CPU_SHA2;
    v = 0, vl = sizeof v;
    if (!sysctlbyname("hw.optional.arm.FEAT_SHA512", &v, &vl, NULL, 0) && v) f |= JWT_CPU_SHA512;
#elif defined(__linux__)
    unsigned long hw = getauxval(AT_HWCAP);
    if (hw & (1ul << 6)) f |= JWT_CPU_SHA2;    /* HWCAP_SHA2 */
    if (hw & (1ul << 21)) f |= JWT_CPU_SHA512; /* HWCAP_SHA512 */
#elif defined(__ARM_FEATURE_SHA2)
    f |= JWT_CPU_SHA2;
#endif
#endif
    const char *mask = getenv("JWT_CPU_MASK"); /* tests and benchmarks: pretend features are missing */
    if (mask && *mask) f &= (unsigned)strtoul(mask, NULL, 0) | JWT_CPU_DETECTED;
    __atomic_store_n(&jwt_cpu_bits, f, __ATOMIC_RELAXED); /* every racing writer stores the same value */
}
static unsigned jwt_cpu(void) {
    unsigned f = __atomic_load_n(&jwt_cpu_bits, __ATOMIC_RELAXED);
    if (!f) jwt_cpu_init(), f = __atomic_load_n(&jwt_cpu_bits, __ATOMIC_RELAXED); /* called before constructors ran */
    return f;
}

/* Resolve-once dispatch: each entry point calls through a pointer that starts at a resolver stub.  The constructor
 * at the end of this file (or the first call, if it comes earlier) replaces it with the chosen engine, so a call
 * is one indirect call with no feature tests.  Relaxed atomics: racing resolvers all store the same pointer. */
#define JWT_LOAD_FN(p)     __atomic_load_n(&(p), __ATOMIC_RELAXED)
#define JWT_STORE_FN(p, f) __atomic_store_n(&(p), (f), __ATOMIC_RELAXED)
unsigned jwt_cpu_features(void) { return jwt_cpu() & ~JWT_CPU_DETECTED; }

/* ======================================================================================
 * 1. constants, plans, key
 * ====================================================================================== */

static const uint32_t K256[64] = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
                                   0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
                                   0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
                                   0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                                   0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
                                   0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
                                   0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
                                   0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                                   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
                                   0xc67178f2 };
static const uint32_t IV256[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
static const uint8_t zero_block[64] __attribute__((aligned(64))) = { 0 };

JWT_INLINE uint32_t be32(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return __builtin_bswap32(v);
}

/* The inner hash continues from the ipad midstate over msg (L bytes), so its total length is
 * 64 + L and it needs nb = ceil((L + 9) / 64) more blocks: nf of them straight out of msg, the
 * rest (1 or 2) from `tail`, which holds the leftover bytes, 0x80, zeros and the bit length. */
typedef struct {
    const uint8_t *m;
    int nf, nb;
    uint8_t tail[128];
} hplan_t;

/* off = bytes already hashed before m: 64 (the ipad block) for HMAC, 0 for a plain SHA-256 */
JWT_INLINE void hplan_init_off(hplan_t *p, const uint8_t *m, int L, int off) {
    int nf = L >> 6, rem = L & 63, nt = rem + 9 > 64 ? 2 : 1;
    uint64_t bits = (uint64_t)(off + L) * 8;
    p->m = m, p->nf = nf, p->nb = nf + nt;
#ifdef JWT_INPUT_PADDED
    /* Caller guarantees >= 64 readable bytes after each token (padded recv buffers): fixed-size
     * copy + mask instead of variable-length memcpy/memset. */
    static const uint8_t keep[128] = { [0 ... 63] = 0xFF };
    const uint8_t *src = m + (nf << 6);
    for (int i = 0; i < 64; i++) p->tail[i] = src[i] & keep[64 - rem + i];
    memset(p->tail + 64, 0, 64);
    p->tail[rem] = 0x80;
    bits = __builtin_bswap64(bits);
    memcpy(p->tail + nt * 64 - 8, &bits, 8);
#else
    memcpy(p->tail, m + (nf << 6), rem);
    p->tail[rem] = 0x80;
    memset(p->tail + rem + 1, 0, nt * 64 - rem - 1 - 8);
    for (int i = 0; i < 8; i++) p->tail[nt * 64 - 1 - i] = (uint8_t)(bits >> (8 * i));
#endif
}

static void hplan_init(hplan_t *p, const uint8_t *m, int L) { hplan_init_off(p, m, L, 64); }

JWT_INLINE const uint8_t *hplan_block(const hplan_t *p, int b) {
    return b < p->nf ? p->m + (b << 6) : p->tail + ((b - p->nf) << 6);
}

static void hmac1_scalar(const jwt_key_t *k, const hplan_t *p, uint32_t mac[8]);
static void sha1_raw(const hplan_t *p, uint32_t dig[8]);
/* plain SHA-256 runs the HMAC machinery from the IV, with no ipad block and no outer hash (raw mode) */
static const jwt_key_t sha_iv_key = {
    { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }, { 0 }
};

/* ======================================================================================
 * 2. SHA-256 engines
 * ====================================================================================== */

/* vpternlogd truth tables (index = a<<2 | b<<1 | c), used by the AVX-512 engine and test.c */
#define JWT_TL_XOR3 0x96 /* a ^ b ^ c */
#define JWT_TL_CH   0xCA /* a ? b : c */
#define JWT_TL_MAJ  0xE8 /* majority */

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

/* ---- scalar (the template with one lane) ---- */
#define MB(name)       name##_scalar
#define MB_LANES       1
#define V              uint32_t
#define VSET1(x)       ((uint32_t)(x))
#define VADD(a, b)     ((a) + (b))
#define VXOR(a, b)     ((a) ^ (b))
#define VSHR(x, n)     ((x) >> (n))
#define VROR(x, n)     ROR32(x, n)
#define VXOR3(a, b, c) ((a) ^ (b) ^ (c))
#define VCH(e, f, g)   ((g) ^ ((e) & ((f) ^ (g))))
#define VMAJ(a, b, c)  ((b) ^ (((a) ^ (b)) & ((b) ^ (c))))
#define VSEL(m, x, y)  (((m) & (x)) | (~(m) & (y)))
#define VMASK(arr)     ((arr)[0])
#define MB_LOAD16(ptr, w)                                                                                              \
    do {                                                                                                               \
        for (int i_ = 0; i_ < 16; i_++) (w)[i_] = be32((ptr)[0] + 4 * i_);                                             \
    } while (0)
#define MB_STORE8(s, out)                                                                                              \
    do {                                                                                                               \
        for (int i_ = 0; i_ < 8; i_++) (out)[0][i_] = (s)[i_];                                                         \
    } while (0)
#define MB_MIN_LANES 1
#include "jwt_mb.inc"
#undef MB
#undef MB_LANES
#undef V
#undef VSET1
#undef VADD
#undef VXOR
#undef VSHR
#undef VROR
#undef VXOR3
#undef VCH
#undef VMAJ
#undef VSEL
#undef VMASK
#undef MB_LOAD16
#undef MB_STORE8
#undef MB_MIN_LANES

#if defined(JWT_OSSL_SHA256) && defined(__x86_64__) && defined(__ELF__)
/* ---- single-stream x86-64: OpenSSL's sha256_block_data_order, extracted (src/sha256_x86_64_ossl.S) ----
 * Batch 1 and the lanes a vector group leaves over run one message at a time, where OpenSSL's hand-scheduled
 * AVX2+BMI2 code (2 blocks interleaved, rorx) beats the compiled scalar template: 763 vs 1,015 ns per HMAC on a
 * Xeon Platinum 8260.  It dispatches on jwt_ossl_ia32cap_P, laid out like OpenSSL's OPENSSL_ia32cap_P for the bits
 * that code reads: word 0 bit 30 "Intel CPU", word 1 = CPUID.1:ECX (SSSE3, AVX), word 2 = CPUID.7.0:EBX (BMI1,
 * AVX2, BMI2, SHA).  AVX and AVX2 are cleared unless the OS saves ymm state (XCR0). */
#include <cpuid.h>
void jwt_ossl_sha256_block(uint32_t h[8], const void *blocks, size_t n);
__attribute__((visibility("hidden"))) unsigned int jwt_ossl_ia32cap_P[4];
__attribute__((constructor)) static void jwt_ossl_cap_init(void) {
    unsigned a, b, c, d, w0 = 0, w1 = 0, w2 = 0;
    if (__get_cpuid(0, &a, &b, &c, &d) && b == 0x756e6547 && d == 0x49656e69 && c == 0x6c65746e) w0 |= 1u << 30;
    if (__get_cpuid(1, &a, &b, &c, &d)) w1 = c;
    if (__get_cpuid_count(7, 0, &a, &b, &c, &d)) w2 = b;
    int ymm = 0;
    if (w1 & (1u << 27)) { /* OSXSAVE: XCR0 bits 1 (SSE) and 2 (AVX) */
        unsigned lo, hi;
        __asm__("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
        ymm = (lo & 6) == 6;
    }
    if (!ymm) w1 &= ~(1u << 28), w2 &= ~(1u << 5);
    jwt_ossl_ia32cap_P[0] = w0, jwt_ossl_ia32cap_P[1] = w1, jwt_ossl_ia32cap_P[2] = w2;
}
static void hmac1_scalar(const jwt_key_t *k, const hplan_t *p, uint32_t mac[8]) {
    uint32_t st[8];
    uint8_t ob[64] = { 0 };
    memcpy(st, k->ih, 32);
    if (p->nf) jwt_ossl_sha256_block(st, p->m, (size_t)p->nf);
    jwt_ossl_sha256_block(st, p->tail, (size_t)(p->nb - p->nf));
    for (int i = 0; i < 8; i++)
        ob[4 * i] = st[i] >> 24, ob[4 * i + 1] = st[i] >> 16, ob[4 * i + 2] = st[i] >> 8, ob[4 * i + 3] = st[i];
    ob[32] = 0x80, ob[62] = ((64 + 32) * 8) >> 8, ob[63] = (uint8_t)((64 + 32) * 8);
    memcpy(mac, k->oh, 32);
    jwt_ossl_sha256_block(mac, ob, 1);
}
static void sha1_raw(const hplan_t *p, uint32_t dig[8]) {
    memcpy(dig, sha_iv_key.ih, 32);
    if (p->nf) jwt_ossl_sha256_block(dig, p->m, (size_t)p->nf);
    jwt_ossl_sha256_block(dig, p->tail, (size_t)(p->nb - p->nf));
}
/* every message one at a time through the extracted block function (tests, benchmarks) */
void jwt_hmac_ossl(const jwt_key_t *k, int n, const uint8_t *const *msg, const int *len, uint32_t (*mac)[8]) {
    for (int i = 0; i < n; i++) {
        hplan_t p;
        hplan_init(&p, msg[i], len[i]);
        hmac1_scalar(k, &p, mac[i]);
    }
}
#else
static void hmac1_scalar(const jwt_key_t *k, const hplan_t *p, uint32_t mac[8]) {
    const hplan_t *pp = p;
    lanes_scalar(k, 1, &pp, (uint32_t(*)[8])mac);
}
static void sha1_raw(const hplan_t *p, uint32_t dig[8]) {
    const hplan_t *pp = p;
    lanes_raw_scalar(1, &pp, (uint32_t(*)[8])dig);
}
#endif

void jwt_key_init(jwt_key_t *k, const void *secret, size_t len) {
    uint8_t key[64] = { 0 }, blk[64];
    uint32_t w[16], st[8];
    if (len > 64) { /* key = SHA-256(secret) */
        const uint8_t *s = secret;
        size_t off = 0;
        memcpy(st, IV256, 32);
        for (; off + 64 <= len; off += 64) {
            for (int i = 0; i < 16; i++) w[i] = be32(s + off + 4 * i);
            compress_scalar(st, w);
        }
        uint8_t last[128] = { 0 };
        size_t rem = len - off, nt = rem + 9 > 64 ? 2 : 1;
        memcpy(last, s + off, rem);
        last[rem] = 0x80;
        for (int i = 0; i < 8; i++) last[nt * 64 - 1 - i] = (uint8_t)(((uint64_t)len * 8) >> (8 * i));
        for (size_t b = 0; b < nt; b++) {
            for (int i = 0; i < 16; i++) w[i] = be32(last + 64 * b + 4 * i);
            compress_scalar(st, w);
        }
        for (int i = 0; i < 8; i++) {
            key[4 * i] = st[i] >> 24, key[4 * i + 1] = st[i] >> 16;
            key[4 * i + 2] = st[i] >> 8, key[4 * i + 3] = st[i];
        }
    } else if (len) {
        memcpy(key, secret, len);
    }
    for (int pass = 0; pass < 2; pass++) {
        uint8_t pad = pass ? 0x5c : 0x36;
        for (int i = 0; i < 64; i++) blk[i] = key[i] ^ pad;
        for (int i = 0; i < 16; i++) w[i] = be32(blk + 4 * i);
        memcpy(st, IV256, 32);
        compress_scalar(st, w);
        memcpy(pass ? k->oh : k->ih, st, 32);
    }
}

/* ---- NEON, 4 lanes ---- */
#ifdef JWT_HAVE_NEON
#define MB(name)   name##_neon
#define MB_LANES   4
#define V          uint32x4_t
#define VSET1(x)   vdupq_n_u32(x)
#define VADD(a, b) vaddq_u32(a, b)
#define VXOR(a, b) veorq_u32(a, b)
#define VSHR(x, n) vshrq_n_u32(x, n)
#define VROR(x, n) vsliq_n_u32(vshrq_n_u32(x, n), x, 32 - (n)) /* shift right, then shift-left-insert */
#if defined(__ARM_FEATURE_SHA3)
#define VXOR3(a, b, c) veor3q_u32(a, b, c) /* EOR3 from the SHA3 extension */
#else
#define VXOR3(a, b, c) veorq_u32(veorq_u32(a, b), c)
#endif
#define VCH(e, f, g)  vbslq_u32(e, f, g)               /* BSL is literally Ch */
#define VMAJ(a, b, c) vbslq_u32(veorq_u32(a, b), c, b) /* a^b ? c : b(=a) */
#define VSEL(m, x, y) vbslq_u32(m, x, y)
#define VMASK(arr)    vld1q_u32(arr)
JWT_INLINE void neon_tr4(uint32x4_t r0, uint32x4_t r1, uint32x4_t r2, uint32x4_t r3, uint32x4_t *o) {
    uint32x4_t t0 = vtrn1q_u32(r0, r1), t1 = vtrn2q_u32(r0, r1);
    uint32x4_t t2 = vtrn1q_u32(r2, r3), t3 = vtrn2q_u32(r2, r3);
    o[0] = vreinterpretq_u32_u64(vtrn1q_u64(vreinterpretq_u64_u32(t0), vreinterpretq_u64_u32(t2)));
    o[1] = vreinterpretq_u32_u64(vtrn1q_u64(vreinterpretq_u64_u32(t1), vreinterpretq_u64_u32(t3)));
    o[2] = vreinterpretq_u32_u64(vtrn2q_u64(vreinterpretq_u64_u32(t0), vreinterpretq_u64_u32(t2)));
    o[3] = vreinterpretq_u32_u64(vtrn2q_u64(vreinterpretq_u64_u32(t1), vreinterpretq_u64_u32(t3)));
}
#define NEON_LDBE(p) vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p)))
#define MB_LOAD16(ptr, w)                                                                                              \
    do {                                                                                                               \
        for (int j_ = 0; j_ < 4; j_++)                                                                                 \
            neon_tr4(NEON_LDBE((ptr)[0] + 16 * j_), NEON_LDBE((ptr)[1] + 16 * j_), NEON_LDBE((ptr)[2] + 16 * j_),      \
                     NEON_LDBE((ptr)[3] + 16 * j_), (w) + 4 * j_);                                                     \
    } while (0)
#define MB_STORE8(s, out)                                                                                              \
    do {                                                                                                               \
        uint32x4_t o_[8];                                                                                              \
        neon_tr4((s)[0], (s)[1], (s)[2], (s)[3], o_);                                                                  \
        neon_tr4((s)[4], (s)[5], (s)[6], (s)[7], o_ + 4);                                                              \
        for (int l_ = 0; l_ < 4; l_++) vst1q_u32((out)[l_], o_[l_]), vst1q_u32((out)[l_] + 4, o_[4 + l_]);             \
    } while (0)
#define MB_MIN_LANES 2
#include "jwt_mb.inc"
#undef MB
#undef MB_LANES
#undef V
#undef VSET1
#undef VADD
#undef VXOR
#undef VSHR
#undef VROR
#undef VXOR3
#undef VCH
#undef VMAJ
#undef VSEL
#undef VMASK
#undef MB_LOAD16
#undef MB_STORE8
#undef MB_MIN_LANES
#endif /* NEON */

/* ---- AVX2 8 lanes, and the AVX-512VL flavour of the very same code ---- */
#if defined(JWT_X86)
JWT_BEGIN_AVX2
JWT_INLINE void avx2_tr8(const __m256i *r, __m256i *o) {
    __m256i t0 = _mm256_unpacklo_epi32(r[0], r[1]), t1 = _mm256_unpackhi_epi32(r[0], r[1]);
    __m256i t2 = _mm256_unpacklo_epi32(r[2], r[3]), t3 = _mm256_unpackhi_epi32(r[2], r[3]);
    __m256i t4 = _mm256_unpacklo_epi32(r[4], r[5]), t5 = _mm256_unpackhi_epi32(r[4], r[5]);
    __m256i t6 = _mm256_unpacklo_epi32(r[6], r[7]), t7 = _mm256_unpackhi_epi32(r[6], r[7]);
    __m256i u0 = _mm256_unpacklo_epi64(t0, t2), u1 = _mm256_unpackhi_epi64(t0, t2);
    __m256i u2 = _mm256_unpacklo_epi64(t1, t3), u3 = _mm256_unpackhi_epi64(t1, t3);
    __m256i u4 = _mm256_unpacklo_epi64(t4, t6), u5 = _mm256_unpackhi_epi64(t4, t6);
    __m256i u6 = _mm256_unpacklo_epi64(t5, t7), u7 = _mm256_unpackhi_epi64(t5, t7);
    o[0] = _mm256_permute2x128_si256(u0, u4, 0x20), o[4] = _mm256_permute2x128_si256(u0, u4, 0x31);
    o[1] = _mm256_permute2x128_si256(u1, u5, 0x20), o[5] = _mm256_permute2x128_si256(u1, u5, 0x31);
    o[2] = _mm256_permute2x128_si256(u2, u6, 0x20), o[6] = _mm256_permute2x128_si256(u2, u6, 0x31);
    o[3] = _mm256_permute2x128_si256(u3, u7, 0x20), o[7] = _mm256_permute2x128_si256(u3, u7, 0x31);
}
#define AVX_BSWAP32                                                                                                    \
    _mm256_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15,   \
                     14, 13, 12)
#define MB_LOAD16(ptr, w)                                                                                              \
    do {                                                                                                               \
        __m256i r_[8], bs_ = AVX_BSWAP32;                                                                              \
        for (int h_ = 0; h_ < 2; h_++) {                                                                               \
            for (int l_ = 0; l_ < 8; l_++)                                                                             \
                r_[l_] = _mm256_shuffle_epi8(_mm256_loadu_si256((const __m256i *)((ptr)[l_] + 32 * h_)), bs_);         \
            avx2_tr8(r_, (w) + 8 * h_);                                                                                \
        }                                                                                                              \
    } while (0)
#define MB_STORE8(s, out)                                                                                              \
    do {                                                                                                               \
        __m256i o_[8];                                                                                                 \
        avx2_tr8((s), o_);                                                                                             \
        for (int l_ = 0; l_ < 8; l_++) _mm256_storeu_si256((__m256i *)(out)[l_], o_[l_]);                              \
    } while (0)
#define MB_LANES          8
#define V                 __m256i
#define VSET1(x)          _mm256_set1_epi32((int)(x))
#define VADD(a, b)        _mm256_add_epi32(a, b)
#define VXOR(a, b)        _mm256_xor_si256(a, b)
#define VSHR(x, n)        _mm256_srli_epi32(x, n)
#define VMASK(arr)        _mm256_loadu_si256((const __m256i *)(arr))
#define JWT_AVX_MIN_LANES 2
/* AVX2 alone: with OpenSSL's single-stream code for leftovers, 2 messages one at a time (2 x 753 ns) beat one
 * 2-lane AVX2 group (822 ns) on a Xeon Platinum 8260; from 3 lanes the vector wins (555 ns) */
#if defined(JWT_OSSL_SHA256) && defined(__x86_64__) && defined(__ELF__)
#define JWT_AVX2_MIN_LANES 3
#else
#define JWT_AVX2_MIN_LANES JWT_AVX_MIN_LANES
#endif
#define MB_MIN_LANES JWT_AVX2_MIN_LANES

#define MB(name)       name##_avx2
#define VROR(x, n)     _mm256_or_si256(_mm256_srli_epi32(x, n), _mm256_slli_epi32(x, 32 - (n)))
#define VXOR3(a, b, c) _mm256_xor_si256(_mm256_xor_si256(a, b), c)
#define VCH(e, f, g)   _mm256_xor_si256(g, _mm256_and_si256(e, _mm256_xor_si256(f, g)))
/* Maj = b ^ ((a ^ b) & (b ^ c)): b ^ c is the previous round's a ^ b, which the fully unrolled
 * compress lets the compiler reuse, so 2 new ops per round instead of 4 (trick from cpuminer-opt) */
#define VMAJ(a, b, c)  _mm256_xor_si256(b, _mm256_and_si256(_mm256_xor_si256(a, b), _mm256_xor_si256(b, c)))
#define VSEL(m, x, y)  _mm256_blendv_epi8(y, x, m)
#include "jwt_mb.inc"
#undef MB
#undef VROR
#undef VXOR3
#undef VCH
#undef VMAJ
#undef VSEL

#if 1 /* AVX-512VL, compiled in its own target region */
JWT_END_TARGET
JWT_BEGIN_AVX512
/* Identical to the AVX2 instantiation except for these five macros (tested on a Xeon Platinum 8260).
 * vpternlogd immediates (truth table index = a<<2 | b<<1 | c):
 *   0x96 = a^b^c, 0xCA = a ? b : c (Ch, and the lane select), 0xE8 = majority.
 * tests/test_jwt.c runs the template with a scalar ternlog emulation using these same constants. */
#undef MB_MIN_LANES
#define MB_MIN_LANES   JWT_AVX_MIN_LANES
#define MB(name)       name##_avx512
#define VROR(x, n)     _mm256_ror_epi32(x, n) /* vprord */
#define VXOR3(a, b, c) _mm256_ternarylogic_epi32(a, b, c, JWT_TL_XOR3)
#define VCH(e, f, g)   _mm256_ternarylogic_epi32(e, f, g, JWT_TL_CH)
#define VMAJ(a, b, c)  _mm256_ternarylogic_epi32(a, b, c, JWT_TL_MAJ)
#define VSEL(m, x, y)  _mm256_ternarylogic_epi32(m, x, y, JWT_TL_CH)
#include "jwt_mb.inc"
#undef MB
#undef VROR
#undef VXOR3
#undef VCH
#undef VMAJ
#undef VSEL
JWT_END_TARGET
JWT_BEGIN_AVX2
#endif

#undef MB_LANES
#undef V
#undef VSET1
#undef VADD
#undef VXOR
#undef VSHR
#undef VMASK
#undef MB_LOAD16
#undef MB_STORE8
#undef MB_MIN_LANES

/* ---- 16 lanes as two interleaved ymm groups ----
 * One 8-lane compress is latency-bound on Skylake-SP (llvm-mca: ~820 cycles vs ~585 of port
 * pressure), so give the scheduler two independent dependency chains.  With AVX-512VL there are
 * 32 ymm registers to hold both; with plain AVX2 (16 registers) it spills. */
typedef struct {
    __m256i a, b;
} v2_t;
#define V2OP1(name, expr)                                                                                              \
    JWT_INLINE v2_t name(v2_t x) {                                                                                     \
        v2_t r;                                                                                                        \
        r.a = expr(x.a), r.b = expr(x.b);                                                                              \
        return r;                                                                                                      \
    }
#define V2OP2(name, expr)                                                                                              \
    JWT_INLINE v2_t name(v2_t x, v2_t y) {                                                                             \
        v2_t r;                                                                                                        \
        r.a = expr(x.a, y.a), r.b = expr(x.b, y.b);                                                                    \
        return r;                                                                                                      \
    }
#define V2OP3(name, expr)                                                                                              \
    JWT_INLINE v2_t name(v2_t x, v2_t y, v2_t z) {                                                                     \
        v2_t r;                                                                                                        \
        r.a = expr(x.a, y.a, z.a), r.b = expr(x.b, y.b, z.b);                                                          \
        return r;                                                                                                      \
    }
JWT_INLINE v2_t v2_set1(uint32_t x) {
    v2_t r;
    r.a = r.b = _mm256_set1_epi32((int)x);
    return r;
}
#define A2_ADD(x, y) _mm256_add_epi32(x, y)
#define A2_XOR(x, y) _mm256_xor_si256(x, y)
V2OP2(v2_add, A2_ADD)
V2OP2(v2_xor, A2_XOR)
#define MB_LANES   16
#define V          v2_t
#define VSET1(x)   v2_set1(x)
#define VADD(a, b) v2_add(a, b)
#define VXOR(a, b) v2_xor(a, b)
#define VSHR(x, n) ((v2_t){ _mm256_srli_epi32((x).a, n), _mm256_srli_epi32((x).b, n) })
#define VMASK(arr)                                                                                                     \
    ((v2_t){ _mm256_loadu_si256((const __m256i *)(arr)), _mm256_loadu_si256((const __m256i *)(arr) + 1) })
#define MB_LOAD16(ptr, w)                                                                                              \
    do {                                                                                                               \
        __m256i r_[8], o_[16], bs_ = AVX_BSWAP32;                                                                      \
        for (int g_ = 0; g_ < 2; g_++) {                                                                               \
            for (int h_ = 0; h_ < 2; h_++) {                                                                           \
                for (int l_ = 0; l_ < 8; l_++)                                                                         \
                    r_[l_] =                                                                                           \
                        _mm256_shuffle_epi8(_mm256_loadu_si256((const __m256i *)((ptr)[8 * g_ + l_] + 32 * h_)), bs_); \
                avx2_tr8(r_, o_ + 8 * h_);                                                                             \
            }                                                                                                          \
            for (int i_ = 0; i_ < 16; i_++) {                                                                          \
                if (g_) (w)[i_].b = o_[i_];                                                                            \
                else (w)[i_].a = o_[i_];                                                                               \
            }                                                                                                          \
        }                                                                                                              \
    } while (0)
#define MB_STORE8(s, out)                                                                                              \
    do {                                                                                                               \
        __m256i i_[8], o_[8];                                                                                          \
        for (int g_ = 0; g_ < 2; g_++) {                                                                               \
            for (int j_ = 0; j_ < 8; j_++) i_[j_] = g_ ? (s)[j_].b : (s)[j_].a;                                        \
            avx2_tr8(i_, o_);                                                                                          \
            for (int l_ = 0; l_ < 8; l_++) _mm256_storeu_si256((__m256i *)(out)[8 * g_ + l_], o_[l_]);                 \
        }                                                                                                              \
    } while (0)
#ifndef JWT_AVX2X_MIN_LANES
#define JWT_AVX2X_MIN_LANES 9 /* <= 8 live lanes: a single 8-lane group is cheaper */
#endif
#define MB_MIN_LANES 1 /* the driver below routes small groups itself */
#define MB_NO_DRIVER

#define A2_ROR(x, n)     _mm256_or_si256(_mm256_srli_epi32(x, n), _mm256_slli_epi32(x, 32 - (n)))
#define A2_XOR3(x, y, z) _mm256_xor_si256(_mm256_xor_si256(x, y), z)
#define A2_CH(e, f, g)   _mm256_xor_si256(g, _mm256_and_si256(e, _mm256_xor_si256(f, g)))
#define A2_MAJ(a, b, c)  _mm256_xor_si256(b, _mm256_and_si256(_mm256_xor_si256(a, b), _mm256_xor_si256(b, c)))
#define A2_SEL(m, x, y)  _mm256_blendv_epi8(y, x, m)
V2OP3(v2_xor3_avx2, A2_XOR3)
V2OP3(v2_ch_avx2, A2_CH)
V2OP3(v2_maj_avx2, A2_MAJ)
V2OP3(v2_sel_avx2, A2_SEL)
#define MB(name)       name##_avx2x2
#define VROR(x, n)     ((v2_t){ A2_ROR((x).a, n), A2_ROR((x).b, n) })
#define VXOR3(a, b, c) v2_xor3_avx2(a, b, c)
#define VCH(e, f, g)   v2_ch_avx2(e, f, g)
#define VMAJ(a, b, c)  v2_maj_avx2(a, b, c)
#define VSEL(m, x, y)  v2_sel_avx2(m, x, y)
#include "jwt_mb.inc"
#undef MB
#undef VROR
#undef VXOR3
#undef VCH
#undef VMAJ
#undef VSEL

#if 1 /* AVX-512VL, compiled in its own target region */
JWT_END_TARGET
JWT_BEGIN_AVX512
#define T2_XOR3(x, y, z) _mm256_ternarylogic_epi32(x, y, z, JWT_TL_XOR3)
#define T2_CH(x, y, z)   _mm256_ternarylogic_epi32(x, y, z, JWT_TL_CH)
#define T2_MAJ(x, y, z)  _mm256_ternarylogic_epi32(x, y, z, JWT_TL_MAJ)
V2OP3(v2_xor3_512, T2_XOR3)
V2OP3(v2_ch_512, T2_CH)
V2OP3(v2_maj_512, T2_MAJ)
#define MB(name)       name##_avx512x2
#define VROR(x, n)     ((v2_t){ _mm256_ror_epi32((x).a, n), _mm256_ror_epi32((x).b, n) })
#define VXOR3(a, b, c) v2_xor3_512(a, b, c)
#define VCH(e, f, g)   v2_ch_512(e, f, g)
#define VMAJ(a, b, c)  v2_maj_512(a, b, c)
#define VSEL(m, x, y)  v2_ch_512(m, x, y)
#include "jwt_mb.inc"
#undef MB
#undef VROR
#undef VXOR3
#undef VCH
#undef VMAJ
#undef VSEL
JWT_END_TARGET
JWT_BEGIN_AVX2
#endif
#undef MB_NO_DRIVER
#undef MB_LANES
#undef V
#undef VSET1
#undef VADD
#undef VXOR
#undef VSHR
#undef VMASK
#undef MB_LOAD16
#undef MB_STORE8
#undef MB_MIN_LANES

/* driver for the 16-lane flavours: full 16-groups go 2x8 interleaved, the rest to the 8-lane engine */
typedef void lanes_fn(const jwt_key_t *, int, const hplan_t *const *, uint32_t (*)[8]);
static void x2_drive(lanes_fn *l16, lanes_fn *l8, const jwt_key_t *k, int n, const uint8_t *const *msg, const int *len,
                     uint32_t (*mac)[8]) {
    enum { CH = 64 };
    hplan_t plan[CH];
    const hplan_t *pp[CH];
    uint32_t tmp[16][8];
    for (int base = 0; base < n; base += CH) {
        int m = n - base < CH ? n - base : CH;
        for (int i = 0; i < m; i++) hplan_init(&plan[i], msg[base + i], len[base + i]);
        for (int i = 0; i < m; i++) {
            const hplan_t *p = &plan[i];
            int j = i;
            while (j > 0 && pp[j - 1]->nb > p->nb) pp[j] = pp[j - 1], j--;
            pp[j] = p;
        }
        for (int g = 0; g < m;) {
            int nl = m - g;
            if (nl >= JWT_AVX2X_MIN_LANES) {
                if (nl > 16) nl = 16;
                l16(k, nl, &pp[g], tmp);
            } else {
                if (nl > 8) nl = 8;
                if (nl < JWT_AVX_MIN_LANES) {
                    for (int l = 0; l < nl; l++) hmac1_scalar(k, pp[g + l], tmp[l]);
                } else {
                    l8(k, nl, &pp[g], tmp);
                }
            }
            for (int l = 0; l < nl; l++) memcpy(mac[base + (int)(pp[g + l] - plan)], tmp[l], 32);
            g += nl;
        }
    }
}
void jwt_hmac_avx2x2(const jwt_key_t *k, int n, const uint8_t *const *msg, const int *len, uint32_t (*mac)[8]) {
    x2_drive(lanes_avx2x2, lanes_avx2, k, n, msg, len, mac);
}
#if 1 /* AVX-512VL, compiled in its own target region */
JWT_END_TARGET
JWT_BEGIN_AVX512
void jwt_hmac_avx512x2(const jwt_key_t *k, int n, const uint8_t *const *msg, const int *len, uint32_t (*mac)[8]) {
    x2_drive(lanes_avx512x2, lanes_avx512, k, n, msg, len, mac);
}

/* ---- zmm, 16 lanes: NOT the default.  Fewest cycles per lane, but heavy 512-bit integer work can
 * drop the core's frequency licence for everything that runs after it; bench/licence_probe.c measures
 * that on real hardware.  Loads/stores reuse the ymm 8x8 transposes and glue the halves. */
#define MB(name)       name##_zmm
#define MB_LANES       16
#define V              __m512i
#define VSET1(x)       _mm512_set1_epi32((int)(x))
#define VADD(a, b)     _mm512_add_epi32(a, b)
#define VXOR(a, b)     _mm512_xor_si512(a, b)
#define VSHR(x, n)     _mm512_srli_epi32(x, n)
#define VROR(x, n)     _mm512_ror_epi32(x, n)
#define VXOR3(a, b, c) _mm512_ternarylogic_epi32(a, b, c, JWT_TL_XOR3)
#define VCH(e, f, g)   _mm512_ternarylogic_epi32(e, f, g, JWT_TL_CH)
#define VMAJ(a, b, c)  _mm512_ternarylogic_epi32(a, b, c, JWT_TL_MAJ)
#define VSEL(m, x, y)  _mm512_ternarylogic_epi32(m, x, y, JWT_TL_CH)
#define VMASK(arr)     _mm512_loadu_si512((const void *)(arr))
#define MB_LOAD16(ptr, w)                                                                                              \
    do {                                                                                                               \
        __m256i r_[8], o_[2][16], bs_ = AVX_BSWAP32;                                                                   \
        for (int g_ = 0; g_ < 2; g_++)                                                                                 \
            for (int h_ = 0; h_ < 2; h_++) {                                                                           \
                for (int l_ = 0; l_ < 8; l_++)                                                                         \
                    r_[l_] =                                                                                           \
                        _mm256_shuffle_epi8(_mm256_loadu_si256((const __m256i *)((ptr)[8 * g_ + l_] + 32 * h_)), bs_); \
                avx2_tr8(r_, o_[g_] + 8 * h_);                                                                         \
            }                                                                                                          \
        for (int i_ = 0; i_ < 16; i_++) (w)[i_] = _mm512_inserti64x4(_mm512_castsi256_si512(o_[0][i_]), o_[1][i_], 1); \
    } while (0)
#define MB_STORE8(s, out)                                                                                              \
    do { /* extract immediates must be literal constants at every -O level */                                          \
        __m256i i_[8], o_[8];                                                                                          \
        for (int j_ = 0; j_ < 8; j_++) i_[j_] = _mm512_castsi512_si256((s)[j_]);                                       \
        avx2_tr8(i_, o_);                                                                                              \
        for (int l_ = 0; l_ < 8; l_++) _mm256_storeu_si256((__m256i *)(out)[l_], o_[l_]);                              \
        for (int j_ = 0; j_ < 8; j_++) i_[j_] = _mm512_extracti64x4_epi64((s)[j_], 1);                                 \
        avx2_tr8(i_, o_);                                                                                              \
        for (int l_ = 0; l_ < 8; l_++) _mm256_storeu_si256((__m256i *)(out)[8 + l_], o_[l_]);                          \
    } while (0)
#define MB_MIN_LANES 1
#define MB_NO_DRIVER
#include "jwt_mb.inc"
#undef MB_NO_DRIVER
#undef MB
#undef MB_LANES
#undef V
#undef VSET1
#undef VADD
#undef VXOR
#undef VSHR
#undef VROR
#undef VXOR3
#undef VCH
#undef VMAJ
#undef VSEL
#undef VMASK
#undef MB_LOAD16
#undef MB_STORE8
#undef MB_MIN_LANES
void jwt_hmac_zmm(const jwt_key_t *k, int n, const uint8_t *const *msg, const int *len, uint32_t (*mac)[8]) {
    x2_drive(lanes_zmm, lanes_avx512, k, n, msg, len, mac);
}
JWT_END_TARGET /* the AVX-512 region ends the AVX2 one too */
#endif
#endif /* AVX2 */

/* ---- ARMv8 SHA2 instructions: S independent streams interleaved for latency hiding ---- */
#if defined(JWT_ARM_SHA2)
    JWT_BEGIN_SHA2
        /* 64 rounds on S streams; m[s][0..3] are the 16 message words (host order) of stream s. */
        JWT_INLINE void
        ce_compress(int S, uint32x4_t *st0, uint32x4_t *st1, uint32x4_t (*m)[4]) {
    uint32x4_t a0[4], a1[4];
    for (int s = 0; s < S; s++) a0[s] = st0[s], a1[s] = st1[s];
#if defined(__clang__)
#pragma clang loop unroll(full)
#else
#pragma GCC unroll 16
#endif
    for (int r = 0; r < 16; r++) {
        uint32x4_t kr = vld1q_u32(K256 + 4 * r);
        for (int s = 0; s < S; s++) {
            uint32x4_t wk = vaddq_u32(m[s][r & 3], kr), t = st0[s];
            st0[s] = vsha256hq_u32(st0[s], st1[s], wk);
            st1[s] = vsha256h2q_u32(st1[s], t, wk);
            if (r < 12)
                m[s][r & 3] = vsha256su1q_u32(vsha256su0q_u32(m[s][r & 3], m[s][(r + 1) & 3]), m[s][(r + 2) & 3],
                                              m[s][(r + 3) & 3]);
        }
    }
    for (int s = 0; s < S; s++) st0[s] = vaddq_u32(st0[s], a0[s]), st1[s] = vaddq_u32(st1[s], a1[s]);
}

/* S plans with identical nb; raw: plain SHA-256 (k = sha_iv_key, no outer hash) */
JWT_INLINE void ce_hmac(int S, int raw, const jwt_key_t *k, const hplan_t *const *p, uint32_t *const *mac) {
    uint32x4_t st0[4], st1[4], m[4][4];
    uint32x4_t ih0 = vld1q_u32(k->ih), ih1 = vld1q_u32(k->ih + 4);
    for (int s = 0; s < S; s++) st0[s] = ih0, st1[s] = ih1;
    for (int b = 0; b < p[0]->nb; b++) {
        for (int s = 0; s < S; s++) {
            const uint8_t *blk = hplan_block(p[s], b);
            for (int j = 0; j < 4; j++) m[s][j] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(blk + 16 * j)));
        }
        ce_compress(S, st0, st1, m);
    }
    if (raw) {
        for (int s = 0; s < S; s++) vst1q_u32(mac[s], st0[s]), vst1q_u32(mac[s] + 4, st1[s]);
        return;
    }
    const uint32_t pad2[4] = { 0x80000000u, 0, 0, 0 }, pad3[4] = { 0, 0, 0, (64 + 32) * 8 };
    for (int s = 0; s < S; s++) {
        m[s][0] = st0[s], m[s][1] = st1[s], m[s][2] = vld1q_u32(pad2), m[s][3] = vld1q_u32(pad3);
        st0[s] = vld1q_u32(k->oh), st1[s] = vld1q_u32(k->oh + 4);
    }
    ce_compress(S, st0, st1, m);
    for (int s = 0; s < S; s++) vst1q_u32(mac[s], st0[s]), vst1q_u32(mac[s] + 4, st1[s]);
}

JWT_INLINE void ce_drive_x(int S, int raw, const jwt_key_t *k, int n, const uint8_t *const *msg, const int *len,
                           uint32_t (*mac)[8]) {
    enum { CH = 64 };
    hplan_t plan[CH];
    const hplan_t *pp[CH];
    for (int base = 0; base < n; base += CH) {
        int m = n - base < CH ? n - base : CH;
        for (int i = 0; i < m; i++) hplan_init_off(&plan[i], msg[base + i], len[base + i], raw ? 0 : 64);
        for (int i = 0; i < m; i++) { /* sort by nb so groups of S share a block count */
            const hplan_t *p = &plan[i];
            int j = i;
            while (j > 0 && pp[j - 1]->nb > p->nb) pp[j] = pp[j - 1], j--;
            pp[j] = p;
        }
        int g = 0;
        while (g < m) {
            int s = S;
            if (m - g < s) s = m - g;
            for (int i = 1; i < s; i++)
                if (pp[g + i]->nb != pp[g]->nb) {
                    s = i;
                    break;
                }
            uint32_t *out[4];
            for (int i = 0; i < s; i++) out[i] = mac[base + (int)(pp[g + i] - plan)];
            switch (s) { /* constant S per call so ce_hmac fully specialises */
                case 4: ce_hmac(4, raw, k, pp + g, out); break;
                case 3:
                    ce_hmac(2, raw, k, pp + g, out);
                    ce_hmac(1, raw, k, pp + g + 2, out + 2);
                    break;
                case 2: ce_hmac(2, raw, k, pp + g, out); break;
                default: ce_hmac(1, raw, k, pp + g, out); break;
            }
            g += s;
        }
    }
}
static void ce_drive(int S, const jwt_key_t *k, int n, const uint8_t *const *msg, const int *len, uint32_t (*mac)[8]) {
    ce_drive_x(S, 0, k, n, msg, len, mac);
}
void jwt_sha256_sha2(int n, const uint8_t *const *msg, const int *len, uint32_t (*dig)[8]) {
    ce_drive_x(4, 1, &sha_iv_key, n, msg, len, dig);
}

void jwt_hmac_sha2_1(const jwt_key_t *k, int n, const uint8_t *const *msg, const int *len, uint32_t (*mac)[8]) {
    ce_drive(1, k, n, msg, len, mac);
}
void jwt_hmac_sha2(const jwt_key_t *k, int n, const uint8_t *const *msg, const int *len, uint32_t (*mac)[8]) {
    ce_drive(4, k, n, msg, len, mac); /* 4 streams: 15% faster than 1 on an M5 */
}
void jwt_hmac_sha2_2(const jwt_key_t *k, int n, const uint8_t *const *msg, const int *len, uint32_t (*mac)[8]) {
    ce_drive(2, k, n, msg, len, mac);
}
JWT_END_SHA2
#endif /* SHA2 */

/* ---- x86 SHA-NI: S independent streams interleaved for latency hiding (the ARM engine's layout) ----
 * Every Zen has SHA-NI; Cascade Lake doesn't, so there this code is compiled and never picked.  The state lives as
 * ABEF / CDGH (the order sha256rnds2 wants); ni_ld / ni_st convert from / to the natural h0..h7. */
#if defined(JWT_X86)
#if defined(__clang__)
#define JWT_BEGIN_SHANI                                                                                                \
    _Pragma("clang attribute push (__attribute__((target(\"sha,sse4.1,ssse3\"))), apply_to = function)")
#else
#define JWT_BEGIN_SHANI _Pragma("GCC push_options") _Pragma("GCC target(\"sha,sse4.1,ssse3\")")
#endif
JWT_BEGIN_SHANI
JWT_INLINE void ni_ld(const uint32_t h[8], __m128i *abef, __m128i *cdgh) {
    __m128i t = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i *)h), 0xB1);       /* CDAB */
    __m128i u = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i *)(h + 4)), 0x1B); /* EFGH */
    *abef = _mm_alignr_epi8(t, u, 8);
    *cdgh = _mm_blend_epi16(u, t, 0xF0);
}
JWT_INLINE void ni_st(__m128i abef, __m128i cdgh, uint32_t h[8]) {
    __m128i t = _mm_shuffle_epi32(abef, 0x1B), u = _mm_shuffle_epi32(cdgh, 0xB1); /* FEBA, DCHG */
    _mm_storeu_si128((__m128i *)h, _mm_blend_epi16(t, u, 0xF0));                  /* DCBA */
    _mm_storeu_si128((__m128i *)(h + 4), _mm_alignr_epi8(u, t, 8));               /* HGFE */
}
/* 64 rounds on S streams; m[s][0..3] are the 16 message words (host order) of stream s. */
JWT_INLINE void ni_compress(int S, __m128i *st0, __m128i *st1, __m128i (*m)[4]) {
    __m128i a0[4], a1[4];
    for (int s = 0; s < S; s++) a0[s] = st0[s], a1[s] = st1[s];
#if defined(__clang__)
#pragma clang loop unroll(full)
#else
#pragma GCC unroll 16
#endif
    for (int r = 0; r < 16; r++) {
        __m128i kr = _mm_loadu_si128((const __m128i *)(K256 + 4 * r));
        for (int s = 0; s < S; s++) {
            __m128i wk = _mm_add_epi32(m[s][r & 3], kr);
            st1[s] = _mm_sha256rnds2_epu32(st1[s], st0[s], wk);
            st0[s] = _mm_sha256rnds2_epu32(st0[s], st1[s], _mm_shuffle_epi32(wk, 0x0E));
            if (r < 12) { /* W[4(r+4)..] from the last four groups: msg1, + W[t-7] (alignr), msg2 */
                __m128i w = _mm_sha256msg1_epu32(m[s][r & 3], m[s][(r + 1) & 3]);
                w = _mm_add_epi32(w, _mm_alignr_epi8(m[s][(r + 3) & 3], m[s][(r + 2) & 3], 4));
                m[s][r & 3] = _mm_sha256msg2_epu32(w, m[s][(r + 3) & 3]);
            }
        }
    }
    for (int s = 0; s < S; s++) st0[s] = _mm_add_epi32(st0[s], a0[s]), st1[s] = _mm_add_epi32(st1[s], a1[s]);
}
/* S plans with identical nb; raw: plain SHA-256 (k = sha_iv_key, no outer hash) */
JWT_INLINE void ni_hmac(int S, int raw, const jwt_key_t *k, const hplan_t *const *p, uint32_t *const *mac) {
    const __m128i bswap = _mm_set_epi64x(0x0c0d0e0f08090a0bLL, 0x0405060700010203LL);
    __m128i st0[4], st1[4], m[4][4], ih0, ih1;
    ni_ld(k->ih, &ih0, &ih1);
    for (int s = 0; s < S; s++) st0[s] = ih0, st1[s] = ih1;
    for (int b = 0; b < p[0]->nb; b++) {
        for (int s = 0; s < S; s++) {
            const uint8_t *blk = hplan_block(p[s], b);
            for (int j = 0; j < 4; j++)
                m[s][j] = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(blk + 16 * j)), bswap);
        }
        ni_compress(S, st0, st1, m);
    }
    if (raw) {
        for (int s = 0; s < S; s++) ni_st(st0[s], st1[s], mac[s]);
        return;
    }
    __m128i oh0, oh1;
    ni_ld(k->oh, &oh0, &oh1);
    for (int s = 0; s < S; s++) {
        uint32_t d[8];
        ni_st(st0[s], st1[s], d);
        m[s][0] = _mm_loadu_si128((const __m128i *)d), m[s][1] = _mm_loadu_si128((const __m128i *)(d + 4));
        m[s][2] = _mm_set_epi32(0, 0, 0, (int)0x80000000u), m[s][3] = _mm_set_epi32((64 + 32) * 8, 0, 0, 0);
        st0[s] = oh0, st1[s] = oh1;
    }
    ni_compress(S, st0, st1, m);
    for (int s = 0; s < S; s++) ni_st(st0[s], st1[s], mac[s]);
}
JWT_INLINE void ni_drive_x(int S, int raw, const jwt_key_t *k, int n, const uint8_t *const *msg, const int *len,
                           uint32_t (*mac)[8]) {
    enum { CH = 64 };
    hplan_t plan[CH];
    const hplan_t *pp[CH];
    for (int base = 0; base < n; base += CH) {
        int m = n - base < CH ? n - base : CH;
        for (int i = 0; i < m; i++) hplan_init_off(&plan[i], msg[base + i], len[base + i], raw ? 0 : 64);
        for (int i = 0; i < m; i++) { /* sort by nb so groups of S share a block count */
            const hplan_t *p = &plan[i];
            int j = i;
            while (j > 0 && pp[j - 1]->nb > p->nb) pp[j] = pp[j - 1], j--;
            pp[j] = p;
        }
        int g = 0;
        while (g < m) {
            int s = S;
            if (m - g < s) s = m - g;
            for (int i = 1; i < s; i++)
                if (pp[g + i]->nb != pp[g]->nb) {
                    s = i;
                    break;
                }
            uint32_t *out[4];
            for (int i = 0; i < s; i++) out[i] = mac[base + (int)(pp[g + i] - plan)];
            switch (s) { /* constant S per call so ni_hmac fully specialises */
                case 4: ni_hmac(4, raw, k, pp + g, out); break;
                case 3:
                    ni_hmac(2, raw, k, pp + g, out);
                    ni_hmac(1, raw, k, pp + g + 2, out + 2);
                    break;
                case 2: ni_hmac(2, raw, k, pp + g, out); break;
                default: ni_hmac(1, raw, k, pp + g, out); break;
            }
            g += s;
        }
    }
}
void jwt_hmac_shani_1(const jwt_key_t *k, int n, const uint8_t *const *msg, const int *len, uint32_t (*mac)[8]) {
    ni_drive_x(1, 0, k, n, msg, len, mac);
}
void jwt_hmac_shani_2(const jwt_key_t *k, int n, const uint8_t *const *msg, const int *len, uint32_t (*mac)[8]) {
    ni_drive_x(2, 0, k, n, msg, len, mac);
}
void jwt_hmac_shani_4(const jwt_key_t *k, int n, const uint8_t *const *msg, const int *len, uint32_t (*mac)[8]) {
    ni_drive_x(4, 0, k, n, msg, len, mac);
}
JWT_END_TARGET
/* whole groups of 16 on the zmm engine, the rest (and batches under 16) on 4 SHA-NI streams */
void jwt_hmac_shani_zmm(const jwt_key_t *k, int n, const uint8_t *const *msg, const int *len, uint32_t (*mac)[8]) {
    int z = n & ~15;
    if (z) jwt_hmac_zmm(k, z, msg, len, mac);
    if (n > z) jwt_hmac_shani_4(k, n - z, msg + z, len + z, mac + z);
}
#endif /* SHA-NI */

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
JWT_INLINE int b64u_tail(uint8_t *dst, const char *src, int r) {
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

#if defined(JWT_HAVE_NEON)
/* 64 chars -> 48 bytes: vld4 de-interleaves the 4 sextets of every quantum into 4 registers,
 * vqtbl4/vqtbx4 translate through a 128-byte table, vst3 re-interleaves the 3 output bytes.
 * Table misses give 0xFF; bytes >= 0x80 index nothing and are caught by OR-ing in the input. */
JWT_INLINE uint8x16_t neon_b64_64(const uint8_t *src, uint8_t *dst, uint8x16x4_t lo, uint8x16x4_t hi) {
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
#elif defined(JWT_X86)
JWT_BEGIN_AVX2
/* 32 chars -> 24 bytes (Muła/Lemire packing; base64url translation via range compares).
 * Stores 32 bytes per block: dst needs the 32 bytes of slack jwt.h asks for. */
JWT_INLINE __m256i avx2_b64_32(const char *src, uint8_t *dst) {
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
JWT_END_TARGET
static int b64url_decode_resolve(uint8_t *dst, const char *src, int n);
static int (*b64url_impl)(uint8_t *, const char *, int) = b64url_decode_resolve;
static int b64url_decode_resolve(uint8_t *dst, const char *src, int n) {
    int (*f)(uint8_t *, const char *, int) = jwt_cpu() & JWT_CPU_AVX2 ? b64url_decode_avx2 : jwt_b64url_decode_scalar;
    JWT_STORE_FN(b64url_impl, f);
    return f(dst, src, n);
}
int jwt_b64url_decode(uint8_t *dst, const char *src, int n) { return JWT_LOAD_FN(b64url_impl)(dst, src, n); }
#else
int jwt_b64url_decode(uint8_t *dst, const char *src, int n) { return jwt_b64url_decode_scalar(dst, src, n); }
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

JWT_INLINE void jws(jcur_t *c) {
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

JWT_INLINE int jstr(jcur_t *c, const uint8_t **s, int *n, int *esc) {
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
JWT_INLINE int jnum(jcur_t *c, const uint8_t **s, int *n, int *isint) {
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
JWT_INLINE uint64_t swar8(uint64_t x) { /* x = 8 digits, first digit in the low byte */
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
JWT_INLINE int jkey(const uint8_t *s, int n, int esc) {
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
JWT_INLINE int header_ok(const uint8_t *h, int n, const char *want) {
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
JWT_INLINE int sub_value(const uint8_t *s, int len, int64_t *uid) {
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
JWT_INLINE int payload_check(const uint8_t *pl, int n, const jnow_t *now, jwt_result_t *r) {
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
JWT_INLINE int jdigits8(const uint8_t *p) {
    uint64_t x;
    memcpy(&x, p, 8);
    uint64_t nd = ((x - 0x3030303030303030ull) | (x + 0x4646464646464646ull)) & 0x8080808080808080ull;
    return nd ? __builtin_ctzll(nd) >> 3 : 8;
}
JWT_INLINE int jdigits(const uint8_t *p, int max) {
    int n = 0, d;
    do n += d = jdigits8(p + n);
    while (d == 8 && n < max);
    return n;
}
/* offset of the first '"', '\\', control or non-ASCII byte */
JWT_INLINE int jstrspan(const uint8_t *p, int max) {
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
#elif defined(JWT_HAVE_NEON)
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

JWT_INLINE int payload_shape(const uint8_t *pl, int n, const jnow_t *now, jwt_result_t *r) {
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
JWT_INLINE void claims_one(jwt_result_t *r, const uint8_t *p64, int n64, const jnow_t *jn) {
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
            uint32_t diff = 0; /* constant time over the 32 bytes */
            for (int w = 0; w < 8; w++) diff |= mac[j][w] ^ want[j][w];
            if (!diff) good[ng++] = j;
        }
        for (int g = 0; g < ng; g++) {
            int j = good[g];
            claims_one(&out[base + idx[j]], msg[j] + poff[j], mlen[j] - poff[j], &jn);
        }
    }
}

void jwt_verify_batch_scalar(const jwt_key_t *k, int n, const char *const *tok, const int *len, int64_t now,
                             jwt_result_t *out) {
    verify_impl(k, n, tok, len, now, out, jwt_hmac_scalar);
}
#ifdef JWT_HAVE_NEON
void jwt_verify_batch_neon(const jwt_key_t *k, int n, const char *const *tok, const int *len, int64_t now,
                           jwt_result_t *out) {
    verify_impl(k, n, tok, len, now, out, jwt_hmac_neon);
}
#endif
#if defined(JWT_ARM_SHA2)
void jwt_verify_batch_sha2(const jwt_key_t *k, int n, const char *const *tok, const int *len, int64_t now,
                           jwt_result_t *out) {
    verify_impl(k, n, tok, len, now, out, jwt_hmac_sha2);
}
#endif
#if defined(JWT_X86)
void jwt_verify_batch_avx2(const jwt_key_t *k, int n, const char *const *tok, const int *len, int64_t now,
                           jwt_result_t *out) {
    verify_impl(k, n, tok, len, now, out, jwt_hmac_avx2);
}
void jwt_verify_batch_avx512(const jwt_key_t *k, int n, const char *const *tok, const int *len, int64_t now,
                             jwt_result_t *out) {
    verify_impl(k, n, tok, len, now, out, jwt_hmac_avx512);
}
#endif

/* the best engine this CPU has (run-time dispatch; see the top of the file) */
static jwt_hmac_fn *hmac_default(void) {
    unsigned f = jwt_cpu();
    (void)f;
#if defined(JWT_ARM_SHA2)
    if (f & JWT_CPU_SHA2) return jwt_hmac_sha2;
#endif
#if defined(JWT_X86)
    if ((f & JWT_CPU_FAST_SHANI) && (f & JWT_CPU_SHANI)) return jwt_hmac_shani_4; /* 4 interleaved SHA-NI streams */
    if ((f & JWT_CPU_SHANI) && (f & JWT_CPU_FAST_ZMM) && (f & JWT_CPU_AVX512VL))
        return jwt_hmac_shani_zmm;                                             /* Zen 5: SHA-NI + zmm */
    if ((f & JWT_CPU_FAST_ZMM) && (f & JWT_CPU_AVX512VL)) return jwt_hmac_zmm; /* 16 lanes; < 9 live -> 8-lane ymm */
    if (f & JWT_CPU_AVX512VL) return jwt_hmac_avx512;
    if (f & JWT_CPU_AVX2) return jwt_hmac_avx2;
#endif
#if defined(JWT_HAVE_NEON)
    return jwt_hmac_neon;
#else
    return jwt_hmac_scalar;
#endif
}
static jwt_sha256_fn *sha256_default(void) {
    unsigned f = jwt_cpu();
    (void)f;
#if defined(JWT_ARM_SHA2)
    if (f & JWT_CPU_SHA2) return jwt_sha256_sha2;
#endif
#if defined(JWT_X86)
    if (f & JWT_CPU_AVX512VL) return jwt_sha256_avx512;
    if (f & JWT_CPU_AVX2) return jwt_sha256_avx2;
#endif
#if defined(JWT_HAVE_NEON)
    return jwt_sha256_neon;
#else
    return jwt_sha256_scalar;
#endif
}
const char *jwt_engine(void) {
    jwt_hmac_fn *h = hmac_default();
#if defined(JWT_ARM_SHA2)
    if (h == jwt_hmac_sha2) return "sha2";
#endif
#if defined(JWT_X86)
    if (h == jwt_hmac_shani_4) return "shani";
    if (h == jwt_hmac_shani_zmm) return "shani+zmm";
    if (h == jwt_hmac_zmm) return "zmm";
    if (h == jwt_hmac_avx512) return "avx512vl";
    if (h == jwt_hmac_avx2) return "avx2";
#endif
#if defined(JWT_HAVE_NEON)
    if (h == jwt_hmac_neon) return "neon";
#endif
    return "scalar";
}

static void hmac_resolve(const jwt_key_t *k, int n, const uint8_t *const *msg, const int *len, uint32_t (*mac)[8]);
static void sha256_resolve(int n, const uint8_t *const *msg, const int *len, uint32_t (*dig)[8]);
static jwt_hmac_fn *hmac_impl = hmac_resolve;
static jwt_sha256_fn *sha256_impl = sha256_resolve;
static void hmac_resolve(const jwt_key_t *k, int n, const uint8_t *const *msg, const int *len, uint32_t (*mac)[8]) {
    jwt_hmac_fn *f = hmac_default();
    JWT_STORE_FN(hmac_impl, f);
    f(k, n, msg, len, mac);
}
static void sha256_resolve(int n, const uint8_t *const *msg, const int *len, uint32_t (*dig)[8]) {
    jwt_sha256_fn *f = sha256_default();
    JWT_STORE_FN(sha256_impl, f);
    f(n, msg, len, dig);
}
/* at load time: pick everything once, before any call */
__attribute__((constructor)) static void jwt_resolve_all(void) {
    JWT_STORE_FN(hmac_impl, hmac_default());
    JWT_STORE_FN(sha256_impl, sha256_default());
#if defined(JWT_X86)
    JWT_STORE_FN(b64url_impl, jwt_cpu() & JWT_CPU_AVX2 ? b64url_decode_avx2 : jwt_b64url_decode_scalar);
#endif
}

void jwt_verify_batch(const jwt_key_t *k, int n, const char *const *tok, const int *len, int64_t now,
                      jwt_result_t *out) {
    verify_impl(k, n, tok, len, now, out, JWT_LOAD_FN(hmac_impl));
}

/* plain SHA-256 of n messages on the default engine (the RS256 / ES256 signing inputs) */
void jwt_sha256_batch(int n, const uint8_t *const *msg, const int *len, uint32_t (*dig)[8]) {
    JWT_LOAD_FN(sha256_impl)(n, msg, len, dig);
}

#ifndef JWT_NO_PK /* RS256 / ES256 / EdDSA; -DJWT_NO_PK leaves them out */
#include "jwt_pk.inc"
#endif
