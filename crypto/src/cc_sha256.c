/* cc_sha256.c — run-time CPU dispatch and every SHA-256 / HMAC-SHA256 engine.  Part of cursed-jwt, MIT licence
 * (see LICENSE).  #included by cursed_crypto.c.  Sections:
 *   1. SHA-256 constants, HMAC message plans, key setup
 *   2. SHA-256 engines: scalar / NEON 4-lane / AVX2 8-lane / AVX-512VL 8-lane (all from cc_mb.inc),
 *      ARMv8 SHA2 instructions with 1/2/4 interleaved streams, x86-64 SHA-NI and the assembly kernels
 *   3. engine choice and the dispatched entry points
 */
#include "cc_internal.h"

/* ---- run-time CPU dispatch ----
 * The library is compiled for the baseline ISA (x86-64, ARMv8-A) and carries every engine the architecture can
 * have: the AVX2 and AVX-512VL engines are compiled inside target regions on x86-64, the SHA2 engine inside one on
 * AArch64.  cc_cpu (filled by a constructor from CPUID + XGETBV, or HWCAP / sysctl) picks the best one the
 * machine has at every entry point, falling back down to scalar.  Building with -march=native still works: the
 * regions are then no-ops, and dispatch still checks the CPU. */
#define CC_CPU_DETECTED (1u << 31) /* the JWT_CPU_* bits are in jwt.h */
static unsigned cc_cpu_bits;
#if defined(CC_X86)
#include <cpuid.h>
#endif
/* the CC_ name of a variable wins; cursed-jwt's JWT_ name still works */
static const char *cc_env(const char *name, const char *old) {
    const char *v = getenv(name);
    return v && *v ? v : getenv(old);
}
__attribute__((constructor)) static void cc_cpu_init(void) {
    unsigned f = CC_CPU_DETECTED;
#if defined(CC_X86)
    unsigned a = 0, b = 0, c = 0, d = 0, ecx1 = 0, ebx7 = 0, ecx7 = 0;
    if (__get_cpuid(1, &a, &b, &c, &d)) ecx1 = c;
    if (__get_cpuid_count(7, 0, &a, &b, &c, &d)) ebx7 = b, ecx7 = c;
    unsigned xcr0 = 0;
    if (ecx1 & (1u << 27)) { /* OSXSAVE: the OS manages the vector state that XCR0 lists */
        unsigned hi;
        __asm__("xgetbv" : "=a"(xcr0), "=d"(hi) : "c"(0));
    }
    int ymm = (xcr0 & 6) == 6, zmm = ymm && (xcr0 & 0xE0) == 0xE0;
    if (ymm && (ebx7 & (1u << 5)) && (ebx7 & (1u << 3)) && (ebx7 & (1u << 8))) f |= CC_CPU_AVX2; /* + BMI1, BMI2 */
    if ((f & CC_CPU_AVX2) && zmm && (ebx7 & (1u << 16)) && (ebx7 & (1u << 31)) && (ebx7 & (1u << 30)) &&
        (ebx7 & (1u << 17)) && (ebx7 & (1u << 28)))
        f |= CC_CPU_AVX512VL; /* F, VL, BW, DQ, CD */
    if ((f & CC_CPU_AVX512VL) && (ebx7 & (1u << 21))) f |= CC_CPU_IFMA;
    if ((ebx7 & (1u << 8)) && (ebx7 & (1u << 19))) f |= CC_CPU_BMI2_ADX;
    if (ebx7 & (1u << 8)) f |= CC_CPU_BMI2;
    if (ebx7 & (1u << 29)) f |= CC_CPU_SHANI;
    if ((f & CC_CPU_AVX512VL) && (ecx7 & (1u << 1))) f |= CC_CPU_VBMI;
    unsigned vb = 0, vc = 0, vd = 0, fam;
    __get_cpuid(0, &a, &vb, &vc, &vd);
    int amd = vb == 0x68747541 && vd == 0x69746e65 && vc == 0x444d4163; /* "AuthenticAMD" */
    __get_cpuid(1, &a, &b, &c, &d);
    fam = ((a >> 8) & 0xF) == 0xF ? ((a >> 8) & 0xF) + ((a >> 20) & 0xFF) : (a >> 8) & 0xF;
    /* AMD's AVX-512 parts (Zen 4 = family 19h, Zen 5 = 1Ah) run 512-bit integer work without the frequency-licence
     * drop Intel's do, so there the 16-lane zmm engine beats the 8-lane ymm one.  Intel always keeps the ymm engine. */
    if ((f & CC_CPU_AVX512VL) && amd && fam >= 0x19) f |= CC_CPU_FAST_ZMM;
    /* Zen 5 server and desktop parts (family 1Ah, models 00h-1Fh Turin, 40h-4Fh Granite Ridge) execute 512-bit ops
     * at full width, and SHA-NI there keeps only 2 sha256rnds2 in flight: groups of 11 or more messages run faster on
     * the zmm engine (x16: 128 vs 197 ns per 570-byte HMAC on Turin at 16 lanes).  Zen 4 and the 256-bit-datapath
     * Zen 5 mobile parts keep SHA-NI. */
    unsigned model = ((a >> 4) & 0xF) | (((a >> 8) & 0xF) == 0xF ? ((a >> 16) & 0xF) << 4 : 0);
    if ((f & CC_CPU_FAST_ZMM) && fam == 0x1A && (model < 0x20 || (model >= 0x40 && model < 0x50))) f |= CC_CPU_FULL_ZMM;
    /* Every Zen has SHA-NI, and there 4 interleaved SHA-NI streams beat every vector engine at every batch size
     * (Zen 2, 3 and 4 measured).  Intel's SHA-NI parts have not been timed, so they keep the vector engines. */
    if ((f & CC_CPU_SHANI) && amd) f |= CC_CPU_FAST_SHANI;
    /* Intel AVX-512 without SHA-NI (Skylake-SP, Cascade Lake, Cooper Lake): only 512-bit code reaches ipsec-mb's
     * multi-buffer HMAC there, and ipsec-mb itself runs its 16-lane AVX-512 kernel on these CPUs.  So groups of 9 or
     * more go to the x16 kernel (fewer stay on ymm), at the cost of the zmm frequency licence: on Cascade Lake, full
     * verify at batch 16 is ~2% slower and scalar code right after zmm runs slower for up to a millisecond.  Masking
     * CC_CPU_ZMM_HMAC keeps HS256 on ymm.  Intel's SHA-NI parts (Ice Lake and later) are unmeasured and unchanged. */
    if ((f & CC_CPU_AVX512VL) && !amd && !(f & CC_CPU_SHANI)) f |= CC_CPU_ZMM_HMAC;
    /* tests: JWT_CPU_FORCE_ZMM=1 claims FAST_ZMM on any AVX-512 CPU, to exercise that dispatch on Intel hardware */
    const char *fz = cc_env("CC_CPU_FORCE_ZMM", "JWT_CPU_FORCE_ZMM");
    if ((f & CC_CPU_AVX512VL) && fz && *fz == '1') f |= CC_CPU_FAST_ZMM;
#elif defined(CC_ARM_SHA2)
#if defined(__APPLE__)
    int v = 0;
    size_t vl = sizeof v;
    if (!sysctlbyname("hw.optional.arm.FEAT_SHA256", &v, &vl, NULL, 0) && v) f |= CC_CPU_SHA2;
    v = 0, vl = sizeof v;
    if (!sysctlbyname("hw.optional.arm.FEAT_SHA512", &v, &vl, NULL, 0) && v) f |= CC_CPU_SHA512;
#elif defined(__linux__)
    unsigned long hw = getauxval(AT_HWCAP);
    if (hw & (1ul << 6)) f |= CC_CPU_SHA2;    /* HWCAP_SHA2 */
    if (hw & (1ul << 21)) f |= CC_CPU_SHA512; /* HWCAP_SHA512 */
#elif defined(__ARM_FEATURE_SHA2)
    f |= CC_CPU_SHA2;
#endif
#endif
    const char *mask = cc_env("CC_CPU_MASK", "JWT_CPU_MASK"); /* tests and benchmarks: pretend features are missing */
    if (mask && *mask) f &= (unsigned)strtoul(mask, NULL, 0) | CC_CPU_DETECTED;
    __atomic_store_n(&cc_cpu_bits, f, __ATOMIC_RELAXED); /* every racing writer stores the same value */
}
static unsigned cc_cpu(void) {
    unsigned f = __atomic_load_n(&cc_cpu_bits, __ATOMIC_RELAXED);
    if (!f) cc_cpu_init(), f = __atomic_load_n(&cc_cpu_bits, __ATOMIC_RELAXED); /* called before constructors ran */
    return f;
}

unsigned cc_cpu_features(void) { return cc_cpu() & ~CC_CPU_DETECTED; }

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

/* The inner hash continues from the ipad midstate over msg (L bytes), so its total length is
 * 64 + L and it needs nb = ceil((L + 9) / 64) more blocks: nf of them straight out of msg, the
 * rest (1 or 2) from `tail`, which holds the leftover bytes, 0x80, zeros and the bit length. */
typedef struct {
    const uint8_t *m;
    int nf, nb;
    uint8_t tail[128];
} hplan_t;

/* off = bytes already hashed before m: 64 (the ipad block) for HMAC, 0 for a plain SHA-256 */
CC_INLINE void hplan_init_off(hplan_t *p, const uint8_t *m, int L, int off) {
    int nf = L >> 6, rem = L & 63, nt = rem + 9 > 64 ? 2 : 1;
    uint64_t bits = (uint64_t)(off + L) * 8;
    p->m = m, p->nf = nf, p->nb = nf + nt;
#ifdef CC_INPUT_PADDED
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

CC_INLINE const uint8_t *hplan_block(const hplan_t *p, int b) {
    return b < p->nf ? p->m + (b << 6) : p->tail + ((b - p->nf) << 6);
}

static void hmac1_scalar(const cc_hmac_key_t *k, const hplan_t *p, uint32_t mac[8]);
static void sha1_raw(const hplan_t *p, uint32_t dig[8]);
/* plain SHA-256 runs the HMAC machinery from the IV, with no ipad block and no outer hash (raw mode) */
static const cc_hmac_key_t sha_iv_key = {
    { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }, { 0 }
};

/* ======================================================================================
 * 2. SHA-256 engines
 * ====================================================================================== */

/* vpternlogd truth tables (index = a<<2 | b<<1 | c), used by the AVX-512 engine and test.c */
#define CC_TL_XOR3 0x96 /* a ^ b ^ c */
#define CC_TL_CH   0xCA /* a ? b : c */
#define CC_TL_MAJ  0xE8 /* majority */

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
#include "cc_mb.inc"
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

#if defined(CC_OSSL_SHA256) && defined(__x86_64__) && defined(__ELF__)
/* ---- single-stream x86-64: OpenSSL's sha256_block_data_order, extracted (crypto/src/sha256_x86_64_ossl.S) ----
 * Batch 1 and the lanes a vector group leaves over run one message at a time, where OpenSSL's hand-scheduled
 * AVX2+BMI2 code (2 blocks interleaved, rorx) beats the compiled scalar template: 763 vs 1,015 ns per HMAC on a
 * Xeon Platinum 8260.  It dispatches on cc_ossl_ia32cap_P, laid out like OpenSSL's OPENSSL_ia32cap_P for the bits
 * that code reads: word 0 bit 30 "Intel CPU", word 1 = CPUID.1:ECX (SSSE3, AVX), word 2 = CPUID.7.0:EBX (BMI1,
 * AVX2, BMI2, SHA).  AVX and AVX2 are cleared unless the OS saves ymm state (XCR0). */
#include <cpuid.h>
void cc_ossl_sha256_block(uint32_t h[8], const void *blocks, size_t n);
#endif
#if (defined(CC_OSSL_SHA256) || defined(CC_OSSL_MONT)) && defined(__x86_64__) && defined(__ELF__)
/* the capability word OpenSSL's extracted asm dispatches on (SHA-256 above; bn_mul_mont reads word 2's BMI2 + ADX) */
#include <cpuid.h>
__attribute__((visibility("hidden"))) unsigned int cc_ossl_ia32cap_P[4];
__attribute__((constructor)) static void cc_ossl_cap_init(void) {
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
    cc_ossl_ia32cap_P[0] = w0, cc_ossl_ia32cap_P[1] = w1, cc_ossl_ia32cap_P[2] = w2;
}
#endif
#if defined(CC_OSSL_SHA256) && defined(__x86_64__) && defined(__ELF__)
static void hmac1_scalar(const cc_hmac_key_t *k, const hplan_t *p, uint32_t mac[8]) {
    uint32_t st[8];
    uint8_t ob[64] = { 0 };
    memcpy(st, k->ih, 32);
    if (p->nf) cc_ossl_sha256_block(st, p->m, (size_t)p->nf);
    cc_ossl_sha256_block(st, p->tail, (size_t)(p->nb - p->nf));
    for (int i = 0; i < 8; i++)
        ob[4 * i] = st[i] >> 24, ob[4 * i + 1] = st[i] >> 16, ob[4 * i + 2] = st[i] >> 8, ob[4 * i + 3] = st[i];
    ob[32] = 0x80, ob[62] = ((64 + 32) * 8) >> 8, ob[63] = (uint8_t)((64 + 32) * 8);
    memcpy(mac, k->oh, 32);
    cc_ossl_sha256_block(mac, ob, 1);
}
static void sha1_raw(const hplan_t *p, uint32_t dig[8]) {
    memcpy(dig, sha_iv_key.ih, 32);
    if (p->nf) cc_ossl_sha256_block(dig, p->m, (size_t)p->nf);
    cc_ossl_sha256_block(dig, p->tail, (size_t)(p->nb - p->nf));
}
/* every message one at a time through the extracted block function (tests, benchmarks) */
void cc_hmac_sha256_ossl(const cc_hmac_key_t *k, int n, const uint8_t *const *msg, const int *len, uint32_t (*mac)[8]) {
    for (int i = 0; i < n; i++) {
        hplan_t p;
        hplan_init(&p, msg[i], len[i]);
        hmac1_scalar(k, &p, mac[i]);
    }
}
#else
static void hmac1_scalar(const cc_hmac_key_t *k, const hplan_t *p, uint32_t mac[8]) {
    const hplan_t *pp = p;
    lanes_scalar(k, 1, &pp, (uint32_t(*)[8])mac);
}
static void sha1_raw(const hplan_t *p, uint32_t dig[8]) {
    const hplan_t *pp = p;
    lanes_raw_scalar(1, &pp, (uint32_t(*)[8])dig);
}
#endif

void cc_hmac_key_init(cc_hmac_key_t *k, const void *secret, size_t len) {
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
#ifdef CC_HAVE_NEON
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
CC_INLINE void neon_tr4(uint32x4_t r0, uint32x4_t r1, uint32x4_t r2, uint32x4_t r3, uint32x4_t *o) {
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
#include "cc_mb.inc"
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
#if defined(CC_X86)
CC_BEGIN_AVX2
CC_INLINE void avx2_tr8(const __m256i *r, __m256i *o) {
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
#define MB_LANES         8
#define V                __m256i
#define VSET1(x)         _mm256_set1_epi32((int)(x))
#define VADD(a, b)       _mm256_add_epi32(a, b)
#define VXOR(a, b)       _mm256_xor_si256(a, b)
#define VSHR(x, n)       _mm256_srli_epi32(x, n)
#define VMASK(arr)       _mm256_loadu_si256((const __m256i *)(arr))
#define CC_AVX_MIN_LANES 2
/* AVX2 alone: with OpenSSL's single-stream code for leftovers, 2 messages one at a time (2 x 753 ns) beat one
 * 2-lane AVX2 group (822 ns) on a Xeon Platinum 8260; from 3 lanes the vector wins (555 ns) */
#if defined(CC_OSSL_SHA256) && defined(__x86_64__) && defined(__ELF__)
#define CC_AVX2_MIN_LANES 3
#else
#define CC_AVX2_MIN_LANES CC_AVX_MIN_LANES
#endif
#define MB_MIN_LANES CC_AVX2_MIN_LANES

#define MB(name)       name##_avx2
#define VROR(x, n)     _mm256_or_si256(_mm256_srli_epi32(x, n), _mm256_slli_epi32(x, 32 - (n)))
#define VXOR3(a, b, c) _mm256_xor_si256(_mm256_xor_si256(a, b), c)
#define VCH(e, f, g)   _mm256_xor_si256(g, _mm256_and_si256(e, _mm256_xor_si256(f, g)))
/* Maj = b ^ ((a ^ b) & (b ^ c)): b ^ c is the previous round's a ^ b, which the fully unrolled
 * compress lets the compiler reuse, so 2 new ops per round instead of 4 (trick from cpuminer-opt) */
#define VMAJ(a, b, c)  _mm256_xor_si256(b, _mm256_and_si256(_mm256_xor_si256(a, b), _mm256_xor_si256(b, c)))
#define VSEL(m, x, y)  _mm256_blendv_epi8(y, x, m)
#include "cc_mb.inc"
#undef MB
#undef VROR
#undef VXOR3
#undef VCH
#undef VMAJ
#undef VSEL

#if 1 /* AVX-512VL, compiled in its own target region */
CC_END_TARGET
CC_BEGIN_AVX512
/* Identical to the AVX2 instantiation except for these five macros (tested on a Xeon Platinum 8260).
 * vpternlogd immediates (truth table index = a<<2 | b<<1 | c):
 *   0x96 = a^b^c, 0xCA = a ? b : c (Ch, and the lane select), 0xE8 = majority.
 * tests/test_jwt.c runs the template with a scalar ternlog emulation using these same constants. */
#undef MB_MIN_LANES
#define MB_MIN_LANES   CC_AVX_MIN_LANES
#define MB(name)       name##_avx512
#define VROR(x, n)     _mm256_ror_epi32(x, n) /* vprord */
#define VXOR3(a, b, c) _mm256_ternarylogic_epi32(a, b, c, CC_TL_XOR3)
#define VCH(e, f, g)   _mm256_ternarylogic_epi32(e, f, g, CC_TL_CH)
#define VMAJ(a, b, c)  _mm256_ternarylogic_epi32(a, b, c, CC_TL_MAJ)
#define VSEL(m, x, y)  _mm256_ternarylogic_epi32(m, x, y, CC_TL_CH)
#include "cc_mb.inc"
#undef MB
#undef VROR
#undef VXOR3
#undef VCH
#undef VMAJ
#undef VSEL
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

/* driver for the zmm engine: full 16-groups go to zmm, smaller ones to the 8-lane engine, or one at a time below 2.
 * It stays out of the AVX-512 region, calls both engines through pointers and is never inlined: merged into one
 * function with the zmm code, a batch of 8 ran 19% slower on a Xeon Platinum 8260 (512-bit frequency licence). */
CC_END_TARGET
CC_BEGIN_AVX2
typedef void lanes_fn(const cc_hmac_key_t *, int, const hplan_t *const *, uint32_t (*)[8]);
__attribute__((noinline)) static void zmm_drive(lanes_fn *l16, lanes_fn *l8, const cc_hmac_key_t *k, int n,
                                                const uint8_t *const *msg, const int *len, uint32_t (*mac)[8]) {
    enum { CH = 64, ZMM_MIN = 9 }; /* <= 8 live lanes: a single 8-lane group is cheaper */
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
            if (nl >= ZMM_MIN) {
                if (nl > 16) nl = 16;
                l16(k, nl, &pp[g], tmp);
            } else {
                if (nl > 8) nl = 8;
                if (nl < CC_AVX_MIN_LANES) {
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
CC_END_TARGET
CC_BEGIN_AVX512

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
#define VXOR3(a, b, c) _mm512_ternarylogic_epi32(a, b, c, CC_TL_XOR3)
#define VCH(e, f, g)   _mm512_ternarylogic_epi32(e, f, g, CC_TL_CH)
#define VMAJ(a, b, c)  _mm512_ternarylogic_epi32(a, b, c, CC_TL_MAJ)
#define VSEL(m, x, y)  _mm512_ternarylogic_epi32(m, x, y, CC_TL_CH)
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
#include "cc_mb.inc"
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
void cc_hmac_sha256_zmm(const cc_hmac_key_t *k, int n, const uint8_t *const *msg, const int *len, uint32_t (*mac)[8]) {
    zmm_drive(lanes_zmm, lanes_avx512, k, n, msg, len, mac);
}
#if defined(CC_SHANI_MB) && defined(__ELF__)
/* ---- zmm, 16 lanes, in assembly: crypto/src/sha256_x16_avx512.S (scripts/gen-sha256-x16.py), a GAS port of Intel
 * ipsec-mb's sha256_x16_avx512 (BSD-3-Clause): the schedule in zmm16-31, the next block's rows loaded during rounds
 * 48-63.  st[j] holds state word j of the 16 lanes; blk is nb * 16 block pointers, block-major; _rows takes one block
 * already transposed (w[t] = word t of every lane). */
void cc_sha256_x16(uint32_t st[8][16], const uint8_t *const *blk, size_t nb);
void cc_sha256_x16_rows(uint32_t st[8][16], const uint32_t w[16][16]);
static void lanes_x16(const cc_hmac_key_t *k, int nl, const hplan_t *const *pl, uint32_t (*mac)[8]) {
    enum { CB = 16 }; /* blocks per kernel call */
    uint32_t st[8][16] __attribute__((aligned(64))), w[16][16] __attribute__((aligned(64)));
    const uint8_t *blk[CB * 16];
    int nb[16], maxnb = 0, ragged = 0;
    for (int l = 0; l < 16; l++) {
        nb[l] = l < nl ? pl[l]->nb : 0;
        if (nb[l] > maxnb) maxnb = nb[l];
    }
    for (int l = 0; l < nl; l++) ragged |= nb[l] != maxnb;
    for (int i = 0; i < 8; i++) _mm512_store_si512(st[i], _mm512_set1_epi32((int)k->ih[i]));
    if (!ragged) {
        for (int b0 = 0; b0 < maxnb; b0 += CB) {
            int c = maxnb - b0 < CB ? maxnb - b0 : CB;
            for (int b = 0; b < c; b++)
                for (int l = 0; l < 16; l++) blk[16 * b + l] = l < nl ? hplan_block(pl[l], b0 + b) : zero_block;
            cc_sha256_x16(st, blk, (size_t)c);
        }
    } else { /* block by block; lanes that ran out keep their state */
        for (int b = 0; b < maxnb; b++) {
            __m512i old[8];
            __mmask16 live = 0;
            for (int l = 0; l < 16; l++) {
                int on = b < nb[l];
                live |= (__mmask16)(on << l);
                blk[l] = on ? hplan_block(pl[l], b) : zero_block;
            }
            for (int i = 0; i < 8; i++) old[i] = _mm512_load_si512(st[i]);
            cc_sha256_x16(st, blk, 1);
            for (int i = 0; i < 8; i++)
                _mm512_store_si512(st[i], _mm512_mask_blend_epi32(live, old[i], _mm512_load_si512(st[i])));
        }
    }
    /* outer hash: one block = inner digest || 0x80 || zeros || bitlen(64 + 32), already in row form */
    for (int i = 0; i < 8; i++) _mm512_store_si512(w[i], _mm512_load_si512(st[i]));
    _mm512_store_si512(w[8], _mm512_set1_epi32((int)0x80000000u));
    for (int i = 9; i < 15; i++) _mm512_store_si512(w[i], _mm512_setzero_si512());
    _mm512_store_si512(w[15], _mm512_set1_epi32((64 + 32) * 8));
    for (int i = 0; i < 8; i++) _mm512_store_si512(st[i], _mm512_set1_epi32((int)k->oh[i]));
    cc_sha256_x16_rows(st, (const uint32_t(*)[16])w);
    for (int l = 0; l < nl; l++)
        for (int j = 0; j < 8; j++) mac[l][j] = st[j][l];
}
void cc_hmac_sha256_x16(const cc_hmac_key_t *k, int n, const uint8_t *const *msg, const int *len, uint32_t (*mac)[8]) {
    zmm_drive(lanes_x16, lanes_avx512, k, n, msg, len, mac);
}
#endif
CC_END_TARGET /* the AVX-512 region ends the AVX2 one too */
#endif
#endif /* AVX2 */

/* ---- ARMv8 SHA2 instructions: S independent streams interleaved for latency hiding ---- */
#if defined(CC_ARM_SHA2)
    CC_BEGIN_SHA2
        /* 64 rounds on S streams; m[s][0..3] are the 16 message words (host order) of stream s. */
        CC_INLINE void
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
CC_INLINE void ce_hmac(int S, int raw, const cc_hmac_key_t *k, const hplan_t *const *p, uint32_t *const *mac) {
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

CC_INLINE void ce_drive_x(int S, int raw, const cc_hmac_key_t *k, int n, const uint8_t *const *msg, const int *len,
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
static void ce_drive(int S, const cc_hmac_key_t *k, int n, const uint8_t *const *msg, const int *len,
                     uint32_t (*mac)[8]) {
    ce_drive_x(S, 0, k, n, msg, len, mac);
}
void cc_sha256_sha2(int n, const uint8_t *const *msg, const int *len, uint32_t (*dig)[8]) {
    ce_drive_x(4, 1, &sha_iv_key, n, msg, len, dig);
}

void cc_hmac_sha256_sha2_1(const cc_hmac_key_t *k, int n, const uint8_t *const *msg, const int *len,
                           uint32_t (*mac)[8]) {
    ce_drive(1, k, n, msg, len, mac);
}
void cc_hmac_sha256_sha2(const cc_hmac_key_t *k, int n, const uint8_t *const *msg, const int *len, uint32_t (*mac)[8]) {
    ce_drive(4, k, n, msg, len, mac); /* 4 streams: 15% faster than 1 on an M5 */
}
void cc_hmac_sha256_sha2_2(const cc_hmac_key_t *k, int n, const uint8_t *const *msg, const int *len,
                           uint32_t (*mac)[8]) {
    ce_drive(2, k, n, msg, len, mac);
}
CC_END_SHA2
#endif /* SHA2 */

/* ---- x86 SHA-NI: S independent streams interleaved for latency hiding (the ARM engine's layout) ----
 * Every Zen has SHA-NI; Cascade Lake doesn't, so there this code is compiled and never picked.  The state lives as
 * ABEF / CDGH (the order sha256rnds2 wants); ni_ld / ni_st convert from / to the natural h0..h7. */
#if defined(CC_X86)
#if defined(__clang__)
#define CC_BEGIN_SHANI                                                                                                 \
    _Pragma("clang attribute push (__attribute__((target(\"sha,sse4.1,ssse3\"))), apply_to = function)")
#else
#define CC_BEGIN_SHANI _Pragma("GCC push_options") _Pragma("GCC target(\"sha,sse4.1,ssse3\")")
#endif
CC_BEGIN_SHANI
CC_INLINE void ni_ld(const uint32_t h[8], __m128i *abef, __m128i *cdgh) {
    __m128i t = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i *)h), 0xB1);       /* CDAB */
    __m128i u = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i *)(h + 4)), 0x1B); /* EFGH */
    *abef = _mm_alignr_epi8(t, u, 8);
    *cdgh = _mm_blend_epi16(u, t, 0xF0);
}
CC_INLINE void ni_st(__m128i abef, __m128i cdgh, uint32_t h[8]) {
    __m128i t = _mm_shuffle_epi32(abef, 0x1B), u = _mm_shuffle_epi32(cdgh, 0xB1); /* FEBA, DCHG */
    _mm_storeu_si128((__m128i *)h, _mm_blend_epi16(t, u, 0xF0));                  /* DCBA */
    _mm_storeu_si128((__m128i *)(h + 4), _mm_alignr_epi8(u, t, 8));               /* HGFE */
}
/* 64 rounds on S streams; m[s][0..3] are the 16 message words (host order) of stream s. */
CC_INLINE void ni_compress(int S, __m128i *st0, __m128i *st1, __m128i (*m)[4]) {
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
CC_INLINE void ni_hmac(int S, int raw, const cc_hmac_key_t *k, const hplan_t *const *p, uint32_t *const *mac) {
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
CC_INLINE void ni_drive_x(int S, int raw, const cc_hmac_key_t *k, int n, const uint8_t *const *msg, const int *len,
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
            /* five left with one block count: 3 + 2 streams, not 4 + a latency-bound single stream */
            if (s == 4 && m - g == 5 && pp[g + 4]->nb == pp[g]->nb) s = 3;
            uint32_t *out[4];
            for (int i = 0; i < s; i++) out[i] = mac[base + (int)(pp[g + i] - plan)];
            switch (s) { /* constant S per call so ni_hmac fully specialises */
                case 4: ni_hmac(4, raw, k, pp + g, out); break;
                case 3: ni_hmac(3, raw, k, pp + g, out); break;
                case 2: ni_hmac(2, raw, k, pp + g, out); break;
                default: ni_hmac(1, raw, k, pp + g, out); break;
            }
            g += s;
        }
    }
}
void cc_hmac_sha256_shani_1(const cc_hmac_key_t *k, int n, const uint8_t *const *msg, const int *len,
                            uint32_t (*mac)[8]) {
    ni_drive_x(1, 0, k, n, msg, len, mac);
}
void cc_hmac_sha256_shani_2(const cc_hmac_key_t *k, int n, const uint8_t *const *msg, const int *len,
                            uint32_t (*mac)[8]) {
    ni_drive_x(2, 0, k, n, msg, len, mac);
}
void cc_hmac_sha256_shani_4(const cc_hmac_key_t *k, int n, const uint8_t *const *msg, const int *len,
                            uint32_t (*mac)[8]) {
    ni_drive_x(4, 0, k, n, msg, len, mac);
}

#if defined(CC_SHANI_MB) && defined(__ELF__)
/* ---- SHA-NI multi-stream assembly: generated 3/4-stream kernels (crypto/src/sha256_shani_mb.S, scripts/gen-shani-mb.py)
 * cc_shani_mbS keeps all 2S state registers resident and the older message groups in a stack ring, so nothing on a
 * stream's dependency chain goes through memory (the compiled ni_compress spills the state at S = 4: ~1,070 stack
 * accesses per 960 sha256rnds2).  st is ABEF / CDGH per stream; blk is nb * S block pointers, block-major. */
void cc_shani_mb3(__m128i *st, const uint8_t *const *blk, size_t nb);
void cc_shani_mb4(__m128i *st, const uint8_t *const *blk, size_t nb);

/* the outer block of HMAC: the inner digest (big-endian), 0x80, zeros, the bit length 768 */
CC_INLINE void hmac_outer_block(const uint32_t d[8], uint8_t ob[64]) {
    const __m128i bswap = _mm_set_epi64x(0x0c0d0e0f08090a0bLL, 0x0405060700010203LL);
    _mm_storeu_si128((__m128i *)ob, _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)d), bswap));
    _mm_storeu_si128((__m128i *)(ob + 16), _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(d + 4)), bswap));
    _mm_storeu_si128((__m128i *)(ob + 32), _mm_set_epi32(0, 0, 0, 0x80));
    _mm_storeu_si128((__m128i *)(ob + 48), _mm_set_epi32(0x00030000, 0, 0, 0)); /* ob[62] = 0x03: 768 bits */
}
CC_INLINE void mb_blocks(int S, __m128i *st, const uint8_t *const *blk, size_t nb) {
    if (S == 4) cc_shani_mb4(st, blk, nb);
    else cc_shani_mb3(st, blk, nb);
}
/* S = 3 or 4 plans with identical nb, through cc_shani_mbS */
CC_INLINE void mb_hmac(int S, const cc_hmac_key_t *k, const hplan_t *const *p, uint32_t *const *mac) {
    enum { CB = 16 }; /* blocks per kernel call: the pointer array stays small for long messages */
    const uint8_t *blk[CB * 4];
    __m128i st[8], ih0, ih1, oh0, oh1;
    ni_ld(k->ih, &ih0, &ih1);
    for (int s = 0; s < S; s++) st[2 * s] = ih0, st[2 * s + 1] = ih1;
    for (int b0 = 0, nb = p[0]->nb; b0 < nb; b0 += CB) {
        int c = nb - b0 < CB ? nb - b0 : CB;
        for (int b = 0; b < c; b++)
            for (int s = 0; s < S; s++) blk[b * S + s] = hplan_block(p[s], b0 + b);
        mb_blocks(S, st, blk, (size_t)c);
    }
    uint8_t ob[4][64];
    ni_ld(k->oh, &oh0, &oh1);
    for (int s = 0; s < S; s++) {
        uint32_t d[8];
        ni_st(st[2 * s], st[2 * s + 1], d);
        hmac_outer_block(d, ob[s]);
        blk[s] = ob[s], st[2 * s] = oh0, st[2 * s + 1] = oh1;
    }
    mb_blocks(S, st, blk, 1);
    for (int s = 0; s < S; s++) ni_st(st[2 * s], st[2 * s + 1], mac[s]);
}
/* ni_drive_x's grouping (up to 4 same-length plans, 5 left as 3 + 2) with the asm kernels for 3 and 4 streams.  Two
 * streams fit in registers compiled, and ni_hmac(2) is 1.5-2% faster there than a 2-stream asm kernel; one stream
 * is latency-bound either way. */
static void mb_drive(const cc_hmac_key_t *k, int n, const uint8_t *const *msg, const int *len, uint32_t (*mac)[8]) {
    enum { CH = 64 };
    hplan_t plan[CH];
    const hplan_t *pp[CH];
    for (int base = 0; base < n; base += CH) {
        int m = n - base < CH ? n - base : CH;
        for (int i = 0; i < m; i++) hplan_init(&plan[i], msg[base + i], len[base + i]);
        for (int i = 0; i < m; i++) { /* sort by nb so groups share a block count */
            const hplan_t *p = &plan[i];
            int j = i;
            while (j > 0 && pp[j - 1]->nb > p->nb) pp[j] = pp[j - 1], j--;
            pp[j] = p;
        }
        int g = 0;
        while (g < m) {
            int s = 4;
            if (m - g < s) s = m - g;
            for (int i = 1; i < s; i++)
                if (pp[g + i]->nb != pp[g]->nb) {
                    s = i;
                    break;
                }
            if (s == 4 && m - g == 5 && pp[g + 4]->nb == pp[g]->nb) s = 3;
            uint32_t *out[4];
            for (int i = 0; i < s; i++) out[i] = mac[base + (int)(pp[g + i] - plan)];
            if (s == 4) mb_hmac(4, k, pp + g, out);
            else if (s == 3) mb_hmac(3, k, pp + g, out);
            else if (s == 2) ni_hmac(2, 0, k, pp + g, out);
            else ni_hmac(1, 0, k, pp + g, out);
            g += s;
        }
    }
}
void cc_hmac_sha256_shani_4r(const cc_hmac_key_t *k, int n, const uint8_t *const *msg, const int *len,
                             uint32_t (*mac)[8]) {
    /* no group of 3 or 4 possible: the compiled engine itself, so batches 1 and 2 run the very same machine code (a
     * second inlined copy of ni_hmac(2) here measured 1.5-4% slower at batch 2 on Zen 2/3, from code placement) */
    if (n <= 2) return cc_hmac_sha256_shani_4(k, n, msg, len, mac);
    mb_drive(k, n, msg, len, mac);
}
/* CC_CPU_FULL_ZMM (Zen 5): groups of CC_X16_MIN..16 messages on the 16-lane x16 kernel, the rest on shani-4r.  A
 * 16-lane group costs the same with fewer live lanes, and x16 at 16 lanes is 1.54x shani-4r on Turin, so it pays from
 * 11 messages up. */
#ifndef CC_X16_MIN
#define CC_X16_MIN 11
#endif
void cc_hmac_sha256_shani_x16(const cc_hmac_key_t *k, int n, const uint8_t *const *msg, const int *len,
                              uint32_t (*mac)[8]) {
    int done = 0;
    while (n - done >= CC_X16_MIN) {
        int m = n - done < 16 ? n - done : 16;
        cc_hmac_sha256_x16(k, m, msg + done, len + done, mac + done);
        done += m;
    }
    if (n > done) cc_hmac_sha256_shani_4r(k, n - done, msg + done, len + done, mac + done);
}
#endif /* CC_SHANI_MB */
CC_END_TARGET
#endif /* SHA-NI */

/* ======================================================================================
 * 3. engine choice
 * ====================================================================================== */

/* the best engine this CPU has (run-time dispatch; see the top of the file) */
static cc_hmac_fn *hmac_default(void) {
    unsigned f = cc_cpu();
    (void)f;
#if defined(CC_ARM_SHA2)
    if (f & CC_CPU_SHA2) return cc_hmac_sha256_sha2;
#endif
#if defined(CC_X86)
    /* each derived bit (FAST_SHANI, FULL_ZMM, FAST_ZMM) is tested with the feature it needs, so that JWT_CPU_MASK can
     * take SHA-NI or AVX-512 away on its own */
    const int shani = (f & CC_CPU_FAST_SHANI) && (f & CC_CPU_SHANI);
#if defined(CC_SHANI_MB) && defined(__ELF__)
    if (shani && (f & CC_CPU_FULL_ZMM) && (f & CC_CPU_AVX512VL))
        return cc_hmac_sha256_shani_x16;       /* Zen 5: x16 for >= 11 */
    if (shani) return cc_hmac_sha256_shani_4r; /* every Zen: 4 SHA-NI streams, hand-scheduled */
#endif
    if (shani) return cc_hmac_sha256_shani_4; /* every Zen: 4 interleaved SHA-NI streams */
#if defined(CC_SHANI_MB) && defined(__ELF__)
    if ((f & CC_CPU_FAST_ZMM) && (f & CC_CPU_AVX512VL)) return cc_hmac_sha256_x16; /* 16 lanes, asm; < 9 live -> ymm */
    if ((f & CC_CPU_ZMM_HMAC) && (f & CC_CPU_AVX512VL)) return cc_hmac_sha256_x16; /* Intel, no SHA-NI: zmm for 9+ */
#endif
    if ((f & CC_CPU_FAST_ZMM) && (f & CC_CPU_AVX512VL))
        return cc_hmac_sha256_zmm; /* 16 lanes; < 9 live -> 8-lane ymm */
    if (f & CC_CPU_AVX512VL) return cc_hmac_sha256_avx512;
    if (f & CC_CPU_AVX2) return cc_hmac_sha256_avx2;
#endif
#if defined(CC_HAVE_NEON)
    return cc_hmac_sha256_neon;
#else
    return cc_hmac_sha256_scalar;
#endif
}
static cc_sha256_fn *sha256_default(void) {
    unsigned f = cc_cpu();
    (void)f;
#if defined(CC_ARM_SHA2)
    if (f & CC_CPU_SHA2) return cc_sha256_sha2;
#endif
#if defined(CC_X86)
    if (f & CC_CPU_AVX512VL) return cc_sha256_avx512;
    if (f & CC_CPU_AVX2) return cc_sha256_avx2;
#endif
#if defined(CC_HAVE_NEON)
    return cc_sha256_neon;
#else
    return cc_sha256_scalar;
#endif
}
const char *cc_engine(void) {
    cc_hmac_fn *h = hmac_default();
#if defined(CC_ARM_SHA2)
    if (h == cc_hmac_sha256_sha2) return "sha2";
#endif
#if defined(CC_X86)
    if (h == cc_hmac_sha256_shani_4) return "shani";
#if defined(CC_SHANI_MB) && defined(__ELF__)
    if (h == cc_hmac_sha256_shani_4r) return "shani";
    if (h == cc_hmac_sha256_shani_x16) return "shani+zmm";
    if (h == cc_hmac_sha256_x16) return "zmm";
#endif
    if (h == cc_hmac_sha256_zmm) return "zmm";
    if (h == cc_hmac_sha256_avx512) return "avx512vl";
    if (h == cc_hmac_sha256_avx2) return "avx2";
#endif
#if defined(CC_HAVE_NEON)
    if (h == cc_hmac_sha256_neon) return "neon";
#endif
    return "scalar";
}

static void hmac_resolve(const cc_hmac_key_t *k, int n, const uint8_t *const *msg, const int *len, uint32_t (*mac)[8]);
static void sha256_resolve(int n, const uint8_t *const *msg, const int *len, uint32_t (*dig)[8]);
CC_HIDDEN cc_hmac_fn *cc__hmac_impl = hmac_resolve; /* the JWT layer calls through it too */
static cc_sha256_fn *sha256_impl = sha256_resolve;
static void hmac_resolve(const cc_hmac_key_t *k, int n, const uint8_t *const *msg, const int *len, uint32_t (*mac)[8]) {
    cc_hmac_fn *f = hmac_default();
    CC_STORE_FN(cc__hmac_impl, f);
    f(k, n, msg, len, mac);
}
static void sha256_resolve(int n, const uint8_t *const *msg, const int *len, uint32_t (*dig)[8]) {
    cc_sha256_fn *f = sha256_default();
    CC_STORE_FN(sha256_impl, f);
    f(n, msg, len, dig);
}
/* at load time: pick everything once, before any call */
__attribute__((constructor)) static void cc_resolve_all(void) {
    CC_STORE_FN(cc__hmac_impl, hmac_default());
    CC_STORE_FN(sha256_impl, sha256_default());
}

/* plain SHA-256 of n messages on the default engine (the RS256 / ES256 signing inputs) */
void cc_sha256_batch(int n, const uint8_t *const *msg, const int *len, uint32_t (*dig)[8]) {
    CC_LOAD_FN(sha256_impl)(n, msg, len, dig);
}

/* ---- the rest of the public API: dispatched HMAC, byte output, constant-time compares ---- */
void cc_hmac_sha256_batch(const cc_hmac_key_t *k, int n, const uint8_t *const *msg, const int *len,
                          uint32_t (*mac)[8]) {
    CC_LOAD_FN(cc__hmac_impl)(k, n, msg, len, mac);
}
CC_INLINE void cc_store_be8(uint8_t o[32], const uint32_t w[8]) {
    for (int j = 0; j < 8; j++) {
        uint32_t v = __builtin_bswap32(w[j]);
        memcpy(o + 4 * j, &v, 4);
    }
}
enum { CC_CHUNK = 64 }; /* messages per engine call in the byte-output and verify forms (stack buffers) */
void cc_sha256_bytes(int n, const uint8_t *const *msg, const int *len, uint8_t (*dig)[32]) {
    uint32_t w[CC_CHUNK][8];
    for (int b = 0; b < n; b += CC_CHUNK) {
        int m = n - b < CC_CHUNK ? n - b : CC_CHUNK;
        CC_LOAD_FN(sha256_impl)(m, msg + b, len + b, w);
        for (int i = 0; i < m; i++) cc_store_be8(dig[b + i], w[i]);
    }
}
void cc_hmac_sha256_bytes(const cc_hmac_key_t *k, int n, const uint8_t *const *msg, const int *len,
                          uint8_t (*mac)[32]) {
    uint32_t w[CC_CHUNK][8];
    for (int b = 0; b < n; b += CC_CHUNK) {
        int m = n - b < CC_CHUNK ? n - b : CC_CHUNK;
        CC_LOAD_FN(cc__hmac_impl)(k, m, msg + b, len + b, w);
        for (int i = 0; i < m; i++) cc_store_be8(mac[b + i], w[i]);
    }
}
int cc_hmac_sha256_verify(const cc_hmac_key_t *k, int n, const uint8_t *const *msg, const int *len,
                          const uint8_t (*tag)[32], uint8_t *ok) {
    uint32_t w[CC_CHUNK][8], t[8];
    int good = 0;
    for (int b = 0; b < n; b += CC_CHUNK) {
        int m = n - b < CC_CHUNK ? n - b : CC_CHUNK;
        CC_LOAD_FN(cc__hmac_impl)(k, m, msg + b, len + b, w);
        for (int i = 0; i < m; i++) {
            for (int j = 0; j < 8; j++) t[j] = be32(tag[b + i] + 4 * j);
            int e = cc_is_zero32(cc_mac_diff8(w[i], t));
            ok[b + i] = (uint8_t)e, good += e;
        }
    }
    return good;
}
int cc_tag_eq32(const void *a, const void *b) {
    const uint8_t *x = a, *y = b;
    uint32_t d = 0;
    for (int i = 0; i < 32; i++) d |= (uint32_t)(x[i] ^ y[i]);
    return cc_is_zero32(cc_opaque32(d));
}
