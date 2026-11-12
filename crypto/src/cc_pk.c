/* cc_pk.c — RS256, ES256 (and, via cc_ed25519.inc, EdDSA) verification, #included by cursed_crypto.c unless
 * -DJWT_NO_PK.
 *
 * Neither algorithm batches the way HMAC does: one P-256 or RSA-2048 verify is 10-100x the cost of the whole
 * HS256 pipeline, and SIMD across tokens needs 52-bit multipliers (AVX-512 IFMA) that Cascade Lake lacks.
 * What a verifier with a long-lived key *can* exploit is that the key is fixed (PK.md has the numbers):
 *
 *   ES256  R = u1*G + u2*Q.  OpenSSL precomputes a comb table for G only; Q is a variable base (~256
 *          doublings).  Here key setup builds a signed-digit comb table for Q as well, so a verify is two
 *          fixed-base multiplications: 2 * ceil(257/W) mixed additions and no doublings.  The x-coordinate
 *          check is done projectively (X == r * Z^2), so there is no field inversion per token, and the
 *          s^-1 of a whole batch share one inversion (Montgomery's trick).
 *          Field and scalar arithmetic: fiat-crypto's generated, formally verified p256_64 / p256_scalar_64
 *          (MIT), fetched by scripts/fetch-fiat.sh.  Verification handles only public data, so the point
 *          arithmetic here is variable-time (branches on exceptional cases).
 *   RS256  s^e mod n with e = 65537 is 16 squarings + 1 multiply.  The key holds R^2 mod n and -n^-1 mod 2^64,
 *          and the expected EMSA-PKCS1-v1_5 block is compared word-wise (no parsing of the decrypted block).
 *          -DJWT_RSA_SCREEN: batch "screening" (Bellare-Garay-Rabin): one check (prod s_i)^e == prod EM_i for
 *          the whole batch, ~2 multiplications per token + 1 exponentiation, falling back to per-token checks
 *          when it fails.  Screening proves every *message* was signed, not that every signature string is
 *          the canonical one (s1*x, s2/x pass together), so it is opt-in.  PK.md discusses it.
 *
 * Arithmetic backends (PK.md "Backends" has the measurements): portable C by default; -DJWT_S2N links s2n-bignum's
 * verified assembly for the P-256 field and RSA-2048; -DJWT_OPENSSL hands RSA to libcrypto's BN Montgomery asm.
 */
#include "fiat/p256_64.c"
#include "fiat/p256_scalar_64.c"

#ifndef CC_P256_W
#define CC_P256_W 8 /* comb window: 33 windows x 128 points x 64 B = 264 KB per base point (W=7: 148 KB, ~12% slower) */
#endif
#define P256_NW ((257 + CC_P256_W - 1) / CC_P256_W)
#ifndef CC_ES_ILV
#define CC_ES_ILV 1 /* ES256 tokens whose point additions run interleaved; no gain measured on an M5 (PK.md) */
#endif
#define P256_H (1 << (CC_P256_W - 1))

typedef uint64_t fe_t[4]; /* little-endian 64-bit limbs; field elements in fiat's Montgomery domain */
typedef struct {
    fe_t x, y;
} p256_aff_t;
typedef struct {
    fe_t x, y, z;
    int inf;
} p256_jac_t;

#define RSA_MAXL 64 /* 4096-bit moduli */
typedef struct {
    int nl, k;   /* limbs, modulus bytes */
    uint64_t n0; /* -n^-1 mod 2^64 */
    uint64_t e;
    uint64_t n[RSA_MAXL], r2[RSA_MAXL]; /* R^2 mod n, R = 2^(64 nl) */
    uint64_t em[RSA_MAXL];              /* EMSA-PKCS1-v1_5 block with a zero hash, as limbs */
#ifdef CC_RSA_SCREEN
    uint64_t kc[16][RSA_MAXL]; /* R^((c-1)(e-1)) mod n for a screened batch of c = 1..16 */
#endif
#ifdef CC_OPENSSL
    struct bignum_st *bn_n, *bn_e, *bn_kcm[16]; /* the same values for libcrypto; kcm = kc R (Montgomery form) */
    struct bn_mont_ctx_st *mont;
#endif
#ifdef CC_RSAZ
    int ifma;                                       /* RSA-2048 on an AVX-512 IFMA CPU: the 52-bit-digit path */
    uint64_t n52[80] __attribute__((aligned(32)));  /* n in radix 2^52, twice (the two-way kernel's [2][40] layout) */
    uint64_t rr52[80] __attribute__((aligned(32))); /* R'^2 mod n, R' = 2^2080, in radix 2^52, twice */
    uint64_t k02[2];                                /* n0 twice, for the two-way kernel */
#ifdef CC_RSAZ8
    /* the same for crypto_mb's 8-lane kernels, one copy per lane: [digit][lane]; k0 there is -n^-1 mod 2^52 */
    uint64_t n52x8[40][8] __attribute__((aligned(64))), rr52x8[40][8] __attribute__((aligned(64)));
    uint64_t k0x8[8] __attribute__((aligned(64)));
    int ifma8; /* ifma, e = 65537, and zmm costs no clock speed (FAST_ZMM: AMD Zen 4 / 5) */
#endif
#endif
} rsa_key_t;

#ifdef CC_OPENSSL
static int rsa_ossl_init(rsa_key_t *k);
#endif

struct cc_pkey {
    int alg; /* CC_PK_RS256, CC_PK_ES256, CC_PK_ED25519 */
    rsa_key_t rsa;
    p256_aff_t (*tg)[P256_H], (*tq)[P256_H]; /* ES256: P256_NW rows each, one allocation */
    uint64_t qx[4], qy[4];                   /* ES256: the public point, plain little-endian limbs */
    struct ed_key *ed;                       /* EdDSA: comb tables for B and -A (cc_ed25519.inc) */
#ifdef CC_ES8
    int es8; /* ES256: batches go 8 tokens at a time through crypto/src/cmb_ec/es8.c (IFMA, and FAST_ZMM: AMD Zen 4 / 5) */
#endif
};

#ifdef CC_CRYPTO_MB
/* -DJWT_CRYPTO_MB: Intel's crypto_mb (intel/cryptography-primitives, Apache-2.0; scripts/build-crypto-mb.sh) runs
 * 8 ES256 verifies or 8 RSA public-key operations at once in 52-bit AVX-512 IFMA lanes, i.e. SIMD across tokens.
 * Used only when the CPU has AVX-512 IFMA (Ice Lake and later; cc_cpu); everything else falls back to the paths
 * below.  Byte order, from Intel's own known-answer tests: r, s, digests and RSA inputs / outputs are big-endian
 * strings, public-key coordinates and moduli little-endian 64-bit limbs. */
#include <crypto_mb/ec_nistp256.h>
#include <crypto_mb/rsa.h>
#include <crypto_mb/status.h>
static int cmb_ok(void) { return (cc_cpu() & CC_CPU_IFMA) != 0; }
#endif
enum { PK_RS256 = CC_PK_RS256, PK_ES256 = CC_PK_ES256, PK_ED25519 = CC_PK_ED25519 };

/* ---------------------------------------------------------------------------------- signing-input hashes */
/* SHA-256 of the m messages of a chunk whose signature length is right, in one multi-buffer call (cc_sha256_batch:
 * 8 lanes on AVX-512 / AVX2, 4 interleaved SHA2 streams on ARM), as 4 little-endian limbs of the big-endian digest */
static void hash_chunk(int m, const uint8_t *const *msg, const int *len, const int *slen, int want, uint64_t (*e)[4]) {
    const uint8_t *mp[32] = { 0 };
    int ml[32] = { 0 }, at[32], c = 0;
    uint32_t dig[32][8];
    for (int i = 0; i < m; i++)
        if (slen[i] == want) mp[c] = msg[i], ml[c] = len[i], at[c++] = i;
    cc_sha256_batch(c, mp, ml, dig);
    for (int j = 0; j < c; j++)
        for (int w = 0; w < 4; w++) e[at[j]][3 - w] = (uint64_t)dig[j][2 * w] << 32 | dig[j][2 * w + 1];
}

/* ---------------------------------------------------------------------------------- P-256 */
static void be_to_limbs4(uint64_t o[4], const uint8_t b[32]) {
    for (int i = 0; i < 4; i++) {
        uint64_t v = 0;
        for (int j = 0; j < 8; j++) v = v << 8 | b[8 * (3 - i) + j];
        o[i] = v;
    }
}
CC_INLINE int fe_iszero(const fe_t a) { return !(a[0] | a[1] | a[2] | a[3]); }
CC_INLINE int fe_eq(const fe_t a, const fe_t b) {
    return !((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) | (a[3] ^ b[3]));
}
/* a < b, plain 256-bit integers */
static int u256_lt(const uint64_t a[4], const uint64_t b[4]) {
    for (int i = 3; i >= 0; i--)
        if (a[i] != b[i]) return a[i] < b[i];
    return 0;
}
static const uint64_t P256_P[4] = { 0xffffffffffffffffull, 0x00000000ffffffffull, 0, 0xffffffff00000001ull };
static const uint64_t P256_N[4] = { 0xf3b9cac2fc632551ull, 0xbce6faada7179e84ull, 0xffffffffffffffffull,
                                    0xffffffff00000000ull };
static const uint8_t P256_B[32] = { 0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd,
                                    0x55, 0x76, 0x98, 0x86, 0xbc, 0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53,
                                    0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b };
static const uint8_t P256_GX[32] = { 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6,
                                     0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb,
                                     0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96 };
static const uint8_t P256_GY[32] = { 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb,
                                     0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31,
                                     0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5 };

/* a + b, a - b, -a mod p for a, b < p; branch-free but without fiat's value barriers (public data only) */
static const uint64_t P256_P[4];
CC_INLINE void fe_add_c(fe_t o, const fe_t a, const fe_t b) {
    unsigned __int128 z = 0;
    uint64_t t[4], r[4], bw = 0;
    for (int i = 0; i < 4; i++) z = (unsigned __int128)a[i] + b[i] + (uint64_t)(z >> 64), t[i] = (uint64_t)z;
    uint64_t cy = (uint64_t)(z >> 64);
    for (int i = 0; i < 4; i++) {
        unsigned __int128 d = (unsigned __int128)t[i] - P256_P[i] - bw;
        r[i] = (uint64_t)d, bw = (uint64_t)(d >> 64) & 1;
    }
    uint64_t keep = (uint64_t)0 - (bw & ~cy); /* borrow and no carry: a + b < p */
    for (int i = 0; i < 4; i++) o[i] = (t[i] & keep) | (r[i] & ~keep);
}
CC_INLINE void fe_sub_c(fe_t o, const fe_t a, const fe_t b) {
    uint64_t t[4], bw = 0;
    for (int i = 0; i < 4; i++) {
        unsigned __int128 d = (unsigned __int128)a[i] - b[i] - bw;
        t[i] = (uint64_t)d, bw = (uint64_t)(d >> 64) & 1;
    }
    uint64_t mask = (uint64_t)0 - bw;
    unsigned __int128 z = 0;
    for (int i = 0; i < 4; i++)
        z = (unsigned __int128)t[i] + (P256_P[i] & mask) + (uint64_t)(z >> 64), o[i] = (uint64_t)z;
}
#define fe_opp(o, a) fe_sub(o, P256_ZERO, a)
static const fe_t P256_ZERO = { 0 };

/* o = a b / 2^256 mod p for a, b < p (Montgomery, CIOS).  p's limbs are 2^64-1, 2^32-1, 0, 2^64-2^32+1 and
 * -p^-1 = 1 mod 2^64, so each reduction round takes m = t0 and needs two multiplications instead of four, the
 * structure OpenSSL's ecp_nistz256 uses.  Cross-checked against fiat_p256_mul by tests/test_pk.c.  ~2x faster
 * than fiat's generic word-by-word code here (which also carries value barriers for constant time). */
#define P256_P1 0x00000000ffffffffull
#define P256_P3 0xffffffff00000001ull
CC_INLINE void fe_mul_c(fe_t o, const fe_t a, const fe_t b) {
    uint64_t t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5, c, m;
    unsigned __int128 z;
    for (int i = 0; i < 4; i++) {
        uint64_t bi = b[i];
        z = (unsigned __int128)a[0] * bi + t0, t0 = (uint64_t)z, c = (uint64_t)(z >> 64);
        z = (unsigned __int128)a[1] * bi + t1 + c, t1 = (uint64_t)z, c = (uint64_t)(z >> 64);
        z = (unsigned __int128)a[2] * bi + t2 + c, t2 = (uint64_t)z, c = (uint64_t)(z >> 64);
        z = (unsigned __int128)a[3] * bi + t3 + c, t3 = (uint64_t)z, c = (uint64_t)(z >> 64);
        z = (unsigned __int128)t4 + c, t4 = (uint64_t)z, t5 = (uint64_t)(z >> 64);
        m = t0; /* t0 + m (2^64 - 1) = m 2^64: limb 0 becomes 0 and carries m */
        z = (unsigned __int128)m * P256_P1 + t1 + m, t0 = (uint64_t)z, c = (uint64_t)(z >> 64);
        z = (unsigned __int128)t2 + c, t1 = (uint64_t)z, c = (uint64_t)(z >> 64);
        z = (unsigned __int128)m * P256_P3 + t3 + c, t2 = (uint64_t)z, c = (uint64_t)(z >> 64);
        z = (unsigned __int128)t4 + c, t3 = (uint64_t)z, c = (uint64_t)(z >> 64);
        t4 = t5 + c;
    }
    /* t < 2p: subtract p once if t >= p */
    uint64_t r0, r1, r2, r3, bw;
    z = (unsigned __int128)t0 - 0xffffffffffffffffull, r0 = (uint64_t)z, bw = (uint64_t)(z >> 64) & 1;
    z = (unsigned __int128)t1 - P256_P1 - bw, r1 = (uint64_t)z, bw = (uint64_t)(z >> 64) & 1;
    z = (unsigned __int128)t2 - bw, r2 = (uint64_t)z, bw = (uint64_t)(z >> 64) & 1;
    z = (unsigned __int128)t3 - P256_P3 - bw, r3 = (uint64_t)z, bw = (uint64_t)(z >> 64) & 1;
    if (t4 >= bw) o[0] = r0, o[1] = r1, o[2] = r2, o[3] = r3; /* no net borrow: t >= p */
    else o[0] = t0, o[1] = t1, o[2] = t2, o[3] = t3;
}
#define fe_sqr_c(o, a) fe_mul_c(o, a, a)

#ifdef CC_S2N
/* -DJWT_S2N: AWS s2n-bignum's formally verified assembly (scripts/fetch-s2n-bignum.sh, MIT-0), Montgomery
 * multiply / square and modular add / sub for p_256.  Same domain and contracts as the C versions above, which
 * tests/test_pk.c still cross-checks against fiat-crypto alongside these.  On x86-64 they need BMI2 + ADX, so they
 * are used only when the CPU has them (s2n_ok); everything falls back to the C. */
void cc_s2n_bignum_montmul_p256(uint64_t z[4], const uint64_t x[4], const uint64_t y[4]);
void cc_s2n_bignum_montsqr_p256(uint64_t z[4], const uint64_t x[4]);
void cc_s2n_bignum_add_p256(uint64_t z[4], const uint64_t x[4], const uint64_t y[4]);
void cc_s2n_bignum_sub_p256(uint64_t z[4], const uint64_t x[4], const uint64_t y[4]);
static int s2n_ok(void) {
#if defined(__x86_64__)
    return (cc_cpu() & CC_CPU_BMI2_ADX) != 0;
#else
    return 1;
#endif
}
#if defined(__x86_64__)
/* x86-64 CPUs without BMI2 / ADX (or VMs that hide them: Vultr's Genoa and Cascade Lake guests do) get
 * s2n-bignum's _alt multiply / square, which use plain mul / adc and are verified like the others; its add / sub
 * need neither extension */
#define CC_S2N_ALT 1
void cc_s2n_bignum_montmul_p256_alt(uint64_t z[4], const uint64_t x[4], const uint64_t y[4]);
void cc_s2n_bignum_montsqr_p256_alt(uint64_t z[4], const uint64_t x[4]);
#endif
#endif
/* the C field operations, for everything outside the per-token point arithmetic */
#define fe_mul fe_mul_c
#define fe_sqr fe_sqr_c
#define fe_add fe_add_c
#define fe_sub fe_sub_c

/* a^(p-2): init only (table building) */
static void fe_inv(fe_t o, const fe_t a) {
    uint64_t e[4];
    memcpy(e, P256_P, 32);
    e[0] -= 2;
    fe_t r;
    fiat_p256_set_one(r);
    for (int i = 255; i >= 0; i--) {
        fe_sqr(r, r);
        if (e[i >> 6] >> (i & 63) & 1) fe_mul(r, r, a);
    }
    memcpy(o, r, 32);
}

#define EC(name) name##_c
#include "cc_pk_ec.inc"
#undef EC
#ifdef CC_S2N
#undef fe_mul
#undef fe_sqr
#undef fe_add
#undef fe_sub
#define fe_mul(o, a, b) cc_s2n_bignum_montmul_p256(o, a, b)
#define fe_sqr(o, a)    cc_s2n_bignum_montsqr_p256(o, a)
#define fe_add(o, a, b) cc_s2n_bignum_add_p256(o, a, b)
#define fe_sub(o, a, b) cc_s2n_bignum_sub_p256(o, a, b)
#define EC(name)        name##_s2n
#include "cc_pk_ec.inc"
#undef EC
#ifdef CC_S2N_ALT
#undef fe_mul
#undef fe_sqr
#define fe_mul(o, a, b) cc_s2n_bignum_montmul_p256_alt(o, a, b)
#define fe_sqr(o, a)    cc_s2n_bignum_montsqr_p256_alt(o, a)
#define EC(name)        name##_s2na
#include "cc_pk_ec.inc"
#undef EC
#endif
#undef fe_mul
#undef fe_sqr
#undef fe_add
#undef fe_sub
#define fe_mul fe_mul_c
#define fe_sqr fe_sqr_c
#define fe_add fe_add_c
#define fe_sub fe_sub_c
#endif
static void es_points(const cc_pkey_t *k, int c, int16_t (*d1)[P256_NW], int16_t (*d2)[P256_NW], uint64_t (*r)[4],
                      const int *at, uint8_t *ok) {
#ifdef CC_S2N
    if (s2n_ok()) {
        es_points_s2n(k, c, d1, d2, r, at, ok);
        return;
    }
#ifdef CC_S2N_ALT
    es_points_s2na(k, c, d1, d2, r, at, ok);
    return;
#endif
#endif
    es_points_c(k, c, d1, d2, r, at, ok);
}

#ifdef CC_ES8
/* -DJWT_ES8: the same additions for 8 tokens at once, one per 64-bit zmm lane, on crypto_mb's 8-lane P-256 field
 * arithmetic (crypto/src/cmb_ec/es8.c, built into build/libcmbec.a).  Each lane gathers its own entries of the tables above.
 * Lanes es8.c can't finish (an exceptional addition, R at infinity) and the rare r + n < p second candidate are
 * redone here by the scalar code, so the results are the scalar code's. */
void cc_es8_points(const void *tg, const void *tq, int nw, int h, const int16_t *const d1[8],
                   const int16_t *const d2[8], const uint64_t r[8][4], unsigned *good, unsigned *redo);
#ifndef CC_ES8_MIN
#define CC_ES8_MIN 3 /* the fewest tokens worth a (padded) group of 8; fewer go to the scalar code */
#endif
static void es_points8(const cc_pkey_t *k, int c, int16_t (*d1)[P256_NW], int16_t (*d2)[P256_NW], uint64_t (*r)[4],
                       const int *at, uint8_t *ok) {
    for (int g = 0; g < c; g += 8) {
        int m = c - g < 8 ? c - g : 8;
        if (m < CC_ES8_MIN) {
            es_points(k, m, d1 + g, d2 + g, r + g, at + g, ok);
            break;
        }
        const int16_t *p1[8], *p2[8];
        uint64_t rr[8][4];
        for (int l = 0; l < 8; l++) { /* a short group repeats its first token */
            int i = g + (l < m ? l : 0);
            p1[l] = d1[i], p2[l] = d2[i], memcpy(rr[l], r[i], 32);
        }
        unsigned good, redo;
        cc_es8_points(k->tg, k->tq, P256_NW, P256_H, p1, p2, (const uint64_t(*)[4])rr, &good, &redo);
        for (int l = 0; l < m; l++) {
            int i = g + l, again = redo >> l & 1;
            if (!again && !(good >> l & 1)) { /* r + n is a candidate too when it's < p */
                uint64_t rn[4];
                fiat_p256_scalar_uint1 cy = 0;
                for (int j = 0; j < 4; j++) fiat_p256_scalar_addcarryx_u64(&rn[j], &cy, cy, r[i][j], P256_N[j]);
                again = !cy && u256_lt(rn, P256_P);
            }
            if (again) es_points(k, 1, d1 + i, d2 + i, r + i, at + i, ok);
            else ok[at[i]] = (uint8_t)(good >> l & 1);
        }
    }
}
#endif

/* tab[w][k-1] = k * 2^(W w) * P, affine, k = 1..H */
static void p256_table(p256_aff_t tab[P256_NW][P256_H], const fe_t px, const fe_t py) {
    p256_jac_t *jac = malloc(sizeof(p256_jac_t) * P256_H);
    fe_t *pre = malloc(sizeof(fe_t) * P256_H);
    fe_t bx, by;
    memcpy(bx, px, 32), memcpy(by, py, 32);
    for (int w = 0; w < P256_NW; w++) {
        jac[0].inf = 1;
        p256_madd_c(&jac[0], bx, by);
        for (int k = 1; k < P256_H; k++) jac[k] = jac[k - 1], p256_madd_c(&jac[k], bx, by);
        /* to affine with one inversion; no k*B is infinity since k < n */
        memcpy(pre[0], jac[0].z, 32);
        for (int k = 1; k < P256_H; k++) fe_mul(pre[k], pre[k - 1], jac[k].z);
        fe_t inv, zi, zi2;
        fe_inv(inv, pre[P256_H - 1]);
        for (int k = P256_H - 1; k >= 0; k--) {
            if (k) fe_mul(zi, inv, pre[k - 1]), fe_mul(inv, inv, jac[k].z);
            else memcpy(zi, inv, 32);
            fe_sqr(zi2, zi);
            fe_mul(tab[w][k].x, jac[k].x, zi2);
            fe_mul(zi2, zi2, zi);
            fe_mul(tab[w][k].y, jac[k].y, zi2);
        }
        /* next base: 2^W * B = 2 * (H * B) */
        p256_jac_t d = jac[P256_H - 1], d2;
        p256_dbl_c(&d2, &d);
        fe_t z2;
        fe_inv(inv, d2.z);
        fe_sqr(z2, inv);
        fe_mul(bx, d2.x, z2);
        fe_mul(z2, z2, inv);
        fe_mul(by, d2.y, z2);
    }
    free(jac), free(pre);
}

static int p256_on_curve(const fe_t x, const fe_t y) { /* y^2 = x^3 - 3x + b */
    fe_t l, r, t, b;
    uint64_t bn[4];
    be_to_limbs4(bn, P256_B);
    fiat_p256_to_montgomery(b, bn);
    fe_sqr(l, y);
    fe_sqr(r, x);
    fe_mul(r, r, x);
    fe_add(t, x, x);
    fe_add(t, t, x);
    fe_sub(r, r, t);
    fe_add(r, r, b);
    return fe_eq(l, r);
}

cc_pkey_t *cc_pkey_es256(const uint8_t x[32], const uint8_t y[32]) {
    uint64_t xi[4], yi[4], gx[4], gy[4];
    be_to_limbs4(xi, x), be_to_limbs4(yi, y);
    if (!u256_lt(xi, P256_P) || !u256_lt(yi, P256_P)) return NULL;
    cc_pkey_t *k = calloc(1, sizeof *k);
    if (!k) return NULL;
#ifdef CC_ES8
    /* 64-byte entries on 64-byte boundaries: es8.c's gathers then never split a cache line */
    if (posix_memalign((void **)&k->tg, 64, sizeof(p256_aff_t[P256_NW][P256_H]) * 2)) k->tg = NULL;
    k->es8 = (cc_cpu() & (CC_CPU_IFMA | CC_CPU_FAST_ZMM)) == (CC_CPU_IFMA | CC_CPU_FAST_ZMM);
#else
    k->tg = malloc(sizeof(p256_aff_t[P256_NW][P256_H]) * 2);
#endif
    if (!k->tg) {
        free(k);
        return NULL;
    }
    k->tq = k->tg + P256_NW;
    fe_t qx, qy, gmx, gmy;
    fiat_p256_to_montgomery(qx, xi), fiat_p256_to_montgomery(qy, yi);
    memcpy(k->qx, xi, 32), memcpy(k->qy, yi, 32);
    if (!p256_on_curve(qx, qy)) {
        free(k->tg), free(k);
        return NULL;
    }
    be_to_limbs4(gx, P256_GX), be_to_limbs4(gy, P256_GY);
    fiat_p256_to_montgomery(gmx, gx), fiat_p256_to_montgomery(gmy, gy);
    p256_table(k->tg, gmx, gmy);
    p256_table(k->tq, qx, qy);
    k->alg = PK_ES256;
    return k;
}

/* u = sum d_w 2^(W w), d_w in [-H+1, H] */
static void p256_recode(int16_t d[P256_NW], const uint64_t u[4]) {
    int carry = 0;
    for (int w = 0; w < P256_NW; w++) {
        int bit = w * CC_P256_W, li = bit >> 6, sh = bit & 63;
        uint64_t v = li < 4 ? u[li] >> sh : 0;
        if (sh + CC_P256_W > 64 && li + 1 < 4) v |= u[li + 1] << (64 - sh);
        int c = (int)(v & ((1u << CC_P256_W) - 1)) + carry;
        if (c > P256_H) d[w] = (int16_t)(c - 2 * P256_H), carry = 1;
        else d[w] = (int16_t)c, carry = 0;
    }
}

/* 1/a mod n for 0 < a < n, plain integers: binary extended Euclid.  Variable-time, which is fine here: s is part of
 * the signature, public.  ~5x cheaper than a^(n-2) with fiat's scalar multiplication. */
static void u256_shr1(uint64_t a[4], uint64_t top) {
    a[0] = a[0] >> 1 | a[1] << 63, a[1] = a[1] >> 1 | a[2] << 63, a[2] = a[2] >> 1 | a[3] << 63,
    a[3] = a[3] >> 1 | top << 63;
}
static uint64_t u256_add(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    unsigned __int128 z = 0;
    for (int i = 0; i < 4; i++) z = (unsigned __int128)a[i] + b[i] + (uint64_t)(z >> 64), r[i] = (uint64_t)z;
    return (uint64_t)(z >> 64);
}
static uint64_t u256_sub(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) { /* returns the borrow */
    uint64_t bw = 0;
    for (int i = 0; i < 4; i++) {
        unsigned __int128 z = (unsigned __int128)a[i] - b[i] - bw;
        r[i] = (uint64_t)z, bw = (uint64_t)(z >> 64) & 1;
    }
    return bw;
}
static void halve_mod_n(uint64_t x[4]) { /* x / 2 mod n, x < n */
    if (x[0] & 1) u256_shr1(x, u256_add(x, x, P256_N));
    else u256_shr1(x, 0);
}
static void sub_mod_n(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    if (u256_sub(r, a, b)) u256_add(r, r, P256_N);
}
static int u256_is1(const uint64_t a[4]) { return a[0] == 1 && !(a[1] | a[2] | a[3]); }
static void sc_inv_plain(uint64_t o[4], const uint64_t a[4]) {
    uint64_t u[4], v[4], x1[4] = { 1 }, x2[4] = { 0 };
    memcpy(u, a, 32), memcpy(v, P256_N, 32);
    while (!u256_is1(u) && !u256_is1(v)) {
        while (!(u[0] & 1)) u256_shr1(u, 0), halve_mod_n(x1);
        while (!(v[0] & 1)) u256_shr1(v, 0), halve_mod_n(x2);
        if (!u256_lt(u, v)) u256_sub(u, u, v), sub_mod_n(x1, x1, x2);
        else u256_sub(v, v, u), sub_mod_n(x2, x2, x1);
    }
    memcpy(o, u256_is1(u) ? x1 : x2, 32);
}
/* the same in fiat's Montgomery domain (mod n): (aR)^-1 R^3 / R = a^-1 R */
static void sc_inv(uint64_t o[4], const uint64_t am[4]) {
    uint64_t one[4] = { 1 }, r3[4], t[4];
    fiat_p256_scalar_to_montgomery(r3, one); /* R */
    fiat_p256_scalar_to_montgomery(r3, r3);  /* R^2 */
    fiat_p256_scalar_to_montgomery(r3, r3);  /* R^3 */
    sc_inv_plain(t, am);
    fiat_p256_scalar_mul(o, t, r3);
}

static void es256_raw(const cc_pkey_t *k, int n, const uint8_t *const *msg, const int *len, const uint8_t *const *sig,
                      const int *slen, uint8_t *ok) {
    enum { CH = 32 };
    for (int base = 0; base < n; base += CH) {
        int m = n - base < CH ? n - base : CH, c = 0, at[CH];
        uint64_t r[CH][4], sm[CH][4], em[CH][4], pre[CH][4], hs[CH][4];
        hash_chunk(m, msg + base, len + base, slen + base, 64, hs);
        for (int i = 0; i < m; i++) {
            int t = base + i;
            ok[t] = 0;
            if (slen[t] != 64) continue;
            uint64_t s[4], e[4];
            be_to_limbs4(r[c], sig[t]), be_to_limbs4(s, sig[t] + 32);
            if (fe_iszero(r[c]) || fe_iszero(s) || !u256_lt(r[c], P256_N) || !u256_lt(s, P256_N)) continue;
            memcpy(e, hs[i], 32);
            if (!u256_lt(e, P256_N)) { /* e < 2^256 < 2n: one subtraction */
                fiat_p256_scalar_uint1 b = 0;
                for (int j = 0; j < 4; j++) fiat_p256_scalar_subborrowx_u64(&e[j], &b, b, e[j], P256_N[j]);
            }
            fiat_p256_scalar_to_montgomery(sm[c], s);
            fiat_p256_scalar_to_montgomery(em[c], e);
            at[c++] = t;
        }
        if (!c) continue;
#ifdef CC_CRYPTO_MB
        if (cmb_ok()) { /* 8 verifies per call; short groups repeat their first lane */
            for (int g = 0; g < c; g += 8) {
                const int8u *pr[8], *ps[8], *pm[8];
                const int64u *px[8], *py[8];
                uint8_t dig[8][32];
                for (int l = 0; l < 8; l++) {
                    int j = g + l < c ? g + l : g, t = at[j];
                    for (int w = 0; w < 4; w++)
                        for (int b = 0; b < 8; b++) dig[l][8 * w + b] = (uint8_t)(hs[t - base][3 - w] >> (56 - 8 * b));
                    pr[l] = sig[t], ps[l] = sig[t] + 32, pm[l] = dig[l];
                    px[l] = (const int64u *)k->qx, py[l] = (const int64u *)k->qy;
                }
                mbx_status st = mbx_nistp256_ecdsa_verify_mb8(pr, ps, pm, px, py, NULL, NULL);
                for (int l = 0; l < 8 && g + l < c; l++) ok[at[g + l]] = MBX_GET_STS(st, l) == MBX_STATUS_OK;
            }
            continue;
        }
#endif
        /* all s^-1 with one inversion (Montgomery's trick), then u1 = e/s, u2 = r/s as signed digits */
        memcpy(pre[0], sm[0], 32);
        for (int i = 1; i < c; i++) fiat_p256_scalar_mul(pre[i], pre[i - 1], sm[i]);
        uint64_t inv[4], w[4];
        int16_t d1[CH][P256_NW], d2[CH][P256_NW];
        sc_inv(inv, pre[c - 1]);
        for (int i = c - 1; i >= 0; i--) {
            if (i) fiat_p256_scalar_mul(w, inv, pre[i - 1]), fiat_p256_scalar_mul(inv, inv, sm[i]);
            else memcpy(w, inv, 32);
            uint64_t u1[4], u2[4], rm[4];
            fiat_p256_scalar_mul(u1, em[i], w);
            fiat_p256_scalar_from_montgomery(u1, u1);
            fiat_p256_scalar_to_montgomery(rm, r[i]);
            fiat_p256_scalar_mul(u2, rm, w);
            fiat_p256_scalar_from_montgomery(u2, u2);
            p256_recode(d1[i], u1), p256_recode(d2[i], u2);
        }
#ifdef CC_ES8
        if (k->es8 && c >= CC_ES8_MIN) {
            es_points8(k, c, d1, d2, r, at, ok);
            continue;
        }
#endif
        es_points(k, c, d1, d2, r, at, ok);
    }
}

/* ---------------------------------------------------------------------------------- RSA */
typedef unsigned __int128 u128;

/* Montgomery multiplication r = a b R^-1 mod n, product scanning (one column of a*b + m*n at a time, in a 3-word
 * accumulator), and a squaring that computes each a_j a_k (j < k) once and doubles it: 16 of RS256's 18
 * multiplications are squarings.  a, b < n; r may alias a or b.  The multiply loops are inlined into fixed-size
 * copies for 2048/3072/4096-bit moduli so their trip counts are constants. */
/* (c0, c1, c2) += x y.  On x86-64 through _addcarry_u64, which gcc and clang turn into add/adc/adc; elsewhere as
 * 128-bit adds (aarch64 compilers emit adds/adcs/adc for these).  gcc turned the obvious `acc += z; c2 += acc < z`
 * into branches and stack spills on x86: 7x slower than OpenSSL on a Cascade Lake. */
#if defined(__x86_64__)
#include <x86intrin.h>
#define MAC(c0, c1, c2, x, y)                                                                                          \
    do {                                                                                                               \
        u128 z_ = (u128)(x) * (y);                                                                                     \
        unsigned long long l_;                                                                                         \
        unsigned char k_ = _addcarry_u64(0, (c0), (uint64_t)z_, &l_);                                                  \
        (c0) = l_;                                                                                                     \
        k_ = _addcarry_u64(k_, (c1), (uint64_t)(z_ >> 64), &l_);                                                       \
        (c1) = l_, (c2) += k_;                                                                                         \
    } while (0)
#else
#define MAC(c0, c1, c2, x, y)                                                                                          \
    do {                                                                                                               \
        u128 z_ = (u128)(x) * (y), s_ = (u128)(c0) + (uint64_t)z_;                                                     \
        (c0) = (uint64_t)s_;                                                                                           \
        s_ = (u128)(c1) + (uint64_t)(z_ >> 64) + (uint64_t)(s_ >> 64);                                                 \
        (c1) = (uint64_t)s_, (c2) += (uint64_t)(s_ >> 64);                                                             \
    } while (0)
#endif
CC_INLINE void mont_fin(uint64_t *r, const uint64_t *t, uint64_t top, const uint64_t *n, int nl) {
    uint64_t d[RSA_MAXL], bw = 0;
    for (int j = 0; j < nl; j++) {
        u128 z = (u128)t[j] - n[j] - bw;
        d[j] = (uint64_t)z, bw = (uint64_t)(z >> 64) & 1;
    }
    memcpy(r, top >= bw ? d : t, sizeof(uint64_t) * nl); /* t >= n unless the subtraction borrowed past top */
}
/* the m*n half of column i, shared by mul and sqr; (c0, c1, c2) hold the a*b part of the column */
#define MONT_COL(i)                                                                                                    \
    do {                                                                                                               \
        if ((i) < nl) {                                                                                                \
            for (int j = 0; j < (i); j++) MAC(c0, c1, c2, m[j], n[(i) - j]);                                           \
            m[i] = c0 * n0;                                                                                            \
            MAC(c0, c1, c2, m[i], n[0]);                                                                               \
        } else {                                                                                                       \
            for (int j = (i) - nl + 1; j < nl; j++) MAC(c0, c1, c2, m[j], n[(i) - j]);                                 \
            t[(i) - nl] = c0;                                                                                          \
        }                                                                                                              \
        c0 = c1, c1 = c2, c2 = 0;                                                                                      \
    } while (0)
CC_INLINE void mont_mul(uint64_t *r, const uint64_t *a, const uint64_t *b, const uint64_t *n, uint64_t n0, int nl) {
    uint64_t m[RSA_MAXL], t[RSA_MAXL], c0 = 0, c1 = 0, c2 = 0;
    for (int i = 0; i < 2 * nl - 1; i++) {
        int lo = i < nl ? 0 : i - nl + 1, hi = i < nl ? i : nl - 1;
        for (int j = lo; j <= hi; j++) MAC(c0, c1, c2, a[j], b[i - j]);
        MONT_COL(i);
    }
    t[nl - 1] = c0;
    mont_fin(r, t, c1, n, nl);
}
CC_INLINE void mont_sqr(uint64_t *r, const uint64_t *a, const uint64_t *n, uint64_t n0, int nl) {
    uint64_t m[RSA_MAXL], t[RSA_MAXL], c0 = 0, c1 = 0, c2 = 0;
    for (int i = 0; i < 2 * nl - 1; i++) {
        int lo = i < nl ? 0 : i - nl + 1;
        uint64_t q0 = 0, q1 = 0, q2 = 0; /* sum of a_j a_(i-j), j < i - j; then doubled */
        for (int j = lo; j < i - j; j++) MAC(q0, q1, q2, a[j], a[i - j]);
        q2 = q2 << 1 | q1 >> 63, q1 = q1 << 1 | q0 >> 63, q0 <<= 1;
        if (!(i & 1)) MAC(q0, q1, q2, a[i >> 1], a[i >> 1]);
        u128 s_ = (u128)c0 + q0;
        c0 = (uint64_t)s_, s_ = (u128)c1 + q1 + (uint64_t)(s_ >> 64);
        c1 = (uint64_t)s_, c2 += q2 + (uint64_t)(s_ >> 64);
        MONT_COL(i);
    }
    t[nl - 1] = c0;
    mont_fin(r, t, c1, n, nl);
}
#undef MONT_COL
typedef struct {
    void (*mul)(uint64_t *, const uint64_t *, const uint64_t *, const rsa_key_t *);
    void (*sqr)(uint64_t *, const uint64_t *, const rsa_key_t *);
    void (*red)(uint64_t *, const uint64_t *, const rsa_key_t *); /* x R^-1 (out of the Montgomery domain); NULL: mul by 1 */
} mont_ops_t;
#define MONT_SIZE(N)                                                                                                   \
    static void mont_mul_##N(uint64_t *r, const uint64_t *a, const uint64_t *b, const rsa_key_t *k) {                  \
        mont_mul(r, a, b, k->n, k->n0, N);                                                                             \
    }                                                                                                                  \
    static void mont_sqr_##N(uint64_t *r, const uint64_t *a, const rsa_key_t *k) { mont_sqr(r, a, k->n, k->n0, N); }
MONT_SIZE(32)
MONT_SIZE(48)
MONT_SIZE(64)
static void mont_mul_any(uint64_t *r, const uint64_t *a, const uint64_t *b, const rsa_key_t *k) {
    mont_mul(r, a, b, k->n, k->n0, k->nl);
}
static void mont_sqr_any(uint64_t *r, const uint64_t *a, const rsa_key_t *k) { mont_sqr(r, a, k->n, k->n0, k->nl); }
#ifdef CC_S2N
/* -DJWT_S2N, 2048-bit moduli: s2n-bignum's Karatsuba product / square (bignum_kmul_32_64, bignum_ksqr_32_64) and
 * its 8-limb-blocked Montgomery reduction (bignum_emontredc_8n), as AWS-LC uses them for RSA-2048.  emontredc
 * leaves z + q n = 2^2048 (c 2^2048 + hi): hi plus carry c is the unreduced result, < 2n. */
void cc_s2n_bignum_kmul_32_64(uint64_t z[64], const uint64_t x[32], const uint64_t y[32], uint64_t t[96]);
void cc_s2n_bignum_ksqr_32_64(uint64_t z[64], const uint64_t x[32], uint64_t t[72]);
uint64_t cc_s2n_bignum_emontredc_8n(uint64_t k, uint64_t *z, const uint64_t *m, uint64_t w);
static void mont_mul_s2n(uint64_t *r, const uint64_t *a, const uint64_t *b, const rsa_key_t *k) {
    uint64_t z[64], t[96];
    cc_s2n_bignum_kmul_32_64(z, a, b, t);
    uint64_t c = cc_s2n_bignum_emontredc_8n(32, z, k->n, k->n0);
    mont_fin(r, z + 32, c, k->n, 32);
}
static void mont_sqr_s2n(uint64_t *r, const uint64_t *a, const rsa_key_t *k) {
    uint64_t z[64], t[72];
    cc_s2n_bignum_ksqr_32_64(z, a, t);
    uint64_t c = cc_s2n_bignum_emontredc_8n(32, z, k->n, k->n0);
    mont_fin(r, z + 32, c, k->n, 32);
}
#endif
#if defined(CC_OSSL_MONT) && defined(__x86_64__) && defined(__ELF__)
/* -DJWT_OSSL_MONT (x86-64 Linux, on by default): OpenSSL's bn_mul_mont, extracted (crypto/src/bn_mont*_x86_64_ossl.S): 4-way
 * multiply and 8-way squaring, with mulx/adcx/adox paths it takes only when the CPU has BMI2 + ADX.  Called directly,
 * without libcrypto's BN layer.  It is the fastest kernel measured on x86-64 CPUs and VMs without ADX, and for
 * moduli s2n-bignum has no fixed kernel for (3072, 4096).  Results are fully reduced; in-place calls are allowed
 * (OpenSSL's own exponentiation makes them). */
#define CC_HAVE_OSSL_MONT 1
int cc_ossl_bn_mul_mont(uint64_t *rp, const uint64_t *ap, const uint64_t *bp, const uint64_t *np, const uint64_t *n0,
                        int num);
static void mont_mul_om(uint64_t *r, const uint64_t *a, const uint64_t *b, const rsa_key_t *k) {
    cc_ossl_bn_mul_mont(r, a, b, k->n, &k->n0, k->nl);
}
static void mont_sqr_om(uint64_t *r, const uint64_t *a, const rsa_key_t *k) {
    cc_ossl_bn_mul_mont(r, a, a, k->n, &k->n0, k->nl);
}
#endif
#if defined(CC_TUNED_RSA_IPP) && defined(__x86_64__) && defined(__ELF__)
/* -DCC_TUNED_RSA_IPP (opt-in: make TUNED=1 or TUNED_RSA_IPP=1): Intel Cryptography Primitives' (ippcp) schoolbook
 * multiply / square followed by a separate Montgomery reduction, for BMI2 CPUs without ADX (mulx with add/adc
 * chains), extracted from ippcp's k0 build (crypto/src/ippcp_mont_k0.asm).  As in ippcp, leaving the Montgomery domain
 * is a bare reduction instead of a multiplication by 1.  Taken only where s2n-bignum and OpenSSL's mulx/adx paths
 * can't run (BMI2 without ADX: many cloud VMs hide ADX); RSA verify there is about 5% faster than OpenSSL's
 * bn_mul_mont (README.md, Options). */
#define CC_HAVE_IPP_MONT 1
void cc_ipp_mul_school(uint64_t *r, const uint64_t *a, int na, const uint64_t *b, int nb);
void cc_ipp_sqr_school(uint64_t *r, const uint64_t *a, int na);
void cc_ipp_mont_red(uint64_t *r, uint64_t *prod, const uint64_t *m, int nm, uint64_t m0);
static void mont_mul_ipp(uint64_t *r, const uint64_t *a, const uint64_t *b, const rsa_key_t *k) {
    uint64_t t[2 * RSA_MAXL];
    cc_ipp_mul_school(t, a, k->nl, b, k->nl);
    cc_ipp_mont_red(r, t, k->n, k->nl, k->n0);
}
static void mont_sqr_ipp(uint64_t *r, const uint64_t *a, const rsa_key_t *k) {
    uint64_t t[2 * RSA_MAXL];
    cc_ipp_sqr_school(t, a, k->nl);
    cc_ipp_mont_red(r, t, k->n, k->nl, k->n0);
}
static void mont_red_ipp(uint64_t *r, const uint64_t *a, const rsa_key_t *k) {
    uint64_t t[2 * RSA_MAXL] = { 0 };
    memcpy(t, a, sizeof(uint64_t) * k->nl);
    cc_ipp_mont_red(r, t, k->n, k->nl, k->n0);
}
static int ipp_mont_ok(void) { /* BMI2 (implied by CC_CPU_AVX2) without ADX */
    unsigned f = cc_cpu();
    return (f & CC_CPU_AVX2) && !(f & CC_CPU_BMI2_ADX);
}
#endif
static mont_ops_t mont_for(const rsa_key_t *k) {
#ifdef CC_S2N
    if (k->nl == 32 && s2n_ok()) return (mont_ops_t){ mont_mul_s2n, mont_sqr_s2n };
#endif
#ifdef CC_HAVE_IPP_MONT
    if (ipp_mont_ok()) return (mont_ops_t){ mont_mul_ipp, mont_sqr_ipp, mont_red_ipp };
#endif
#ifdef CC_HAVE_OSSL_MONT
    if (k->nl % 4 == 0) return (mont_ops_t){ mont_mul_om, mont_sqr_om }; /* every RSA size we accept (256..512 B) */
#endif
    switch (k->nl) {
        case 32: return (mont_ops_t){ mont_mul_32, mont_sqr_32 };
        case 48: return (mont_ops_t){ mont_mul_48, mont_sqr_48 };
        case 64: return (mont_ops_t){ mont_mul_64, mont_sqr_64 };
        default: return (mont_ops_t){ mont_mul_any, mont_sqr_any };
    }
}

static void be_to_limbs(uint64_t *o, int nl, const uint8_t *b, int len) { /* len <= 8 nl */
    memset(o, 0, sizeof(uint64_t) * nl);
    for (int i = 0; i < len; i++) o[(len - 1 - i) >> 3] |= (uint64_t)b[i] << (8 * ((len - 1 - i) & 7));
}

/* x = 2x mod n, for x < n */
static void rsa_dbl(uint64_t *x, const rsa_key_t *k) {
    int nl = k->nl;
    uint64_t c = 0;
    for (int j = 0; j < nl; j++) {
        uint64_t v = x[j];
        x[j] = v << 1 | c, c = v >> 63;
    }
    int ge = c != 0;
    if (!ge) {
        ge = 1;
        for (int j = nl - 1; j >= 0; j--)
            if (x[j] != k->n[j]) {
                ge = x[j] > k->n[j];
                break;
            }
    }
    if (ge) {
        uint64_t bw = 0;
        for (int j = 0; j < nl; j++) {
            u128 z = (u128)x[j] - k->n[j] - bw;
            x[j] = (uint64_t)z, bw = (uint64_t)(z >> 64) & 1;
        }
    }
}

#ifdef CC_RSAZ
/* -DJWT_RSAZ, RSA-2048 on AVX-512 IFMA CPUs (Ice Lake and later, Zen 4 / 5): OpenSSL's
 * ossl_rsaz_amm52x40_x1_ifma256 (rsaz-4k-avx512.pl, Apache-2.0; generated by scripts/fetch-ossl-rsaz.sh, which renames
 * it cc_ossl_rsaz_amm52x40_x1_ifma256 and hides it), an almost-Montgomery multiplication of 40-digit numbers in
 * radix 2^52 on ymm registers (no zmm, so no clock drop).
 * Its output is < 2n with every digit < 2^52, and is a valid input to the next call; AMM(y, 1) at the end leaves
 * y < n (Gueron 2012), and one conditional subtraction below makes that unconditional. k0 is n0 (-n^-1 mod 2^64). */
static int rsa_lt_n(const uint64_t *s, const rsa_key_t *k);
void cc_ossl_rsaz_amm52x40_x1_ifma256(uint64_t *res, const uint64_t *a, const uint64_t *b, const uint64_t *m,
                                      uint64_t k0);
/* the same multiplication on two independent [2][40] operand pairs in one pass (rsaz-4k-avx512.pl's x2): one
 * multiplication's per-digit dependency chain is the bound, so a second one in the same loop is nearly free */
void cc_ossl_rsaz_amm52x40_x2_ifma256(uint64_t *res, const uint64_t *a, const uint64_t *b, const uint64_t *m,
                                      const uint64_t k0[2]);
static int ifma_ok(void) { return (cc_cpu() & CC_CPU_IFMA) != 0; }
#define M52 ((1ull << 52) - 1)
static void to52(uint64_t o[40], const uint64_t in[32]) { /* 2048 bits, radix 2^64 -> radix 2^52 */
    for (int i = 0; i < 40; i++) {
        int b = 52 * i, w = b >> 6, sh = b & 63;
        uint64_t v = in[w] >> sh;
        if (sh > 12 && w + 1 < 32) v |= in[w + 1] << (64 - sh);
        o[i] = v & M52;
    }
}
static void from52(uint64_t o[32], const uint64_t in[40]) { /* value < 2^2048 */
    memset(o, 0, 32 * sizeof(uint64_t));
    for (int i = 0; i < 40; i++) {
        int b = 52 * i, w = b >> 6, sh = b & 63;
        if (w < 32) o[w] |= in[i] << sh;
        if (sh > 12 && w + 1 < 32) o[w + 1] |= in[i] >> (64 - sh);
    }
}
static void rsa_ifma_init(rsa_key_t *k) {
    k->ifma = k->nl == 32 && ifma_ok();
    if (!k->ifma) return;
    uint64_t x[RSA_MAXL];
    memcpy(x, k->r2, 32 * sizeof(uint64_t));    /* 2^4096 mod n */
    for (int i = 0; i < 64; i++) rsa_dbl(x, k); /* 2^4160 = R'^2 mod n */
    to52(k->n52, k->n), to52(k->rr52, x);
    memcpy(k->n52 + 40, k->n52, 40 * sizeof(uint64_t)), memcpy(k->rr52 + 40, k->rr52, 40 * sizeof(uint64_t));
    k->k02[0] = k->k02[1] = k->n0;
#ifdef CC_RSAZ8
    for (int d = 0; d < 40; d++)
        for (int l = 0; l < 8; l++) k->n52x8[d][l] = k->n52[d], k->rr52x8[d][l] = k->rr52[d];
    for (int l = 0; l < 8; l++) k->k0x8[l] = k->n0 & ((1ull << 52) - 1);
    k->ifma8 = k->e == 65537 && (cc_cpu() & CC_CPU_FAST_ZMM) != 0;
#endif
}
/* y = s^e mod n (radix 2^52, < n) -> accept iff it equals em */
static int rsa_fin52(const rsa_key_t *k, const uint64_t y[40], const uint64_t *em) {
    uint64_t r[32];
    for (int i = 0; i < 40; i++)
        if (y[i] >> 52) return 0;            /* not normalised: cannot happen; reject rather than trust it */
    if (y[39] >> (2048 - 39 * 52)) return 0; /* >= 2^2048 > n: cannot happen after AMM(y, 1) */
    from52(r, y);
    if (!rsa_lt_n(r, k)) { /* reduce once (belt and braces: Gueron's bound already gives y < n) */
        uint64_t bw = 0;
        for (int j = 0; j < 32; j++) {
            u128 z = (u128)r[j] - k->n[j] - bw;
            r[j] = (uint64_t)z, bw = (uint64_t)(z >> 64) & 1;
        }
    }
    uint64_t d = 0;
    for (int j = 0; j < 32; j++) d |= r[j] ^ em[j];
    return d == 0;
}
static int rsa_one_ifma(const rsa_key_t *k, const uint64_t *s, const uint64_t *em) {
    uint64_t s52[40] __attribute__((aligned(32))), x[40] __attribute__((aligned(32))),
        y[40] __attribute__((aligned(32)));
    uint64_t one[40] __attribute__((aligned(32))) = { 1 };
    to52(s52, s);
    cc_ossl_rsaz_amm52x40_x1_ifma256(x, s52, k->rr52, k->n52, k->n0); /* s R' */
    memcpy(y, x, sizeof y);
    for (int b = 62 - __builtin_clzll(k->e); b >= 0; b--) {
        cc_ossl_rsaz_amm52x40_x1_ifma256(y, y, y, k->n52, k->n0);
        if (k->e >> b & 1) cc_ossl_rsaz_amm52x40_x1_ifma256(y, y, x, k->n52, k->n0);
    }
    cc_ossl_rsaz_amm52x40_x1_ifma256(y, y, one, k->n52, k->n0); /* out of the Montgomery domain */
    return rsa_fin52(k, y, em);
}
#ifdef CC_RSAZ8
/* -DJWT_RSAZ8: crypto_mb's 8-lane public-exponent exponentiation (Intel cryptography-primitives, Apache-2.0,
 * scripts/fetch-crypto-mb-rsa.sh): 8 tokens, one per 64-bit lane of the zmm registers, s^65537 by 16 squarings
 * (AMS52x40_diagonal_mb8) and 1 multiplication, then out of the Montgomery domain.  The per-key n, R'^2 = 2^4160
 * mod n and k0 are ours (above), so nothing is recomputed per call. */
void cc_cmb_exp52x40_pub65537_mb8(uint64_t out[][8], const uint64_t base[][8], const uint64_t modulus[][8],
                                  const uint64_t toMont[][8], const uint64_t k0[8], uint64_t work_buffer[][8]);
static void rsa_eight_ifma(const rsa_key_t *k, uint64_t (*s)[RSA_MAXL], uint64_t (*em)[RSA_MAXL], const int *at,
                           uint8_t *ok) {
    uint64_t b[40][8] __attribute__((aligned(64))), o[40][8] __attribute__((aligned(64)));
    uint64_t w[80][8] __attribute__((aligned(64))), t[40];
    for (int l = 0; l < 8; l++) {
        to52(t, s[l]);
        for (int d = 0; d < 40; d++) b[d][l] = t[d];
    }
    cc_cmb_exp52x40_pub65537_mb8(o, (const uint64_t(*)[8])b, (const uint64_t(*)[8])k->n52x8,
                                 (const uint64_t(*)[8])k->rr52x8, k->k0x8, w);
    for (int l = 0; l < 8; l++) {
        for (int d = 0; d < 40; d++) t[d] = o[d][l];
        ok[at[l]] = (uint8_t)rsa_fin52(k, t, em[l]);
    }
}
#endif
/* two tokens under one key, side by side in the two-way kernel: ok[0], ok[1] for (s0, em0), (s1, em1) */
static void rsa_two_ifma(const rsa_key_t *k, const uint64_t *s0, const uint64_t *s1, const uint64_t *em0,
                         const uint64_t *em1, uint8_t *ok0, uint8_t *ok1) {
    uint64_t s52[80] __attribute__((aligned(32))), x[80] __attribute__((aligned(32))),
        y[80] __attribute__((aligned(32)));
    uint64_t one[80] __attribute__((aligned(32))) = { 1 };
    one[40] = 1;
    to52(s52, s0), to52(s52 + 40, s1);
    cc_ossl_rsaz_amm52x40_x2_ifma256(x, s52, k->rr52, k->n52, k->k02);
    memcpy(y, x, sizeof y);
    for (int b = 62 - __builtin_clzll(k->e); b >= 0; b--) {
        cc_ossl_rsaz_amm52x40_x2_ifma256(y, y, y, k->n52, k->k02);
        if (k->e >> b & 1) cc_ossl_rsaz_amm52x40_x2_ifma256(y, y, x, k->n52, k->k02);
    }
    cc_ossl_rsaz_amm52x40_x2_ifma256(y, y, one, k->n52, k->k02);
    *ok0 = (uint8_t)rsa_fin52(k, y, em0), *ok1 = (uint8_t)rsa_fin52(k, y + 40, em1);
}
#undef M52
#endif

/* x = s^e R mod n from sR (Montgomery domain); left-to-right binary */
static void rsa_pow(uint64_t *x, const uint64_t *sr, uint64_t e, const rsa_key_t *k, mont_ops_t mo) {
    int top = 63 - __builtin_clzll(e);
    memcpy(x, sr, sizeof(uint64_t) * k->nl);
    for (int b = top - 1; b >= 0; b--) {
        mo.sqr(x, x, k);
        if (e >> b & 1) mo.mul(x, x, sr, k);
    }
}

static const uint8_t sha256_di[19] = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                       0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };

cc_pkey_t *cc_pkey_rs256(const uint8_t *n, size_t nlen, const uint8_t *e, size_t elen) {
    while (nlen && !*n) n++, nlen--;
    while (elen && !*e) e++, elen--;
    if (nlen < 256 || nlen > 512 || !(n[nlen - 1] & 1) || !elen || elen > 8 || !(e[elen - 1] & 1)) return NULL;
#ifdef CC_RSAZ8
    /* crypto_mb's kernels load the per-lane modulus with aligned 64-byte moves; calloc only promises 16 */
    cc_pkey_t *pk = NULL;
    if (posix_memalign((void **)&pk, 64, sizeof *pk)) return NULL;
    memset(pk, 0, sizeof *pk);
#else
    cc_pkey_t *pk = calloc(1, sizeof *pk);
#endif
    if (!pk) return NULL;
    rsa_key_t *k = &pk->rsa;
    k->k = (int)nlen, k->nl = (int)((nlen + 7) / 8);
    be_to_limbs(k->n, k->nl, n, (int)nlen);
    k->e = 0;
    for (size_t i = 0; i < elen; i++) k->e = k->e << 8 | e[i];
    if (k->e < 3) {
        free(pk);
        return NULL;
    }
    uint64_t inv = 1; /* Newton: n^-1 mod 2^64 */
    for (int i = 0; i < 6; i++) inv *= 2 - k->n[0] * inv;
    k->n0 = -inv;
    /* R^2 mod n by doubling 1 2*64*nl times */
    int nl = k->nl;
    uint64_t x[RSA_MAXL + 1] = { 1 };
    for (int it = 0; it < 2 * 64 * nl; it++) rsa_dbl(x, k);
    memcpy(k->r2, x, sizeof(uint64_t) * nl);
#ifdef CC_RSAZ
    rsa_ifma_init(k);
#endif
#ifdef CC_RSA_SCREEN
    { /* kc[c-1] = Q^(c-1), Q = R^(e-1): computed in the Montgomery domain, stored plain */
        mont_ops_t mo = mont_for(k);
        uint64_t q[RSA_MAXL], km[RSA_MAXL], one[RSA_MAXL] = { 1 };
        rsa_pow(q, k->r2, k->e - 1, k, mo); /* (R)^(e-1), Montgomery form */
        mo.mul(km, k->r2, one, k);          /* 1, Montgomery form */
        for (int c = 0; c < 16; c++) {
            mo.mul(k->kc[c], km, one, k);
            mo.mul(km, km, q, k);
        }
    }
#endif
    /* EM = 00 01 FF..FF 00 DigestInfo H, with H = 0 */
    uint8_t em[512];
    int kk = k->k, ps = kk - 3 - 19 - 32;
    em[0] = 0, em[1] = 1;
    memset(em + 2, 0xff, (size_t)ps);
    em[2 + ps] = 0;
    memcpy(em + 3 + ps, sha256_di, 19);
    memset(em + kk - 32, 0, 32);
    be_to_limbs(k->em, nl, em, kk);
    pk->alg = PK_RS256;
#ifdef CC_OPENSSL
    if (!rsa_ossl_init(k)) {
        cc_pkey_free(pk);
        return NULL;
    }
#endif
    return pk;
}

/* expected EM limbs for a message hash (4 limbs): the template with the hash in limbs 0..3 */
static void rsa_em(uint64_t *o, const rsa_key_t *k, const uint64_t h[4]) {
    memcpy(o, k->em, sizeof(uint64_t) * k->nl);
    memcpy(o, h, 32);
}

static int rsa_lt_n(const uint64_t *s, const rsa_key_t *k) {
    for (int j = k->nl - 1; j >= 0; j--)
        if (s[j] != k->n[j]) return s[j] < k->n[j];
    return 0;
}

#ifdef CC_OPENSSL
/* -DJWT_OPENSSL: the RSA arithmetic goes to libcrypto's BN_mod_exp_mont / BN_mod_mul_montgomery, i.e. OpenSSL's
 * hand-written bn_mul_mont / sqr8x assembly, which neither the C here nor s2n-bignum beats (PK.md).  Everything
 * else stays ours: the token front end, the exact PKCS#1 block compare, screening.  Limbs are little-endian
 * uint64 arrays, so on a little-endian host they are BN_lebin2bn byte strings. */
#include <openssl/bn.h>
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "CC_OPENSSL assumes a little-endian host"
#endif
static int rsa_ossl_init(rsa_key_t *k) {
    BN_CTX *ctx = BN_CTX_new();
    k->bn_n = BN_lebin2bn((const uint8_t *)k->n, 8 * k->nl, NULL);
    k->bn_e = BN_new();
    k->mont = BN_MONT_CTX_new();
    int ok =
        ctx && k->bn_n && k->bn_e && k->mont && BN_set_word(k->bn_e, k->e) && BN_MONT_CTX_set(k->mont, k->bn_n, ctx);
#ifdef CC_RSA_SCREEN
    for (int c = 0; ok && c < 16; c++)
        ok = (k->bn_kcm[c] = BN_lebin2bn((const uint8_t *)k->kc[c], 8 * k->nl, NULL)) &&
             BN_to_montgomery(k->bn_kcm[c], k->bn_kcm[c], k->mont, ctx);
#endif
    BN_CTX_free(ctx);
    return ok;
}
static void rsa_ossl_free(rsa_key_t *k) {
    BN_free(k->bn_n), BN_free(k->bn_e), BN_MONT_CTX_free(k->mont);
    for (int c = 0; c < 16; c++) BN_free(k->bn_kcm[c]);
}
static int bn_eq_limbs(const BIGNUM *x, const uint64_t *em, int nl) {
    uint64_t t[RSA_MAXL], d = 0;
    if (BN_bn2lebinpad(x, (uint8_t *)t, 8 * nl) < 0) return 0;
    for (int j = 0; j < nl; j++) d |= t[j] ^ em[j];
    return d == 0;
}
/* Which kernels win (PK.md, measured): on x86-64, s2n-bignum's mulx/adx RSA-2048 code beats libcrypto (16.2 vs 20.0 us
 * per verify on a Cascade Lake); on arm64 libcrypto's armv8-mont beats s2n-bignum (8.4 vs 13.2 us on an M5); for
 * 3072/4096-bit moduli s2n-bignum has no fixed-size kernel here and libcrypto beats the C. */
static int rsa_use_ossl(const rsa_key_t *k) {
#if defined(CC_HAVE_OSSL_MONT)
    (void)k; /* the same OpenSSL kernel, called directly (mont_for), beats going through libcrypto's BN layer */
    return 0;
#elif defined(CC_S2N) && defined(__x86_64__)
    return k->nl != 32 || !s2n_ok();
#else
    (void)k;
    return 1;
#endif
}
static void rs256_ossl(const rsa_key_t *k, int c, uint64_t (*s)[RSA_MAXL], uint64_t (*em)[RSA_MAXL], const int *at,
                       uint8_t *ok) {
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return; /* allocation failure: everything stays rejected */
    BN_CTX_start(ctx);
    BIGNUM *x = BN_CTX_get(ctx), *a = BN_CTX_get(ctx), *b = BN_CTX_get(ctx), *t = BN_CTX_get(ctx);
    if (!t) goto out;
    (void)b;
#ifdef CC_RSA_SCREEN
    if (c >= 2) { /* the same algebra as the C screening below, with libcrypto's Montgomery products */
        BN_lebin2bn((const uint8_t *)s[0], 8 * k->nl, a), BN_lebin2bn((const uint8_t *)em[0], 8 * k->nl, b);
        for (int i = 1; i < c; i++) {
            BN_lebin2bn((const uint8_t *)s[i], 8 * k->nl, t), BN_mod_mul_montgomery(a, a, t, k->mont, ctx);
            BN_lebin2bn((const uint8_t *)em[i], 8 * k->nl, t), BN_mod_mul_montgomery(b, b, t, k->mont, ctx);
        }
        if (BN_mod_exp_mont(x, a, k->bn_e, k->bn_n, ctx, k->mont) &&
            BN_mod_mul_montgomery(x, x, k->bn_kcm[c - 1], k->mont, ctx) && !BN_cmp(x, b)) {
            for (int i = 0; i < c; i++) ok[at[i]] = 1;
            goto out;
        }
    }
#endif
    for (int i = 0; i < c; i++) {
        BN_lebin2bn((const uint8_t *)s[i], 8 * k->nl, a);
        ok[at[i]] = BN_mod_exp_mont(x, a, k->bn_e, k->bn_n, ctx, k->mont) && bn_eq_limbs(x, em[i], k->nl);
    }
out:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}
#endif

#ifdef CC_CRYPTO_MB
/* crypto_mb handles e = 65537 with full-size 2048 / 3072 / 4096-bit moduli */
static int rsa_cmb_usable(const rsa_key_t *k) {
    int bits = 8 * k->k;
    return cmb_ok() && k->e == 65537 && (bits == 2048 || bits == 3072 || bits == 4096) && (k->n[k->nl - 1] >> 63);
}
static void limbs_to_be(uint8_t *o, const uint64_t *x, int kbytes) {
    for (int i = 0; i < kbytes; i++) o[kbytes - 1 - i] = (uint8_t)(x[i >> 3] >> (8 * (i & 7)));
}
/* s_i^65537 mod n for c tokens, 8 per call; short groups repeat their first lane */
static void rs256_cmb(const rsa_key_t *k, int c, uint64_t (*s)[RSA_MAXL], uint64_t (*em)[RSA_MAXL], const int *at,
                      uint8_t *ok) {
    const mbx_RSA_Method *m = mbx_RSA_pub65537_Method(8 * k->k);
    int8u *buf = malloc((size_t)mbx_RSA_Method_BufSize(m));
    static _Thread_local uint8_t in[8][512], out[8][512];
    if (!buf) return; /* allocation failure: everything stays rejected */
    for (int g = 0; g < c; g += 8) {
        const int8u *from[8];
        int8u *to[8];
        const int64u *np[8];
        for (int l = 0; l < 8; l++) {
            int j = g + l < c ? g + l : g;
            limbs_to_be(in[l], s[j], k->k);
            from[l] = in[l], to[l] = out[l], np[l] = (const int64u *)k->n;
        }
        mbx_status st = mbx_rsa_public_mb8(from, to, np, 8 * k->k, m, buf);
        for (int l = 0; l < 8 && g + l < c; l++) {
            uint8_t want[512];
            limbs_to_be(want, em[g + l], k->k);
            ok[at[g + l]] = MBX_GET_STS(st, l) == MBX_STATUS_OK && !memcmp(out[l], want, (size_t)k->k);
        }
    }
    free(buf);
}
#endif

static int rsa_one(const rsa_key_t *k, mont_ops_t mo, const uint64_t *s, const uint64_t *em) {
    uint64_t sr[RSA_MAXL], x[RSA_MAXL], one[RSA_MAXL] = { 1 };
    mo.mul(sr, s, k->r2, k);
    rsa_pow(x, sr, k->e, k, mo);
    if (mo.red) mo.red(x, x, k);
    else mo.mul(x, x, one, k);
    uint64_t d = 0;
    for (int j = 0; j < k->nl; j++) d |= x[j] ^ em[j];
    return d == 0;
}

static void rs256_raw(const cc_pkey_t *pk, int n, const uint8_t *const *msg, const int *len, const uint8_t *const *sig,
                      const int *slen, uint8_t *ok) {
    const rsa_key_t *k = &pk->rsa;
    mont_ops_t mo = mont_for(k);
    enum { CH = 16 };
    for (int base = 0; base < n; base += CH) {
        int m = n - base < CH ? n - base : CH, c = 0, at[CH];
        uint64_t s[CH][RSA_MAXL], em[CH][RSA_MAXL], hs[CH][4];
        hash_chunk(m, msg + base, len + base, slen + base, k->k, hs);
        for (int i = 0; i < m; i++) {
            int t = base + i;
            ok[t] = 0;
            if (slen[t] != k->k) continue;
            be_to_limbs(s[c], k->nl, sig[t], k->k);
            if (!rsa_lt_n(s[c], k)) continue;
            rsa_em(em[c], k, hs[i]);
            at[c++] = t;
        }
#ifdef CC_RSAZ
        /* on IFMA: two tokens per call, the odd one alone; a screened batch (c >= 2) still goes to the screening */
#ifdef CC_RSA_SCREEN
        if (k->ifma && c < 2) {
#else
        if (k->ifma) {
#endif
            int i = 0;
#ifdef CC_RSAZ8
            if (k->ifma8) /* crypto_mb's kernel has e = 65537 built in, and runs on zmm */
                for (; i + 8 <= c; i += 8) rsa_eight_ifma(k, s + i, em + i, at + i, ok);
#endif
            for (; i + 1 < c; i += 2) rsa_two_ifma(k, s[i], s[i + 1], em[i], em[i + 1], &ok[at[i]], &ok[at[i + 1]]);
            if (i < c) ok[at[i]] = (uint8_t)rsa_one_ifma(k, s[i], em[i]);
            continue;
        }
#endif
#ifdef CC_OPENSSL
#ifdef CC_CRYPTO_MB
        if (rsa_use_ossl(k) && !rsa_cmb_usable(k)) {
#else
        if (rsa_use_ossl(k)) {
#endif
            rs256_ossl(k, c, s, em, at, ok);
            continue;
        }
#endif
#ifdef CC_RSA_SCREEN
        /* A = prod s_i R^-(c-1), B = prod EM_i R^-(c-1) by chained Montgomery products of the raw values; then
         * (prod s)^e == prod EM  <=>  A^e R^((c-1)(e-1)) == B  <=>  mont(pow(A R), kc[c-1]) == B.
         * 2c + e's ~18 multiplications for the whole batch instead of ~19 per token. */
        if (c >= 2) {
            uint64_t A[RSA_MAXL], B[RSA_MAXL], x[RSA_MAXL];
            memcpy(A, s[0], sizeof(uint64_t) * k->nl), memcpy(B, em[0], sizeof(uint64_t) * k->nl);
            for (int i = 1; i < c; i++) mo.mul(A, A, s[i], k), mo.mul(B, B, em[i], k);
            mo.mul(A, A, k->r2, k);
            rsa_pow(x, A, k->e, k, mo);
            mo.mul(x, x, k->kc[c - 1], k);
            uint64_t d = 0;
            for (int j = 0; j < k->nl; j++) d |= x[j] ^ B[j];
            if (!d) {
                for (int i = 0; i < c; i++) ok[at[i]] = 1;
                continue;
            }
        }
#endif
#ifdef CC_CRYPTO_MB
        if (rsa_cmb_usable(k)) {
            rs256_cmb(k, c, s, em, at, ok);
            continue;
        }
#endif
        for (int i = 0; i < c; i++) ok[at[i]] = (uint8_t)rsa_one(k, mo, s[i], em[i]);
    }
}

/* ---------------------------------------------------------------------------------- EdDSA */
#include "cc_ed25519.inc"

cc_pkey_t *cc_pkey_ed25519(const uint8_t pub[32]) {
    cc_pkey_t *k = calloc(1, sizeof *k);
    if (!k) return NULL;
    if (!(k->ed = (struct ed_key *)ed_key_new(pub))) {
        free(k);
        return NULL;
    }
    k->alg = PK_ED25519;
    return k;
}

/* ---------------------------------------------------------------------------------- key teardown, verify */
int cc_pkey_alg(const cc_pkey_t *k) { return k->alg; }
int cc_pkey_sig_bytes(const cc_pkey_t *k) { return k->alg == PK_RS256 ? k->rsa.k : 64; }

void cc_pkey_free(cc_pkey_t *k) {
    if (!k) return;
    free(k->ed);
#ifdef CC_OPENSSL
    if (k->alg == PK_RS256) rsa_ossl_free(&k->rsa);
#endif
    free(k->tg), free(k);
}

void cc_verify_batch(const cc_pkey_t *k, int n, const uint8_t *const *msg, const int *len, const uint8_t *const *sig,
                     const int *slen, uint8_t *ok) {
    if (k->alg == PK_ES256) es256_raw(k, n, msg, len, sig, slen, ok);
    else if (k->alg == PK_ED25519) ed25519_raw((const ed_key_t *)k->ed, n, msg, len, sig, slen, ok);
    else rs256_raw(k, n, msg, len, sig, slen, ok);
}
