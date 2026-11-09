/* es8.c — ES256's comb additions for 8 tokens at once, one token per 64-bit lane of the zmm registers (-DJWT_ES8).
 *
 * The field arithmetic is Intel crypto_mb's 8-lane P-256 code (cryptography-primitives @ 316ce55, Apache-2.0,
 * fetched pinned by scripts/fetch-crypto-mb-rsa.sh): five 52-bit digits per element, one element per set of five
 * zmm registers, almost-Montgomery multiplication with R = 2^260, values kept in [0, 2p).  Its two .c files are
 * #included below so that the compiler can inline them into the point code; nothing in them is changed.
 *
 * The point code is cursed-jwt's (crypto/src/cc_pk_ec.inc), not crypto_mb's: the per-key signed-digit comb tables of
 * cc_pk.c (k 2^(8j) G and k 2^(8j) Q, k = 1..128, affine, 64-bit limbs in fiat-crypto's Montgomery domain, R = 2^256)
 * are read in place.  Each lane gathers its own entry (the digits differ per token), and the entry is moved into
 * crypto_mb's domain on the way in: v 2^260 = 16 (v 2^256), one Solinas fold of the top 4 bits, no multiplication.
 * The addition is madd-2007-bl, as in the scalar code, 7M + 4S, with "at infinity" kept as a lane mask.  The
 * exceptional cases (acc = +-q) are not handled here: they make H = 0, so Z3 = 2 Z1 H = 0, and since every later Z3
 * is a multiple of Z1, Z stays 0.  A lane whose final Z is 0 (mod p) is reported back for the scalar code to redo, as
 * is a lane still at infinity.  Honest tokens never get there; crafted ones only cost themselves a scalar verify.
 *
 * Build: -O3 -D_MBX=2 -mavx512f -mavx512ifma -mavx512vl -mavx512bw -mavx512dq; the Makefile then makes every symbol
 * but cc_es8_* local, so crypto_mb's own names can't clash with a crypto_mb linked next to it. */
#include <stdint.h>
#include <string.h>

#include "sources/ippcp/crypto_mb/src/ecnist/low_level_arith/ifma_arith_m256.c"
#include "sources/ippcp/crypto_mb/src/ecnist/low_level_arith/ifma_arith_p256.c"

/* the one crypto_mb helper the two files call that isn't among them (ifma_aminv52_p256, unused here) */
void zero_mb8(int64u (*out)[8], int len) { memset(out, 0, (size_t)len * sizeof *out); }

#define MUL ifma_amm52_p256_mb8
#define SQR ifma_ams52_p256_mb8
#define ADD ifma_add52_p256_mb8
#define SUB ifma_sub52_p256_mb8
#define NEG ifma_neg52_p256_mb8

typedef struct {
    U64 x[5], y[5], z[5];
    __mmask8 inf;
} acc8_t;

/* (x0..x3: v 2^256 mod p, < p, 64-bit limbs) -> v 2^260 mod p in [0, 2p), 52-bit digits */
static inline void to260(U64 d[5], U64 x0, U64 x1, U64 x2, U64 x3) {
    const U64 m = set64(DIGIT_MASK);
    /* 16 v < 2^260: digit i holds bits [52 i - 4, 52 i + 48) of v */
    U64 d0 = and64(slli64(x0, 4), m);
    U64 d1 = and64(or64(srli64(x0, 48), slli64(x1, 16)), m);
    U64 d2 = and64(or64(srli64(x1, 36), slli64(x2, 28)), m);
    U64 d3 = and64(or64(srli64(x2, 24), slli64(x3, 40)), m);
    U64 d4 = srli64(x3, 12);
    /* 16 v = lo + hi 2^256, hi < 16; 2^256 = 2^224 - 2^192 - 2^96 + 1 (mod p).  The sum is >= 0 and
     * < 2^256 + 15 2^224 < 2p.  d0 has its low 4 bits clear, so d0 + hi doesn't carry. */
    U64 hi = srli64(d4, 48);
    d4 = and64(d4, set64((1ull << 48) - 1));
    d4 = add64(d4, slli64(hi, 16)); /* 2^224 = 2^(4*52 + 16) */
    d3 = sub64(d3, slli64(hi, 36)); /* 2^192 = 2^(3*52 + 36) */
    d1 = sub64(d1, slli64(hi, 44)); /* 2^96  = 2^(52 + 44) */
    d0 = add64(d0, hi);
    d2 = add64(d2, srai64(d1, 52)), d1 = and64(d1, m); /* signed carries */
    d3 = add64(d3, srai64(d2, 52)), d2 = and64(d2, m);
    d4 = add64(d4, srai64(d3, 52)), d3 = and64(d3, m);
    d[0] = d0, d[1] = d1, d[2] = d2, d[3] = d3, d[4] = d4;
}

/* lane l reads row[|dig[l]| - 1] (x then y, 8 limbs); negative digits negate y; zero digits leave acc alone */
static inline __attribute__((always_inline)) void add_row(acc8_t *a, const uint64_t *row, const int16_t *const *dig,
                                                          int j, const U64 one[5]) {
    int64_t off[8] __attribute__((aligned(64)));
    unsigned nz = 0, ng = 0;
    for (int l = 0; l < 8; l++) {
        int d = dig[l][j], m = d < 0 ? -d : d;
        nz |= (unsigned)(d != 0) << l, ng |= (unsigned)(d < 0) << l;
        off[l] = m ? (int64_t)(m - 1) * 64 : 0;
    }
    if (!nz) return;
    U64 vo = _mm512_load_si512(off);
    U64 qx[5], qy[5], t5[5];
    to260(qx, _mm512_i64gather_epi64(vo, row + 0, 1), _mm512_i64gather_epi64(vo, row + 1, 1),
          _mm512_i64gather_epi64(vo, row + 2, 1), _mm512_i64gather_epi64(vo, row + 3, 1));
    to260(qy, _mm512_i64gather_epi64(vo, row + 4, 1), _mm512_i64gather_epi64(vo, row + 5, 1),
          _mm512_i64gather_epi64(vo, row + 6, 1), _mm512_i64gather_epi64(vo, row + 7, 1));
    if (ng) {
        NEG(t5, qy);
        mask_mov_FE256_mb8(qy, qy, (__mmask8)ng, t5);
    }
    /* madd-2007-bl: the same sequence as cc_pk_ec.inc's p256_madd */
    U64 z1z1[5], u2[5], s2[5], h[5], r[5], hh[5], i[5], jj[5], v[5], x3[5], z3[5];
    SQR(z1z1, a->z);
    MUL(u2, qx, z1z1);
    MUL(s2, qy, a->z);
    MUL(s2, s2, z1z1);
    SUB(h, u2, a->x);
    SUB(r, s2, a->y);
    ADD(r, r, r);
    SQR(hh, h);
    ADD(i, hh, hh);
    ADD(i, i, i);
    MUL(jj, h, i);
    MUL(v, a->x, i);
    SQR(x3, r);
    SUB(x3, x3, jj);
    SUB(x3, x3, v);
    SUB(x3, x3, v);
    ADD(z3, a->z, h);
    SQR(z3, z3);
    SUB(z3, z3, z1z1);
    SUB(z3, z3, hh);
    SUB(v, v, x3);
    MUL(v, r, v);
    MUL(jj, a->y, jj);
    ADD(jj, jj, jj);
    SUB(t5, v, jj); /* Y3 */
    __mmask8 up = (__mmask8)(nz & ~a->inf), ld = (__mmask8)(nz & a->inf);
    mask_mov_FE256_mb8(a->x, a->x, up, x3);
    mask_mov_FE256_mb8(a->y, a->y, up, t5);
    mask_mov_FE256_mb8(a->z, a->z, up, z3);
    if (ld) { /* a lane's first non-zero digit: acc = (qx, qy, 1) */
        mask_mov_FE256_mb8(a->x, a->x, ld, qx);
        mask_mov_FE256_mb8(a->y, a->y, ld, qy);
        mask_mov_FE256_mb8(a->z, a->z, ld, one);
        a->inf = (__mmask8)(a->inf & ~nz);
    }
}

/* the 2 x nw additions; tg / tq: nw rows of h entries of 8 limbs each */
static __attribute__((flatten)) void comb8(acc8_t *a, const uint64_t *tg, const uint64_t *tq, int nw, int h,
                                           const int16_t *const d1[8], const int16_t *const d2[8]) {
    __ALIGN64 U64 one[5];
    MB_FUNC_NAME(ifma_tomont52_p256_)(one, (const U64 *)ones); /* 1 in the domain: 2^260 mod p */
    for (int k = 0; k < 5; k++) a->x[k] = a->y[k] = a->z[k] = get_zero64();
    a->inf = 0xff;
    for (int j = 0; j < nw; j++) {
        add_row(a, tg + (size_t)j * h * 8, d1, j, one);
        add_row(a, tq + (size_t)j * h * 8, d2, j, one);
    }
}

static void to52(U64 d[5], const uint64_t v[8][4]) { /* plain 256-bit integers, one per lane */
    int64u t[5][8] __attribute__((aligned(64)));
    for (int l = 0; l < 8; l++) {
        const uint64_t *x = v[l];
        t[0][l] = x[0] & DIGIT_MASK;
        t[1][l] = (x[0] >> 52 | x[1] << 12) & DIGIT_MASK;
        t[2][l] = (x[1] >> 40 | x[2] << 24) & DIGIT_MASK;
        t[3][l] = (x[2] >> 28 | x[3] << 36) & DIGIT_MASK;
        t[4][l] = x[3] >> 16;
    }
    for (int k = 0; k < 5; k++) d[k] = _mm512_load_si512(t[k]);
}
static void from52(uint64_t v[8][4], const U64 d[5]) { /* digits < 2^52, value < 2^256 */
    int64u t[5][8] __attribute__((aligned(64)));
    for (int k = 0; k < 5; k++) _mm512_store_si512(t[k], d[k]);
    for (int l = 0; l < 8; l++) {
        v[l][0] = t[0][l] | t[1][l] << 52;
        v[l][1] = t[1][l] >> 12 | t[2][l] << 40;
        v[l][2] = t[2][l] >> 24 | t[3][l] << 28;
        v[l][3] = t[3][l] >> 36 | t[4][l] << 16;
    }
}
/* out of the domain, fully reduced: v 2^260 -> v < p */
static void plain(uint64_t o[8][4], const U64 a[5]) {
    __ALIGN64 U64 t[5];
    MB_FUNC_NAME(ifma_frommont52_p256_)(t, a);
    from52(o, t);
}

/* Lane l verifies (d1[l], d2[l], r[l]): R = sum of the comb entries, accept iff X == r Z^2 (mod p).  *good gets the
 * accepted lanes; *redo the lanes the caller must redo with the scalar code (an exceptional addition, or R at
 * infinity).  The r + n candidate (only when r + n < p) is the caller's too. */
void cc_es8_points(const void *tg, const void *tq, int nw, int h, const int16_t *const d1[8],
                   const int16_t *const d2[8], const uint64_t r[8][4], unsigned *good, unsigned *redo) {
    acc8_t a;
    comb8(&a, tg, tq, nw, h, d1, d2);
    __ALIGN64 U64 z2[5], rm[5], t[5], x[5], z[5];
    to52(t, r);
    MB_FUNC_NAME(ifma_tomont52_p256_)(rm, t);
    SQR(z2, a.z);
    MUL(t, rm, z2);
    MB_FUNC_NAME(ifma_reduce52_p256_)(t, t); /* [0, 2p) -> [0, p) */
    MB_FUNC_NAME(ifma_reduce52_p256_)(x, a.x);
    MB_FUNC_NAME(ifma_reduce52_p256_)(z, a.z);
    __mmask8 bad = (__mmask8)(a.inf | MB_FUNC_NAME(is_zero_FE256_)(z));
    *good = (unsigned)(MB_FUNC_NAME(cmp_eq_FE256_)(t, x) & ~bad);
    *redo = bad;
}

/* tests (tests/test_pk.c): the same additions, returning the accumulators as plain integers < p, and the field
 * operations one by one on plain integers (a, b < 2^256 here, in [0, 2p) where the operation requires it) */
void cc_es8_comb(const void *tg, const void *tq, int nw, int h, const int16_t *const d1[8], const int16_t *const d2[8],
                 uint64_t x[8][4], uint64_t y[8][4], uint64_t z[8][4], unsigned *inf) {
    acc8_t a;
    comb8(&a, tg, tq, nw, h, d1, d2);
    plain(x, a.x), plain(y, a.y), plain(z, a.z);
    *inf = a.inf;
}
/* op: 0 a b R^-1, 1 a^2 R^-1, 2 a + b, 3 a - b, 4 -a (all mod p, in [0, 2p)), 5 to260 (a = v 2^256 < p: v 2^260),
 * 6 reduce ([0, 2p) -> [0, p)); results as raw integers (not reduced).  Returns a lane mask of results that are
 * out of range (>= 2p, or a digit >= 2^52). */
unsigned cc_es8_fe(int op, uint64_t o[8][4], uint64_t ohi[8], const uint64_t a[8][4], const uint64_t b[8][4],
                   const uint64_t ahi[8], const uint64_t bhi[8]) {
    __ALIGN64 U64 va[5], vb[5], vr[5];
    to52(va, a), to52(vb, b);
    /* bit 256 (values in [2^256, 2p)) goes in digit 4 */
    va[4] = add64(va[4], slli64(_mm512_loadu_si512(ahi), 48));
    vb[4] = add64(vb[4], slli64(_mm512_loadu_si512(bhi), 48));
    switch (op) {
        case 0: MUL(vr, va, vb); break;
        case 1: SQR(vr, va); break;
        case 2: ADD(vr, va, vb); break;
        case 3: SUB(vr, va, vb); break;
        case 4: NEG(vr, va); break;
        case 5: {
            U64 l[4];
            for (int k = 0; k < 4; k++) {
                int64u t[8] __attribute__((aligned(64)));
                for (int q = 0; q < 8; q++) t[q] = a[q][k];
                l[k] = _mm512_load_si512(t);
            }
            to260(vr, l[0], l[1], l[2], l[3]);
            break;
        }
        default: MB_FUNC_NAME(ifma_reduce52_p256_)(vr, va); break;
    }
    __mmask8 bad = 0;
    for (int k = 0; k < 5; k++) bad |= _mm512_cmpgt_epu64_mask(vr[k], set64(DIGIT_MASK));
    __ALIGN64 U64 hi4;
    hi4 = srli64(vr[4], 48);
    vr[4] = and64(vr[4], set64((1ull << 48) - 1));
    from52(o, vr);
    _mm512_storeu_si512(ohi, hi4);
    /* >= 2p? */
    __ALIGN64 U64 c[5];
    for (int k = 0; k < 5; k++) c[k] = vr[k];
    c[4] = add64(c[4], slli64(hi4, 48));
    bad |= (__mmask8)~MB_FUNC_NAME(cmp_lt_FE256_)(c, (const U64 *)p256x2_mb);
    return bad;
}
