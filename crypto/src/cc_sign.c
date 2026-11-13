/* cc_sign.c — signing, #included by cursed_crypto.c after cc_pk.c (unless -DCC_NO_PK).  Part of cursed-jwt, MIT licence
 * (see LICENSE).
 *
 * Ed25519 (RFC 8032 5.1.6), deterministic:
 *     (a, prefix) = SHA-512(seed), a clamped;  A = [a] B
 *     r = SHA-512(prefix || M) mod L;  R = [r] B;  k = SHA-512(R || A || M) mod L;  S = r + k a mod L
 *
 * Everything here is constant time in the secrets (seed, a, prefix, r, and k and S, which are computed from them):
 * no branch and no memory address depends on them, and only integer additions, multiplications, shifts and logic
 * touch them (no division).
 *   - Field and scalar arithmetic is fiat-crypto's (curve25519_64.c, curve25519_scalar_64.c): generated, branch-free.
 *     The helpers below call nothing else; none of cc_ed25519.inc's verify-side code (its variable-time scalar
 *     reduction, recoding, table walk, decoding or compares) is used.
 *   - [r] B is ref10's fixed-base method: 64 signed radix-16 digits of r (recoded with arithmetic only), a table of
 *     i 256^j B (i = 1..8, j = 0..31) built from public data at key setup, and for every digit a scan of its whole
 *     8-entry row by masks (each entry ANDed with all ones or zero, then ORed in), then a conditional negation the
 *     same way.  The addition (mixed, extended + affine Niels) and doubling formulas for a = -1 twisted Edwards are
 *     complete: no exceptional case, so no branch, and the identity needs none either.
 *   - Reduction mod L of the 512-bit hashes: the hash is split into pieces < 2^252 < L, each fed to fiat's Montgomery
 *     arithmetic mod L with constant multipliers 2^252 and 2^504.  Fiat requires inputs < L, which these are.
 *   - The encoding of R inverts Z with a fixed addition chain (Fermat, 254 squarings + 11 multiplications); a batch
 *     shares one inversion (Montgomery's trick, which is multiplications only).
 *   - Secrets on the stack are wiped (cc_wipe) before returning; cc_skey_free wipes the key.
 * Checked by tests/test_ct.c (valgrind, the seed marked secret), tests/ct_trace.c (identical instruction and address
 * traces under two seeds, SDE / qemu) and tests/dudect_sign.c (fixed vs random seed). */

#if defined(CC_ED25519_ASM) && !defined(CC_NO_ED25519_ASM) && defined(__x86_64__) && defined(__ELF__)
/* -DJWT_ED25519_ASM (the Makefile's default on x86-64 Linux): [n] B is s2n-bignum's edwards25519_scalarmulbase
 * (crypto/src/s2n/, vendored; formally verified; constant time: its table is read with cmov over whole blocks, and it
 * returns the affine point, fully reduced, after its own constant-time inversion).  It needs BMI2 + ADX; the _alt
 * version (plain mul / adc) runs on every other x86-64.  The key then keeps no table, and a batch needs no shared
 * inversion.  -DJWT_NO_ED25519_ASM keeps the portable code below (the tests run both). */
#define CC_SIGN_S2N 1
void cc_s2n_edwards25519_scalarmulbase(uint64_t res[8], const uint64_t scalar[4]);
void cc_s2n_edwards25519_scalarmulbase_alt(uint64_t res[8], const uint64_t scalar[4]);
#endif

typedef uint64_t sg_fe[5]; /* fiat's 5 x 51-bit limbs */
typedef struct {
    sg_fe X, Y, Z, T; /* extended: x = X/Z, y = Y/Z, xy = T/Z */
} sg_p3;
typedef struct {
    sg_fe ypx, ymx, xy2d; /* y + x, y - x, 2 d x y of an affine point */
} sg_niels;
typedef uint64_t sg_sc[4]; /* a scalar mod L, 4 x 64-bit little-endian limbs (fiat's scalar representation) */

struct cc_skey {
    int alg;
#ifndef CC_SIGN_S2N
    sg_niels tab[32][8]; /* tab[j][i] = (i + 1) 256^j B: public */
#endif
    sg_sc a_m;          /* the secret scalar a mod L, Montgomery form */
    uint8_t prefix[32]; /* the nonce key */
    uint8_t pub[32];    /* A, encoded */
    /* ES256 (cc_sign_es256.inc) */
    uint8_t es_d[32];             /* d, big-endian (RFC 6979's int2octets(d)) */
    uint64_t es_dm[4];            /* d R mod n (fiat's p256_scalar Montgomery form) */
    uint8_t es_qx[32], es_qy[32]; /* the public point */
    cc_pkey_t *vk;                /* the public key, when verify-after-sign is on */
    /* RS256 (cc_sign_rs256.inc, -DJWT_OPENSSL): libcrypto's key */
    void *rs_pkey;
    int rs_bytes; /* the modulus' bytes: the signature's length */
};

/* ---- field helpers: fiat calls only ---- */
#define SG_MUL(o, a, b) fiat_25519_carry_mul(o, a, b)
#define SG_SQR(o, a)    fiat_25519_carry_square(o, a)
static void sg_add(sg_fe o, const sg_fe a, const sg_fe b) {
    sg_fe t;
    fiat_25519_add(t, a, b);
    fiat_25519_carry(o, t);
}
static void sg_sub(sg_fe o, const sg_fe a, const sg_fe b) {
    sg_fe t;
    fiat_25519_sub(t, a, b);
    fiat_25519_carry(o, t);
}
static void sg_neg(sg_fe o, const sg_fe a) {
    sg_fe t;
    fiat_25519_opp(t, a);
    fiat_25519_carry(o, t);
}
static void sg_set(sg_fe o, uint64_t v) { o[0] = v, o[1] = o[2] = o[3] = o[4] = 0; }
static void sg_sqn(sg_fe o, const sg_fe a, int n) { /* n is a constant of the chain */
    SG_SQR(o, a);
    while (--n > 0) SG_SQR(o, o);
}
/* z^(p-2), a fixed addition chain: the same operations for every z */
static void sg_inv(sg_fe o, const sg_fe z) {
    sg_fe t0, t1, t2, t3;
    SG_SQR(t0, z);                           /* 2 */
    sg_sqn(t1, t0, 2), SG_MUL(t1, z, t1);    /* 9 */
    SG_MUL(t0, t0, t1);                      /* 11 */
    SG_SQR(t2, t0), SG_MUL(t1, t1, t2);      /* 2^5 - 1 */
    sg_sqn(t2, t1, 5), SG_MUL(t1, t2, t1);   /* 2^10 - 1 */
    sg_sqn(t2, t1, 10), SG_MUL(t2, t2, t1);  /* 2^20 - 1 */
    sg_sqn(t3, t2, 20), SG_MUL(t2, t3, t2);  /* 2^40 - 1 */
    sg_sqn(t2, t2, 10), SG_MUL(t1, t2, t1);  /* 2^50 - 1 */
    sg_sqn(t2, t1, 50), SG_MUL(t2, t2, t1);  /* 2^100 - 1 */
    sg_sqn(t3, t2, 100), SG_MUL(t2, t3, t2); /* 2^200 - 1 */
    sg_sqn(t2, t2, 50), SG_MUL(t1, t2, t1);  /* 2^250 - 1 */
    sg_sqn(t1, t1, 5), SG_MUL(o, t1, t0);    /* 2^255 - 21 = p - 2 */
}

/* ---- point arithmetic, complete formulas (a = -1, d non-square) ---- */
/* P += q (affine Niels): ref10's ge_madd, 7M */
static void sg_madd(sg_p3 *P, const sg_niels *q) {
    sg_fe a, b, c, d, e, f, g, h;
    fiat_25519_sub(a, P->Y, P->X), SG_MUL(a, a, q->ymx);
    fiat_25519_add(b, P->Y, P->X), SG_MUL(b, b, q->ypx);
    SG_MUL(c, P->T, q->xy2d);
    sg_add(d, P->Z, P->Z);
    fiat_25519_sub(e, b, a), fiat_25519_sub(f, d, c), fiat_25519_add(g, d, c), fiat_25519_add(h, b, a);
    SG_MUL(P->X, e, f), SG_MUL(P->Y, g, h), SG_MUL(P->T, e, h), SG_MUL(P->Z, f, g);
}
/* P = 2P: dbl-2008-hwcd with a = -1, 4M + 4S */
static void sg_dbl(sg_p3 *P) {
    sg_fe a, b, c, e, f, g, h, t;
    SG_SQR(a, P->X), SG_SQR(b, P->Y), SG_SQR(c, P->Z), sg_add(c, c, c);
    sg_add(t, P->X, P->Y), SG_SQR(e, t), sg_sub(e, e, a), sg_sub(e, e, b);
    sg_sub(g, b, a);               /* D + B with D = -A */
    sg_sub(f, g, c);               /* G - C */
    sg_neg(h, a), sg_sub(h, h, b); /* D - B */
    SG_MUL(P->X, e, f), SG_MUL(P->Y, g, h), SG_MUL(P->T, e, h), SG_MUL(P->Z, f, g);
}
/* P += Q, both extended (add-2008-hwcd-3), for building the table from public points */
static void sg_add_p3(sg_p3 *P, const sg_p3 *Q, const sg_fe d2) {
    sg_fe a, b, c, d, e, f, g, h, t;
    fiat_25519_sub(a, P->Y, P->X), fiat_25519_sub(t, Q->Y, Q->X), SG_MUL(a, a, t);
    fiat_25519_add(b, P->Y, P->X), fiat_25519_add(t, Q->Y, Q->X), SG_MUL(b, b, t);
    SG_MUL(c, P->T, Q->T), SG_MUL(c, c, d2);
    SG_MUL(d, P->Z, Q->Z), sg_add(d, d, d);
    fiat_25519_sub(e, b, a), fiat_25519_sub(f, d, c), fiat_25519_add(g, d, c), fiat_25519_add(h, b, a);
    SG_MUL(P->X, e, f), SG_MUL(P->Y, g, h), SG_MUL(P->T, e, h), SG_MUL(P->Z, f, g);
}

/* all ones if x == y else 0, for small non-negative ints: arithmetic, then through an empty asm so the compiler can
 * neither see the value nor turn its uses into a branch */
static uint64_t sg_eqmask(uint32_t x, uint32_t y) {
    uint64_t m = 0 - (uint64_t)(((x ^ y) - 1u) >> 31);
#if defined(__GNUC__)
    __asm__("" : "+r"(m));
#endif
    return m;
}
/* t = d (i 256^j B for d = +-i, the identity for 0).  Every one of the row's 8 entries is read, whatever d is: each
 * is ANDed with its mask (all ones for the wanted one, else zero) and ORed in, so the loads, their addresses and the
 * instructions are the same for every d, and the loop vectorises.  Then a conditional negation, the same way. */
static void sg_select(sg_niels *t, const sg_niels row[8], int8_t d) {
    enum { W = (int)(sizeof(sg_niels) / sizeof(uint64_t)) };  /* 15 limbs: ypx, ymx, xy2d */
    uint32_t neg = (uint32_t)(uint8_t)d >> 7;                 /* 1 iff d < 0 */
    uint32_t mag = (uint32_t)(d - ((-(int32_t)neg & d) * 2)); /* |d|, 0..8 */
    uint64_t acc[W], m0 = sg_eqmask(mag, 0);
    for (int w = 0; w < W; w++) acc[w] = 0;
    acc[0] = m0 & 1, acc[5] = m0 & 1; /* the identity: y + x = y - x = 1, 2dxy = 0 */
    for (int i = 0; i < 8; i++) {
        uint64_t m = sg_eqmask(mag, (uint32_t)i + 1);
        const uint64_t *e = (const uint64_t *)&row[i];
        for (int w = 0; w < W; w++) acc[w] |= e[w] & m;
    }
    memcpy(t, acc, sizeof *t);
    sg_fe nxy; /* -(x, y) = (-x, y): swap y + x and y - x, negate 2dxy */
    sg_neg(nxy, t->xy2d);
    uint64_t mn = sg_eqmask(neg, 1);
    for (int w = 0; w < 5; w++) {
        uint64_t p = t->ypx[w], q = t->ymx[w], x = (p ^ q) & mn;
        t->ypx[w] = p ^ x, t->ymx[w] = q ^ x;
        t->xy2d[w] ^= (t->xy2d[w] ^ nxy[w]) & mn;
    }
    cc_wipe(nxy, sizeof nxy), cc_wipe(acc, sizeof acc);
}
/* P = [s] B for a scalar s < 2^255 given as 32 little-endian bytes (ref10's ge_scalarmult_base) */
static void sg_base_mul(sg_p3 *P, const sg_niels tab[32][8], const uint8_t s[32]) {
    int8_t e[64];
    for (int i = 0; i < 32; i++) e[2 * i] = (int8_t)(s[i] & 15), e[2 * i + 1] = (int8_t)(s[i] >> 4);
    int8_t carry = 0; /* to signed digits in [-8, 8): arithmetic only */
    for (int i = 0; i < 63; i++) {
        e[i] = (int8_t)(e[i] + carry);
        carry = (int8_t)((e[i] + 8) >> 4); /* e[i] + 8 is in 8..24: no sign to shift */
        e[i] = (int8_t)(e[i] - carry * 16);
    }
    e[63] = (int8_t)(e[63] + carry); /* s < 2^255: the top digit stays <= 8 */
    sg_niels t;
    sg_set(P->X, 0), sg_set(P->Y, 1), sg_set(P->Z, 1), sg_set(P->T, 0);
    for (int i = 1; i < 64; i += 2) sg_select(&t, tab[i / 2], e[i]), sg_madd(P, &t);
    sg_dbl(P), sg_dbl(P), sg_dbl(P), sg_dbl(P);
    for (int i = 0; i < 64; i += 2) sg_select(&t, tab[i / 2], e[i]), sg_madd(P, &t);
    cc_wipe(e, sizeof e), cc_wipe(&t, sizeof t);
}
/* the encoding of P given 1/Z: y with the parity of x in the top bit */
static void sg_encode(uint8_t out[32], const sg_p3 *P, const sg_fe zi) {
    sg_fe x, y;
    uint8_t xb[32];
    SG_MUL(x, P->X, zi), SG_MUL(y, P->Y, zi);
    fiat_25519_to_bytes(out, y), fiat_25519_to_bytes(xb, x);
    out[31] |= (uint8_t)((xb[0] & 1) << 7);
    cc_wipe(x, sizeof x), cc_wipe(y, sizeof y), cc_wipe(xb, sizeof xb);
}

#ifdef CC_SIGN_S2N
/* out = the encoding of [s] B, for a scalar s given as 32 little-endian bytes */
static void sg_base_encode_s2n(uint8_t out[32], const uint8_t s[32]) {
    uint64_t sc[4], res[8];
    for (int i = 0; i < 4; i++) {
        uint64_t v = 0;
        for (int j = 7; j >= 0; j--) v = v << 8 | s[8 * i + j];
        sc[i] = v;
    }
    if (cc_cpu() & CC_CPU_BMI2_ADX) cc_s2n_edwards25519_scalarmulbase(res, sc); /* (a branch on the CPU only) */
    else cc_s2n_edwards25519_scalarmulbase_alt(res, sc);
    for (int i = 0; i < 4; i++) /* y, little-endian, then the parity of x in the top bit */
        for (int j = 0; j < 8; j++) out[8 * i + j] = (uint8_t)(res[4 + i] >> (8 * j));
    out[31] |= (uint8_t)((res[0] & 1) << 7);
    cc_wipe(sc, sizeof sc), cc_wipe(res, sizeof res);
}
#endif

/* ---- scalars mod L: fiat's Montgomery arithmetic ---- */
/* x mod L, Montgomery form, for a 512-bit little-endian x: x = x0 + x1 2^252 + x2 2^504 with x0, x1 < 2^252 and
 * x2 < 2^8, all < L, so each is a valid fiat input. */
static void sg_sc_reduce(sg_sc out_m, const uint8_t x[64]) {
    uint64_t w[8], p[3][4];
    for (int i = 0; i < 8; i++) {
        uint64_t v = 0;
        for (int j = 7; j >= 0; j--) v = v << 8 | x[8 * i + j];
        w[i] = v;
    }
    const uint64_t m60 = (1ull << 60) - 1;
    p[0][0] = w[0], p[0][1] = w[1], p[0][2] = w[2], p[0][3] = w[3] & m60;
    for (int i = 0; i < 4; i++) p[1][i] = w[3 + i] >> 60 | w[4 + i] << 4;
    p[1][3] &= m60;
    p[2][0] = w[7] >> 56, p[2][1] = p[2][2] = p[2][3] = 0;
    /* Montgomery products (x y / R mod L, R = 2^256) with R^2, 2^252 R^2 and 2^504 R^2 mod L give x0 R, x1 2^252 R
     * and x2 2^504 R: their sum is x R, the Montgomery form of x mod L, in three products and two additions.  The
     * constants are reduced mod L, as fiat requires. */
    static const sg_sc R2 = { 0xa40611e3449c0f01ull, 0xd00e1ba768859347ull, 0xceec73d217f5be65ull,
                              0x0399411b7c309a3dull };
    static const sg_sc K1 = { 0x54343c555c028163ull, 0x5e359edba69ac777ull, 0x78065dc6c04ec5b6ull,
                              0x09e530b773599cecull }; /* 2^252 R^2 mod L */
    static const sg_sc K2 = { 0x81e91088eac17b3full, 0x605bf084507c17c7ull, 0xd7e7faf80eb68700ull,
                              0x05f9dc924e5a45ffull }; /* 2^504 R^2 mod L */
    sg_sc m0, m1, m2;
    fiat_25519_scalar_mul(m0, p[0], R2);
    fiat_25519_scalar_mul(m1, p[1], K1);
    fiat_25519_scalar_mul(m2, p[2], K2);
    fiat_25519_scalar_add(m0, m0, m1);
    fiat_25519_scalar_add(out_m, m0, m2);
    cc_wipe(w, sizeof w), cc_wipe(p, sizeof p), cc_wipe(m0, sizeof m0), cc_wipe(m1, sizeof m1), cc_wipe(m2, sizeof m2);
}
static void sg_sc_bytes(uint8_t out[32], const sg_sc m) { /* from Montgomery form to 32 little-endian bytes */
    sg_sc v;
    fiat_25519_scalar_from_montgomery(v, m);
    fiat_25519_scalar_to_bytes(out, v);
    cc_wipe(v, sizeof v);
}

/* ---- key setup ---- */
/* the table of i 256^j B, from the base point's affine coordinates (public data; the formulas are the same ones) */
static int sg_table(sg_niels tab[32][8]) {
    static const uint8_t bx[32] = { 0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25,
                                    0x95, 0x60, 0xc7, 0x2c, 0x69, 0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2,
                                    0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21 };
    static const uint8_t by[32] = { 0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                                    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                                    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66 };
    sg_fe d2, num, den; /* 2d = 2 * -121665 / 121666 */
    sg_set(num, 121665), sg_neg(num, num), sg_add(num, num, num);
    sg_set(den, 121666), sg_inv(den, den);
    SG_MUL(d2, num, den);
    sg_p3 base, pts[8];
    memset(&base, 0, sizeof base); /* (every field is set below; for static analysers) */
    fiat_25519_from_bytes(base.X, bx), fiat_25519_from_bytes(base.Y, by);
    sg_set(base.Z, 1), SG_MUL(base.T, base.X, base.Y);
    sg_fe z[256], pre[256], inv, zi, x, y;
    sg_p3 *all = malloc(sizeof(sg_p3) * 256);
    if (!all) return 0;
    for (int j = 0; j < 32; j++) {
        pts[0] = base;
        for (int i = 1; i < 8; i++) pts[i] = pts[i - 1], sg_add_p3(&pts[i], &base, d2);
        for (int i = 0; i < 8; i++) all[8 * j + i] = pts[i];
        base = pts[7]; /* 256 B = 2^5 (8 B) */
        for (int i = 0; i < 5; i++) sg_dbl(&base);
    }
    for (int i = 0; i < 256; i++) memcpy(z[i], all[i].Z, sizeof(sg_fe));
    memcpy(pre[0], z[0], sizeof(sg_fe));
    for (int i = 1; i < 256; i++) SG_MUL(pre[i], pre[i - 1], z[i]);
    sg_inv(inv, pre[255]);
    for (int i = 255; i >= 0; i--) {
        if (i) SG_MUL(zi, inv, pre[i - 1]), SG_MUL(inv, inv, z[i]);
        else memcpy(zi, inv, sizeof zi);
        sg_niels *q = &tab[i / 8][i % 8];
        SG_MUL(x, all[i].X, zi), SG_MUL(y, all[i].Y, zi);
        sg_add(q->ypx, y, x), sg_sub(q->ymx, y, x);
        SG_MUL(q->xy2d, x, y), SG_MUL(q->xy2d, q->xy2d, d2);
    }
    free(all);
    return 1;
}

cc_skey_t *cc_skey_ed25519(const uint8_t seed[32]) {
    cc_skey_t *k = calloc(1, sizeof *k);
    if (!k) return NULL;
    k->alg = CC_PK_ED25519;
#ifndef CC_SIGN_S2N
    if (!sg_table(k->tab)) {
        free(k);
        return NULL;
    }
#endif
    uint8_t h[64], a[64] = { 0 };
    cc_sha512(seed, 32, h);
    memcpy(a, h, 32);
    a[0] &= 248, a[31] &= 127, a[31] |= 64;
    memcpy(k->prefix, h + 32, 32);
    sg_sc_reduce(k->a_m, a); /* a mod L: [a] B = [a mod L] B, and S needs it reduced */
    uint8_t ar[32];
    sg_sc_bytes(ar, k->a_m);
#ifdef CC_SIGN_S2N
    sg_base_encode_s2n(k->pub, ar);
#else
    sg_p3 A;
    sg_fe zi;
    sg_base_mul(&A, (const sg_niels(*)[8])k->tab, ar);
    sg_inv(zi, A.Z);
    sg_encode(k->pub, &A, zi);
    cc_wipe(&A, sizeof A), cc_wipe(zi, sizeof zi);
#endif
    cc_wipe(h, sizeof h), cc_wipe(a, sizeof a), cc_wipe(ar, sizeof ar);
    return k;
}
/* RS256 (delegated to libcrypto under -DJWT_OPENSSL) */
#include "cc_sign_rs256.inc"

void cc_skey_free(cc_skey_t *k) {
    if (!k) return;
    cc_pkey_free(k->vk);
    if (k->alg == CC_PK_RS256) rs_free(k); /* (libcrypto clears its own key material) */
    cc_wipe(k, sizeof *k);
    free(k);
}
int cc_skey_alg(const cc_skey_t *k) { return k->alg; }
int cc_skey_sig_bytes(const cc_skey_t *k) {
    return k->alg == CC_PK_RS256 ? k->rs_bytes : k->alg == CC_PK_ED25519 || k->alg == CC_PK_ES256 ? 64 : 0;
}
void cc_skey_public(const cc_skey_t *k, uint8_t pub[32]) { memcpy(pub, k->pub, 32); }

/* ---- signing ---- */
static void ed_sign_batch(const cc_skey_t *k, int n, const uint8_t *const *msg, const int *len, uint8_t *const *sig) {
    enum { CH = 16 };
    for (int base = 0; base < n; base += CH) {
        int m = n - base < CH ? n - base : CH;
        if (m < 1) break; /* (never: base < n; it tells the compiler, which can't prove it under -fwrapv) */
        sg_p3 R[CH];
        sg_sc r_m[CH];
        memset(R, 0, sizeof R); /* (m >= 1 entries are set below; for static analysers) */
        sg_fe pre[CH], inv, zi;
        uint8_t h[64], rb[32];
        cc_sha512_ctx c;
        for (int i = 0; i < m; i++) { /* r = SHA-512(prefix || M) mod L, R = [r] B */
            cc_sha512_init(&c);
            cc_sha512_update(&c, k->prefix, 32);
            cc_sha512_update(&c, msg[base + i], (size_t)len[base + i]);
            cc_sha512_final(&c, h);
            sg_sc_reduce(r_m[i], h);
            sg_sc_bytes(rb, r_m[i]);
#ifdef CC_SIGN_S2N
            sg_base_encode_s2n(sig[base + i], rb); /* R, the signature's first half */
#else
            sg_base_mul(&R[i], (const sg_niels(*)[8])k->tab, rb);
#endif
        }
#ifndef CC_SIGN_S2N
        /* one inversion for the batch's Z (Montgomery's trick: multiplications only) */
        memcpy(pre[0], R[0].Z, sizeof(sg_fe));
        for (int i = 1; i < m; i++) SG_MUL(pre[i], pre[i - 1], R[i].Z);
        sg_inv(inv, pre[m - 1]);
        for (int i = m - 1; i >= 0; i--) {
            if (i) SG_MUL(zi, inv, pre[i - 1]), SG_MUL(inv, inv, R[i].Z);
            else memcpy(zi, inv, sizeof zi);
            sg_encode(sig[base + i], &R[i], zi); /* R, the signature's first half */
        }
#endif
        for (int i = 0; i < m; i++) { /* k = SHA-512(R || A || M) mod L, S = r + k a mod L */
            uint8_t *s = sig[base + i];
            sg_sc km, sm;
            cc_sha512_init(&c);
            cc_sha512_update(&c, s, 32);
            cc_sha512_update(&c, k->pub, 32);
            cc_sha512_update(&c, msg[base + i], (size_t)len[base + i]);
            cc_sha512_final(&c, h);
            sg_sc_reduce(km, h);
            fiat_25519_scalar_mul(sm, km, k->a_m); /* k a R */
            fiat_25519_scalar_add(sm, sm, r_m[i]); /* (r + k a) R */
            sg_sc_bytes(s + 32, sm);
            cc_wipe(km, sizeof km), cc_wipe(sm, sizeof sm);
        }
        cc_wipe(R, sizeof R), cc_wipe(r_m, sizeof r_m), cc_wipe(pre, sizeof pre), cc_wipe(inv, sizeof inv),
            cc_wipe(zi, sizeof zi), cc_wipe(h, sizeof h), cc_wipe(rb, sizeof rb);
    }
}

/* ---------------------------------------------------------------------------------- ES256 */
#include "cc_sign_es256.inc"

int cc_sign_batch(const cc_skey_t *k, int n, const uint8_t *const *msg, const int *len, uint8_t *const *sig) {
    if (k->alg == CC_PK_ES256) return es_sign_batch(k, n, msg, len, sig);
    if (k->alg == CC_PK_RS256) return rs_sign_batch(k, n, msg, len, sig);
    ed_sign_batch(k, n, msg, len, sig);
    return 0;
}
