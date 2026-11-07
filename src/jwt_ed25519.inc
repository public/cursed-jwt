/* jwt_ed25519.inc — EdDSA (Ed25519, RFC 8032; JWS "alg":"EdDSA", RFC 8037) verification, #included by jwt_pk.inc.
 *
 * The ES256 design again: a verifier keeps its public keys, so key setup builds signed-digit comb tables of
 * k * 2^(W j) for the base point B and for -A, and a verify is
 *     R' = [S] B + [k] (-A),   k = SHA-512(R || A || M) mod L
 * with 2 * ceil(254/W) mixed additions and no doublings.  Twisted Edwards addition with a = -1 is complete, so the
 * additions never branch.  The R' of a whole batch are normalised with one shared inversion (Montgomery's trick),
 * and the token is valid iff encode(R') == R byte for byte, with S < L.  That is RFC 8032's cofactorless check,
 * the one OpenSSL (and so pyca/cryptography and Wycheproof's "valid" set) implements.
 * Field and scalar arithmetic: fiat-crypto's generated, formally verified curve25519_64.c / curve25519_scalar_64.c
 * (MIT), fetched by scripts/fetch-fiat.sh.  Verification handles public data only, so nothing here is constant-time.
 */
#include "fiat/curve25519_64.c"
#include "fiat/curve25519_scalar_64.c"

#ifndef JWT_ED_W
#define JWT_ED_W 7 /* comb window: 37 rows x 64 points x 120 B = 284 KB per base point */
#endif
#define ED_NW ((254 + JWT_ED_W - 1) / JWT_ED_W)
#define ED_H  (1 << (JWT_ED_W - 1))

typedef uint64_t fe25_t[5]; /* fiat's unsaturated 5 x 51-bit limbs */
typedef struct {
    fe25_t X, Y, Z, T; /* extended coordinates: x = X/Z, y = Y/Z, xy = T/Z */
} ed_p3;
typedef struct {
    fe25_t ypx, ymx, xy2d; /* y + x, y - x, 2 d x y of an affine point ("Niels" form) */
} ed_niels;
#if defined(JWT_S2N) && defined(__x86_64__)
/* -DJWT_S2N on x86-64: the comb additions run on s2n-bignum's formally verified edwards25519_pepadd (BMI2 + ADX) or
 * edwards25519_pepadd_alt (plain mul / adc, any x86-64): extended projective += precomputed affine, 7M, with every
 * coordinate fully reduced mod p in 4 x 64-bit limbs.  Tables are stored in its (y - x, y + x, 2dxy) order; the
 * accumulated point goes back to fiat's limbs once, for the batched inversion and the encoding. */
#define JWT_ED_S2N 1
typedef uint64_t ed_pp4[12];
void edwards25519_pepadd(uint64_t p3[16], const uint64_t p1[16], const uint64_t p2[12]);
void edwards25519_pepadd_alt(uint64_t p3[16], const uint64_t p1[16], const uint64_t p2[12]);
#endif
typedef struct ed_key {
#ifdef JWT_ED_S2N
    ed_pp4 tb[ED_NW][ED_H], ta[ED_NW][ED_H]; /* B and -A */
#else
    ed_niels tb[ED_NW][ED_H], ta[ED_NW][ED_H]; /* B and -A */
#endif
    uint8_t a[32]; /* the public key as given (hashed into k) */
} ed_key_t;

/* ---- field helpers over fiat's tight (carried) / loose (sum) bounds ---- */
#define F_MUL(o, a, b) fiat_25519_carry_mul(o, a, b)
#define F_SQR(o, a)    fiat_25519_carry_square(o, a)
static void f_add(fe25_t o, const fe25_t a, const fe25_t b) { /* tight result */
    fe25_t t;
    fiat_25519_add(t, a, b);
    fiat_25519_carry(o, t);
}
static void f_sub(fe25_t o, const fe25_t a, const fe25_t b) {
    fe25_t t;
    fiat_25519_sub(t, a, b);
    fiat_25519_carry(o, t);
}
static void f_neg(fe25_t o, const fe25_t a) {
    fe25_t t;
    fiat_25519_opp(t, a);
    fiat_25519_carry(o, t);
}
static void f_set(fe25_t o, uint64_t v) { o[0] = v, o[1] = o[2] = o[3] = o[4] = 0; }
static int f_eq(const fe25_t a, const fe25_t b) { /* canonical comparison */
    uint8_t x[32], y[32];
    fiat_25519_to_bytes(x, a), fiat_25519_to_bytes(y, b);
    return !memcmp(x, y, 32);
}
static int f_iszero(const fe25_t a) {
    uint8_t x[32], z[32] = { 0 };
    fiat_25519_to_bytes(x, a);
    return !memcmp(x, z, 32);
}
/* a^e for e given little-endian: init only (and once per batch) */
static void f_pow(fe25_t o, const fe25_t a, const uint8_t e[32]) {
    fe25_t r;
    f_set(r, 1);
    for (int i = 255; i >= 0; i--) {
        F_SQR(r, r);
        if (e[i >> 3] >> (i & 7) & 1) F_MUL(r, r, a);
    }
    memcpy(o, r, sizeof r);
}
static const uint8_t ED_P_MINUS_2[32] = { 0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f };
static const uint8_t ED_P_SQRT_EXP[32] = {
    0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* (p-5)/8 */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f
};
static void f_sqn(fe25_t o, const fe25_t a, int n) {
    F_SQR(o, a);
    while (--n > 0) F_SQR(o, o);
}
/* a^(p-2) with the standard addition chain (ref10's fe_invert): 254 squarings + 11 multiplications, not ~500 */
static void f_inv(fe25_t o, const fe25_t z) {
    fe25_t t0, t1, t2, t3;
    F_SQR(t0, z);                          /* 2 */
    f_sqn(t1, t0, 2), F_MUL(t1, z, t1);    /* 9 */
    F_MUL(t0, t0, t1);                     /* 11 */
    F_SQR(t2, t0), F_MUL(t1, t1, t2);      /* 2^5 - 1 */
    f_sqn(t2, t1, 5), F_MUL(t1, t2, t1);   /* 2^10 - 1 */
    f_sqn(t2, t1, 10), F_MUL(t2, t2, t1);  /* 2^20 - 1 */
    f_sqn(t3, t2, 20), F_MUL(t2, t3, t2);  /* 2^40 - 1 */
    f_sqn(t2, t2, 10), F_MUL(t1, t2, t1);  /* 2^50 - 1 */
    f_sqn(t2, t1, 50), F_MUL(t2, t2, t1);  /* 2^100 - 1 */
    f_sqn(t3, t2, 100), F_MUL(t2, t3, t2); /* 2^200 - 1 */
    f_sqn(t2, t2, 50), F_MUL(t1, t2, t1);  /* 2^250 - 1 */
    f_sqn(t1, t1, 5), F_MUL(o, t1, t0);    /* 2^255 - 21 = p - 2 */
}

static fe25_t ED_D, ED_D2, ED_SQRTM1; /* d = -121665/121666, 2d, sqrt(-1): set once by ed_consts() */
static void ed_consts(void) {
    static int done;
    if (__atomic_load_n(&done, __ATOMIC_ACQUIRE)) return;
    fe25_t num, den, t;
    f_set(num, 121665), f_neg(num, num);
    f_set(den, 121666), f_inv(den, den);
    F_MUL(t, num, den);
    static const uint8_t pm1_4[32] = { 0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* (p-1)/4 */
                                       0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                       0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f };
    fe25_t two, s;
    f_set(two, 2);
    f_pow(s, two, pm1_4);
    memcpy(ED_D, t, sizeof t), f_add(ED_D2, t, t), memcpy(ED_SQRTM1, s, sizeof s);
    __atomic_store_n(&done, 1, __ATOMIC_RELEASE); /* racing initialisers compute the same values */
}

/* RFC 8032 5.1.3 decoding: y from the low 255 bits (canonical, < p), x = sqrt((y^2-1)/(d y^2+1)) with the sign
 * bit's parity.  0 if no such point. */
static int ed_decode(ed_p3 *P, const uint8_t s[32]) {
    uint8_t b[32];
    memcpy(b, s, 32);
    int sign = b[31] >> 7;
    b[31] &= 0x7f;
    static const uint8_t p_le[32] = { 0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f };
    int i = 31;
    while (i > 0 && b[i] == p_le[i]) i--;
    if (b[i] >= p_le[i]) return 0; /* y >= p: not canonical */
    fe25_t y, u, v, v3, x, t, one;
    fiat_25519_from_bytes(y, b);
    f_set(one, 1);
    F_SQR(u, y);
    F_MUL(v, u, ED_D);
    f_sub(u, u, one); /* u = y^2 - 1 */
    f_add(v, v, one); /* v = d y^2 + 1 */
    /* x = u v^3 (u v^7)^((p-5)/8) */
    F_SQR(v3, v), F_MUL(v3, v3, v);
    F_SQR(t, v3), F_MUL(t, t, v), F_MUL(t, t, u); /* u v^7 */
    f_pow(t, t, ED_P_SQRT_EXP);
    F_MUL(x, t, v3), F_MUL(x, x, u);
    F_SQR(t, x), F_MUL(t, t, v); /* v x^2 */
    if (!f_eq(t, u)) {
        fe25_t nu;
        f_neg(nu, u);
        if (!f_eq(t, nu)) return 0;
        F_MUL(x, x, ED_SQRTM1);
    }
    uint8_t xb[32];
    fiat_25519_to_bytes(xb, x);
    if (f_iszero(x) && sign) return 0;
    if ((xb[0] & 1) != sign) f_neg(x, x);
    memcpy(P->X, x, sizeof x), memcpy(P->Y, y, sizeof y), f_set(P->Z, 1), F_MUL(P->T, x, y);
    return 1;
}

#ifndef JWT_ED_S2N /* (with s2n-bignum on x86-64, edwards25519_pepadd does these) */
/* P += Q (Niels), ref10's ge_madd: 8M */
static void ed_madd(ed_p3 *P, const ed_niels *q) {
    fe25_t a, b, c, d, e, f, g, h;
    f_sub(a, P->Y, P->X), F_MUL(a, a, q->ymx);
    f_add(b, P->Y, P->X), F_MUL(b, b, q->ypx);
    F_MUL(c, P->T, q->xy2d);
    f_add(d, P->Z, P->Z);
    f_sub(e, b, a), f_sub(f, d, c), f_add(g, d, c), f_add(h, b, a);
    F_MUL(P->X, e, f), F_MUL(P->Y, g, h), F_MUL(P->T, e, h), F_MUL(P->Z, f, g);
}
/* P += -Q (Niels): swap y+x / y-x, negate 2dxy */
static void ed_msub(ed_p3 *P, const ed_niels *q) {
    fe25_t a, b, c, d, e, f, g, h;
    f_sub(a, P->Y, P->X), F_MUL(a, a, q->ypx);
    f_add(b, P->Y, P->X), F_MUL(b, b, q->ymx);
    F_MUL(c, P->T, q->xy2d);
    f_add(d, P->Z, P->Z);
    f_sub(e, b, a), f_add(f, d, c), f_sub(g, d, c), f_add(h, b, a);
    F_MUL(P->X, e, f), F_MUL(P->Y, g, h), F_MUL(P->T, e, h), F_MUL(P->Z, f, g);
}
#endif
/* P = P + Q, both extended (add-2008-hwcd-3, a = -1): table building only */
static void ed_add(ed_p3 *P, const ed_p3 *Q) {
    fe25_t a, b, c, d, e, f, g, h, t;
    f_sub(a, P->Y, P->X), f_sub(t, Q->Y, Q->X), F_MUL(a, a, t);
    f_add(b, P->Y, P->X), f_add(t, Q->Y, Q->X), F_MUL(b, b, t);
    F_MUL(c, P->T, Q->T), F_MUL(c, c, ED_D2);
    F_MUL(d, P->Z, Q->Z), f_add(d, d, d);
    f_sub(e, b, a), f_sub(f, d, c), f_add(g, d, c), f_add(h, b, a);
    F_MUL(P->X, e, f), F_MUL(P->Y, g, h), F_MUL(P->T, e, h), F_MUL(P->Z, f, g);
}
static void ed_dbl(ed_p3 *P) { /* dbl-2008-hwcd, a = -1 */
    fe25_t a, b, c, e, f, g, h, t;
    F_SQR(a, P->X), F_SQR(b, P->Y), F_SQR(c, P->Z), f_add(c, c, c);
    f_add(t, P->X, P->Y), F_SQR(e, t), f_sub(e, e, a), f_sub(e, e, b);
    f_sub(g, b, a);              /* D + B with D = -A */
    f_sub(f, g, c);              /* G - C */
    f_neg(h, a), f_sub(h, h, b); /* D - B */
    F_MUL(P->X, e, f), F_MUL(P->Y, g, h), F_MUL(P->T, e, h), F_MUL(P->Z, f, g);
}

/* tab[w][k-1] = k 2^(W w) P in Niels form, k = 1..H */
static void ed_table(ed_niels tab[ED_NW][ED_H], const ed_p3 *P) {
    ed_p3 *jac = malloc(sizeof(ed_p3) * ED_H), base = *P;
    fe25_t *pre = malloc(sizeof(fe25_t) * ED_H);
    for (int w = 0; w < ED_NW; w++) {
        jac[0] = base;
        for (int k = 1; k < ED_H; k++) jac[k] = jac[k - 1], ed_add(&jac[k], &base);
        memcpy(pre[0], jac[0].Z, sizeof(fe25_t));
        for (int k = 1; k < ED_H; k++) F_MUL(pre[k], pre[k - 1], jac[k].Z);
        fe25_t inv, zi, x, y;
        f_inv(inv, pre[ED_H - 1]);
        for (int k = ED_H - 1; k >= 0; k--) {
            if (k) F_MUL(zi, inv, pre[k - 1]), F_MUL(inv, inv, jac[k].Z);
            else memcpy(zi, inv, sizeof zi);
            F_MUL(x, jac[k].X, zi), F_MUL(y, jac[k].Y, zi);
            f_add(tab[w][k].ypx, y, x), f_sub(tab[w][k].ymx, y, x);
            F_MUL(tab[w][k].xy2d, x, y), F_MUL(tab[w][k].xy2d, tab[w][k].xy2d, ED_D2);
        }
        base = jac[ED_H - 1]; /* 2^W base = 2 (H base) */
        ed_dbl(&base);
    }
    free(jac), free(pre);
}

/* ---- scalars mod L ---- */
static const uint8_t ED_L[32] = { 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
                                  0xa2, 0xde, 0xf9, 0xde, 0x14, 0,    0,    0,    0,    0,    0,
                                  0,    0,    0,    0,    0,    0,    0,    0,    0,    0x10 };
static int ed_lt_l(const uint8_t s[32]) { /* little-endian s < L */
    for (int i = 31; i >= 0; i--)
        if (s[i] != ED_L[i]) return s[i] < ED_L[i];
    return 0;
}
static void le_to_limbs(uint64_t o[4], const uint8_t *b) {
    for (int i = 0; i < 4; i++) {
        uint64_t v = 0;
        for (int j = 7; j >= 0; j--) v = v << 8 | b[8 * i + j];
        o[i] = v;
    }
}
/* x mod L for x < 2^256: subtract 8L, 4L, 2L, L when they fit (2^256 < 16 L) */
static void sc_reduce256(uint64_t x[4]) {
    uint64_t l[4];
    le_to_limbs(l, ED_L);
    for (int sh = 3; sh >= 0; sh--) {
        uint64_t m[4], cy = 0;
        for (int i = 0; i < 4; i++) m[i] = l[i] << sh | cy, cy = sh ? l[i] >> (64 - sh) : 0;
        int ge = 1;
        for (int i = 3; i >= 0; i--)
            if (x[i] != m[i]) {
                ge = x[i] > m[i];
                break;
            }
        if (!ge) continue;
        uint64_t bw = 0;
        for (int i = 0; i < 4; i++) {
            unsigned __int128 z = (unsigned __int128)x[i] - m[i] - bw;
            x[i] = (uint64_t)z, bw = (uint64_t)(z >> 64) & 1;
        }
    }
}
/* k = h mod L for a 512-bit little-endian h: lo + hi 2^256, through fiat's Montgomery arithmetic mod L */
static void sc_reduce512(uint64_t k[4], const uint8_t h[64]) {
    uint64_t lo[4], hi[4], one[4] = { 1 }, r2[4], r3[4], a[4], b[4];
    le_to_limbs(lo, h), le_to_limbs(hi, h + 32);
    sc_reduce256(lo), sc_reduce256(hi);
    fiat_25519_scalar_to_montgomery(r2, one); /* R */
    fiat_25519_scalar_to_montgomery(r2, r2);  /* R^2 */
    fiat_25519_scalar_to_montgomery(r3, r2);  /* R^3 */
    fiat_25519_scalar_mul(a, lo, r2);         /* lo R */
    fiat_25519_scalar_mul(b, hi, r3);         /* hi R^2 */
    fiat_25519_scalar_add(a, a, b);           /* (lo + hi R) R */
    fiat_25519_scalar_from_montgomery(k, a);
}
/* signed base-2^W digits of a scalar < 2^253 (little-endian limbs) */
static void ed_recode(int16_t d[ED_NW], const uint64_t u[4]) {
    int carry = 0;
    for (int w = 0; w < ED_NW; w++) {
        int bit = w * JWT_ED_W, li = bit >> 6, sh = bit & 63;
        uint64_t v = li < 4 ? u[li] >> sh : 0;
        if (sh + JWT_ED_W > 64 && li + 1 < 4) v |= u[li + 1] << (64 - sh);
        int c = (int)(v & ((1u << JWT_ED_W) - 1)) + carry;
        if (c > ED_H) d[w] = (int16_t)(c - 2 * ED_H), carry = 1;
        else d[w] = (int16_t)c, carry = 0;
    }
}

/* ---- SHA-512 (FIPS 180-4), streaming, for k = SHA-512(R || A || M) ---- */
static const uint64_t K512[80] = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull, 0x3956c25bf348b538ull,
    0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull, 0xd807aa98a3030242ull, 0x12835b0145706fbeull,
    0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull, 0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull,
    0xc19bf174cf692694ull, 0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
    0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull, 0x983e5152ee66dfabull,
    0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull, 0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull,
    0x06ca6351e003826full, 0x142929670a0e6e70ull, 0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull,
    0x53380d139d95b3dfull, 0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull,
    0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull, 0xd192e819d6ef5218ull,
    0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull, 0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull,
    0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull, 0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull, 0x5b9cca4f7763e373ull,
    0x682e6ff3d6b2b8a3ull, 0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull, 0xca273eceea26619cull,
    0xd186b8c721c0c207ull, 0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull, 0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull,
    0x113f9804bef90daeull, 0x1b710b35131c471bull, 0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull,
    0x431d67c49c100d4cull, 0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull, 0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull
};
#define ROR64(x, n) ((x) >> (n) | (x) << (64 - (n)))
static void sha512_block(uint64_t st[8], const uint8_t *p) {
    uint64_t w[80], a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
    for (int i = 0; i < 16; i++) {
        uint64_t v = 0;
        for (int j = 0; j < 8; j++) v = v << 8 | p[8 * i + j];
        w[i] = v;
    }
    for (int i = 16; i < 80; i++) {
        uint64_t s0 = ROR64(w[i - 15], 1) ^ ROR64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = ROR64(w[i - 2], 19) ^ ROR64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    for (int i = 0; i < 80; i++) {
        uint64_t t1 = h + (ROR64(e, 14) ^ ROR64(e, 18) ^ ROR64(e, 41)) + ((e & f) ^ (~e & g)) + K512[i] + w[i];
        uint64_t t2 = (ROR64(a, 28) ^ ROR64(a, 34) ^ ROR64(a, 39)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g, g = f, f = e, e = d + t1, d = c, c = b, b = a, a = t1 + t2;
    }
    st[0] += a, st[1] += b, st[2] += c, st[3] += d, st[4] += e, st[5] += f, st[6] += g, st[7] += h;
}
/* SHA-512(p1 (32 bytes) || p2 (32 bytes) || m) */
static void sha512_ram(uint8_t out[64], const uint8_t *p1, const uint8_t *p2, const uint8_t *m, size_t ml) {
    uint64_t st[8] = { 0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
                       0x510e527fade682d1ull, 0x9b05688c2b3e6c1full, 0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull };
    uint8_t blk[128];
    memcpy(blk, p1, 32), memcpy(blk + 32, p2, 32);
    size_t fill = 64, total = 64 + ml;
    while (ml) {
        size_t n = 128 - fill < ml ? 128 - fill : ml;
        memcpy(blk + fill, m, n), fill += n, m += n, ml -= n;
        if (fill == 128) sha512_block(st, blk), fill = 0;
    }
    blk[fill++] = 0x80;
    if (fill > 112) memset(blk + fill, 0, 128 - fill), sha512_block(st, blk), fill = 0;
    memset(blk + fill, 0, 128 - fill);
    uint64_t bits = (uint64_t)total * 8;
    for (int i = 0; i < 8; i++) blk[127 - i] = (uint8_t)(bits >> (8 * i));
    sha512_block(st, blk);
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++) out[8 * i + j] = (uint8_t)(st[i] >> (56 - 8 * j));
}

#ifdef JWT_ED_S2N
static void ed_fe_to4(uint64_t o[4], const fe25_t a) { /* canonical, little-endian limbs (x86-64 is little-endian) */
    fiat_25519_to_bytes((uint8_t *)o, a);
}
static int ed_table4(ed_pp4 out[ED_NW][ED_H], const ed_p3 *P) {
    ed_niels(*t)[ED_H] = malloc(sizeof(ed_niels) * ED_NW * ED_H);
    if (!t) return 0;
    ed_table(t, P);
    for (int w = 0; w < ED_NW; w++)
        for (int i = 0; i < ED_H; i++)
            ed_fe_to4(out[w][i], t[w][i].ymx), ed_fe_to4(out[w][i] + 4, t[w][i].ypx),
                ed_fe_to4(out[w][i] + 8, t[w][i].xy2d);
    free(t);
    return 1;
}
/* -Q = (-x, y): swap y - x and y + x, negate 2dxy (p - v; 0 stays 0) */
static void ed_neg4(uint64_t o[12], const uint64_t q[12]) {
    static const uint64_t p[4] = { 0xffffffffffffffedull, ~0ull, ~0ull, 0x7fffffffffffffffull };
    memcpy(o, q + 4, 32), memcpy(o + 4, q, 32);
    uint64_t z = q[8] | q[9] | q[10] | q[11], bw = 0;
    for (int j = 0; j < 4; j++) {
        u128 d = (u128)p[j] - q[8 + j] - bw;
        o[8 + j] = z ? (uint64_t)d : 0, bw = (uint64_t)(d >> 64) & 1;
    }
}
#include "jwt_ed25519_r43x6.inc"
#endif

/* ---- key setup and batch verification ---- */
static ed_key_t *ed_key_new(const uint8_t pub[32]) {
    ed_consts();
    ed_p3 A, B;
    if (!ed_decode(&A, pub)) return NULL;
    static const uint8_t b_enc[32] = { 0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                                       0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                                       0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66 };
    if (!ed_decode(&B, b_enc)) return NULL;
    ed_key_t *k = malloc(sizeof *k);
    if (!k) return NULL;
    memcpy(k->a, pub, 32);
    f_neg(A.X, A.X), f_neg(A.T, A.T); /* -A */
#ifdef JWT_ED_S2N
    if (!ed_table4(k->tb, &B) || !ed_table4(k->ta, &A)) {
        free(k);
        return NULL;
    }
#else
    ed_table(k->tb, &B), ed_table(k->ta, &A);
#endif
    return k;
}

static void ed25519_raw(const ed_key_t *k, int n, const uint8_t *const *msg, const int *len, const uint8_t *const *sig,
                        const int *slen, uint8_t *ok) {
    enum { CH = 32 };
#ifdef JWT_ED_S2N
    void (*pepadd)(uint64_t *, const uint64_t *, const uint64_t *) =
        s2n_ok() ? edwards25519_pepadd : edwards25519_pepadd_alt;
    const int r43 = ed_r43_ok();
#endif
    for (int base = 0; base < n; base += CH) {
        int m = n - base < CH ? n - base : CH, c = 0, at[CH];
        ed_p3 R[CH];
        for (int i = 0; i < m; i++) {
            int t = base + i;
            ok[t] = 0;
            if (slen[t] != 64 || !ed_lt_l(sig[t] + 32)) continue; /* S must be canonical */
            uint8_t h[64];
            uint64_t s[4], kk[4];
            sha512_ram(h, sig[t], k->a, msg[t], (size_t)len[t]);
            sc_reduce512(kk, h);
            le_to_limbs(s, sig[t] + 32);
            int16_t ds[ED_NW], dk[ED_NW];
            ed_recode(ds, s), ed_recode(dk, kk);
            ed_p3 *P = &R[c];
#ifdef JWT_ED_S2N
            if (r43) {
                ed_comb_r43(k, ds, dk, P);
                at[c++] = t;
                continue;
            }
            uint64_t P4[16] = { 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 }, nq[12]; /* the identity */
            for (int j = 0; j < ED_NW; j++) {
                if (ds[j] > 0) pepadd(P4, P4, k->tb[j][ds[j] - 1]);
                else if (ds[j] < 0) ed_neg4(nq, k->tb[j][-ds[j] - 1]), pepadd(P4, P4, nq);
                if (dk[j] > 0) pepadd(P4, P4, k->ta[j][dk[j] - 1]);
                else if (dk[j] < 0) ed_neg4(nq, k->ta[j][-dk[j] - 1]), pepadd(P4, P4, nq);
            }
            /* back to fiat (coordinates are < p, so canonical): the encoding below needs X, Y, Z */
            fiat_25519_from_bytes(P->X, (const uint8_t *)P4), fiat_25519_from_bytes(P->Y, (const uint8_t *)(P4 + 4));
            fiat_25519_from_bytes(P->Z, (const uint8_t *)(P4 + 8));
#else
            f_set(P->X, 0), f_set(P->Y, 1), f_set(P->Z, 1), f_set(P->T, 0); /* the identity: additions are complete */
            for (int j = 0; j < ED_NW; j++) {
                if (ds[j] > 0) ed_madd(P, &k->tb[j][ds[j] - 1]);
                else if (ds[j] < 0) ed_msub(P, &k->tb[j][-ds[j] - 1]);
                if (dk[j] > 0) ed_madd(P, &k->ta[j][dk[j] - 1]);
                else if (dk[j] < 0) ed_msub(P, &k->ta[j][-dk[j] - 1]);
            }
#endif
            at[c++] = t;
        }
        if (!c) continue;
        /* encode every R' with one inversion of all the Z (Montgomery's trick) */
        fe25_t pre[CH], inv, zi, x, y;
        memcpy(pre[0], R[0].Z, sizeof(fe25_t));
        for (int i = 1; i < c; i++) F_MUL(pre[i], pre[i - 1], R[i].Z);
        f_inv(inv, pre[c - 1]);
        for (int i = c - 1; i >= 0; i--) {
            if (i) F_MUL(zi, inv, pre[i - 1]), F_MUL(inv, inv, R[i].Z);
            else memcpy(zi, inv, sizeof zi);
            F_MUL(x, R[i].X, zi), F_MUL(y, R[i].Y, zi);
            uint8_t enc[32], xb[32];
            fiat_25519_to_bytes(enc, y), fiat_25519_to_bytes(xb, x);
            enc[31] |= (uint8_t)((xb[0] & 1) << 7);
            ok[at[i]] = !memcmp(enc, sig[at[i]], 32);
        }
    }
}
