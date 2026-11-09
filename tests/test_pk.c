/* test_pk.c — the RS256 / ES256 against tests/make_pk_vectors.py's output: Wycheproof, NIST
 * CAVP, RFC 7515 A.2/A.3 and random pyca/cryptography cases, all pre-checked against cryptography.
 *   ./test_pk pk_vectors.txt
 * Every raw vector runs alone, then each run of vectors under one key runs as whole batches in random order and in
 * random sub-batches (so invalid signatures sit next to valid ones: the batch inversion and, with -DJWT_RSA_SCREEN,
 * the screening fallback must still single them out).  Tokens run through jwt_verify_batch_pk at batch sizes 1-40. */
#include "jwt.c"

#include <stdio.h>

static int fails, checks;
#define CHECK(cond, ...)                                                                                               \
    do {                                                                                                               \
        checks++;                                                                                                      \
        if (!(cond)) {                                                                                                 \
            if (++fails <= 30) fprintf(stderr, "FAIL: " __VA_ARGS__), fputc('\n', stderr);                             \
        }                                                                                                              \
    } while (0)

static uint64_t rng = 0x243F6A8885A308D3ull;
static uint32_t rnd(void) {
    rng ^= rng << 13, rng ^= rng >> 7, rng ^= rng << 17;
    return (uint32_t)(rng >> 16);
}
static int unhex(const char *h, uint8_t *out) {
    if (!strcmp(h, "-")) return 0;
    int n = (int)strlen(h) / 2;
    for (int i = 0; i < n; i++) {
        unsigned v;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
    return n;
}

typedef struct {
    char src[96];
    uint8_t *msg, *sig;
    int ml, sl, expect;
} rv_t;

/* es: 0 RS256 (a = n, b = e), 1 ES256 (x, y), 2 EdDSA (a = the public key, b unused) */
static jwt_pkey_t *make_key(int es, const char *a, const char *b) {
    uint8_t k1[600], k2[600];
    int l1 = unhex(a, k1), l2 = unhex(b, k2);
    if (es == 2) return l1 == 32 ? jwt_pkey_ed25519(k1) : NULL;
    if (es) {
        if (l1 != 32 || l2 != 32) return NULL;
        return jwt_pkey_es256(k1, k2);
    }
    return jwt_pkey_rs256(k1, (size_t)l1, k2, (size_t)l2);
}

/* run vectors v[0..n-1] (same key) as one batch in the order given by ord */
static void run_batch(const jwt_pkey_t *k, rv_t *v, const int *ord, int n, const char *what) {
    const uint8_t *msg[64] = { 0 }, *sig[64] = { 0 };
    int ml[64] = { 0 }, sl[64] = { 0 };
    uint8_t ok[64];
    for (int i = 0; i < n; i++)
        msg[i] = v[ord[i]].msg, ml[i] = v[ord[i]].ml, sig[i] = v[ord[i]].sig, sl[i] = v[ord[i]].sl;
    jwt_pk_verify_raw(k, n, msg, ml, sig, sl, ok);
    for (int i = 0; i < n; i++)
        CHECK(ok[i] == v[ord[i]].expect, "%s (%s, batch of %d): got %d, want %d", v[ord[i]].src, what, n, ok[i],
              v[ord[i]].expect);
}

#ifdef JWT_ES8
static void es8_lanes(const jwt_pkey_t *k, rv_t *v, int n);
#endif
static void run_group(int es, const char *ka, const char *kb, rv_t *v, int n, long *nkey_rejected) {
    jwt_pkey_t *k = make_key(es, ka, kb);
    if (!k) { /* a key the library refuses (e.g. a point not on the curve): every vector must be invalid */
        for (int i = 0; i < n; i++) CHECK(!v[i].expect, "%s: key rejected but the vector is valid", v[i].src);
        *nkey_rejected += n;
        return;
    }
    int ord[64];
    for (int i = 0; i < n; i++) ord[0] = i, run_batch(k, v, ord, 1, "alone");
    for (int rep = 0; rep < 6; rep++) {
        int m = n < 64 ? n : 64;
        for (int i = 0; i < m; i++) ord[i] = (int)(rnd() % n); /* with repeats */
        run_batch(k, v, ord, 1 + (int)(rnd() % m), "random sub-batch");
    }
    for (int base = 0; base < n; base += 64) { /* all of them, shuffled */
        int m = n - base < 64 ? n - base : 64;
        for (int i = 0; i < m; i++) ord[i] = base + i;
        for (int i = m - 1; i > 0; i--) {
            int j = (int)(rnd() % (i + 1)), t = ord[i];
            ord[i] = ord[j], ord[j] = t;
        }
        run_batch(k, v, ord, m, "whole group");
    }
#ifdef JWT_ES8
    if (es == 1) es8_lanes(k, v, n);
#endif
    jwt_pkey_free(k);
}

typedef struct {
    char src[96], *tok;
    int len, status;
    int64_t now, uid;
    char user[300];
} jt_t;

static void run_tokens(const jwt_pkey_t *k, jt_t *t, int n) {
    for (int bs = 1; bs <= 40; bs += bs < 4 ? 1 : 7) {
        for (int base = 0; base < n; base += bs) {
            int m = n - base < bs ? n - base : bs;
            const char *tp[64];
            int tl[64];
            jwt_result_t r[64];
            /* tokens with different "now" go in separate calls */
            for (int i = 0; i < m; i++) tp[i] = t[base + i].tok, tl[i] = t[base + i].len;
            int same = 1;
            for (int i = 1; i < m; i++) same &= t[base + i].now == t[base].now;
            if (same) {
                jwt_verify_batch_pk(k, m, tp, tl, t[base].now, r);
            } else {
                for (int i = 0; i < m; i++) jwt_verify_batch_pk(k, 1, tp + i, tl + i, t[base + i].now, r + i);
            }
            for (int i = 0; i < m; i++) {
                const jt_t *e = &t[base + i];
                int good = r[i].status == e->status;
                if (good && e->status == JWT_OK)
                    good = r[i].uid == e->uid && r[i].username_len == strlen(e->user) &&
                           !memcmp(r[i].username, e->user, strlen(e->user));
                CHECK(good, "%s (batch %d): status %d uid %lld user %.*s, want %d %lld %s", e->src, bs, r[i].status,
                      (long long)r[i].uid, r[i].username_len, r[i].username, e->status, (long long)e->uid, e->user);
            }
        }
    }
}

/* the P-256-specific field multiplication and the binary-GCD scalar inverse against fiat-crypto's verified code */
static void rand_below(uint64_t o[4], const uint64_t m[4]) {
    do {
        for (int i = 0; i < 4; i++) o[i] = (uint64_t)rnd() << 32 ^ rnd();
        switch (rnd() % 8) { /* edge values */
            case 0: memcpy(o, m, 32), o[0] -= 1 + rnd() % 3; break;
            case 1: o[1] = o[2] = o[3] = 0, o[0] %= 4; break;
            case 2: o[3] = m[3], o[2] = m[2]; break;
        }
    } while (!u256_lt(o, m));
}
static void test_arith(void) {
    int bad = 0, n = 200000;
    for (int it = 0; it < n; it++) {
        uint64_t a[4], b[4], x[4], y[4];
        rand_below(a, P256_P), rand_below(b, P256_P);
        fiat_p256_mul(y, a, b);
        fe_mul_c(x, a, b), bad += memcmp(x, y, 32) != 0;
        fiat_p256_square(y, a);
        fe_sqr_c(x, a), bad += memcmp(x, y, 32) != 0;
        fiat_p256_add(y, a, b);
        fe_add_c(x, a, b), bad += memcmp(x, y, 32) != 0;
        fiat_p256_sub(y, a, b);
        fe_sub_c(x, a, b), bad += memcmp(x, y, 32) != 0;
#ifdef JWT_S2N
        if (s2n_ok()) {
            uint64_t z[4];
            fiat_p256_mul(y, a, b), bignum_montmul_p256(z, a, b), bad += memcmp(z, y, 32) != 0;
            fiat_p256_square(y, a), bignum_montsqr_p256(z, a), bad += memcmp(z, y, 32) != 0;
            fiat_p256_add(y, a, b), bignum_add_p256(z, a, b), bad += memcmp(z, y, 32) != 0;
            fiat_p256_sub(y, a, b), bignum_sub_p256(z, a, b), bad += memcmp(z, y, 32) != 0;
        }
#endif
#ifdef CC_S2N_ALT
        { /* the ADX-free kernels run on any x86-64 */
            uint64_t z[4];
            fiat_p256_mul(y, a, b), bignum_montmul_p256_alt(z, a, b), bad += memcmp(z, y, 32) != 0;
            fiat_p256_square(y, a), bignum_montsqr_p256_alt(z, a), bad += memcmp(z, y, 32) != 0;
        }
#endif
        rand_below(a, P256_N);
        if (fe_iszero(a)) continue;
        uint64_t am[4], im[4], one[4];
        fiat_p256_scalar_to_montgomery(am, a);
        sc_inv(im, am);
        fiat_p256_scalar_mul(one, im, am);
        fiat_p256_scalar_from_montgomery(one, one);
        bad += !u256_is1(one);
    }
    CHECK(!bad, "field / scalar arithmetic: %d mismatches against fiat-crypto", bad);
#ifdef JWT_S2N
    if (!s2n_ok()) printf("  s2n-bignum kernels: skipped, this CPU lacks BMI2/ADX (the C kernels run instead)\n");
    else { /* RSA-2048 Montgomery: s2n-bignum kernels vs the C ones */ uint8_t nb[256], e3[3] = { 1, 0, 1 };
        for (int i = 0; i < 256; i++) nb[i] = (uint8_t)rnd();
        nb[0] |= 0x80, nb[255] |= 1;
        cc_pkey_t *pk = cc_pkey_rs256(nb, 256, e3, 3);
        uint64_t u[32], v[32], w1[32], w2[32];
        int rb = 0;
        for (int it = 0; it < 20000; it++) {
            for (int i = 0; i < 32; i++) u[i] = (uint64_t)rnd() << 32 ^ rnd(), v[i] = (uint64_t)rnd() << 32 ^ rnd();
            u[31] &= pk->rsa.n[31] >> 1, v[31] &= pk->rsa.n[31] >> 1; /* < n */
            if (it & 1) memcpy(u, pk->rsa.n, 256), u[0] -= 2;         /* n - 2 */
            mont_mul_s2n(w1, u, v, &pk->rsa), mont_mul_32(w2, u, v, &pk->rsa), rb += memcmp(w1, w2, 256) != 0;
            mont_sqr_s2n(w1, u, &pk->rsa), mont_sqr_32(w2, u, &pk->rsa), rb += memcmp(w1, w2, 256) != 0;
        }
        CHECK(!rb, "RSA-2048 Montgomery: %d s2n-bignum / C mismatches", rb);
        cc_pkey_free(pk);
        printf("  s2n-bignum (-DJWT_S2N): P-256 field ops and RSA-2048 mont mul/sqr cross-checked\n");
    }
#endif
#ifdef CC_S2N_ALT
    printf("  s2n-bignum P-256 _alt mul/sqr (ADX-free) cross-checked against fiat-crypto\n");
#endif
    printf("  P-256 fe_mul/sqr/add/sub (selected and C) vs fiat-crypto, sc_inv: %d random + edge inputs\n", n);
}

#ifdef CC_ED_S2N
/* the radix-2^43 glue of cc_ed25519_r43x6.inc: ed_r43_canon against fiat-crypto on random and extreme limbs, and
 * ed_r43_from4 -> ed_r43_canon round trips (the latter on AVX-512 IFMA CPUs only) */
static void test_r43(void) {
    int bad = 0, n = 20000;
    fe25_t p43[6]; /* 2^(43 i) as fiat elements */
    for (int i = 0; i < 6; i++) {
        uint8_t b[32] = { 0 };
        b[(43 * i) / 8] = (uint8_t)(1u << ((43 * i) % 8));
        fiat_25519_from_bytes(p43[i], b);
    }
    for (int it = 0; it < n; it++) {
        long l[8] = { 0 };
        for (int i = 0; i < 6; i++) {
            uint64_t r = (uint64_t)rand() << 31 ^ (uint64_t)rand() << 62 ^ (uint64_t)rand();
            int mode = it % 5;
            l[i] = (long)(mode == 0 ? (1ull << 44) - 1 : mode == 1 ? r % 2 : r & ((1ull << 44) - 1));
        }
        if (it % 7 == 0) /* exactly p and p + 1 in radix 2^43 (limbs of 2^255 - 19, then + 1) */
            l[0] = (1L << 43) - 19 + (it % 14 == 0), l[1] = l[2] = l[3] = l[4] = (1L << 43) - 1, l[5] = (1L << 40) - 1;
        fe25_t acc, t, li;
        memset(acc, 0, sizeof acc);
        for (int i = 0; i < 6; i++) {
            uint8_t b[32] = { 0 };
            for (int j = 0; j < 8; j++) b[j] = (uint8_t)((uint64_t)l[i] >> (8 * j));
            fiat_25519_from_bytes(li, b);
            fiat_25519_carry_mul(t, li, p43[i]);
            fiat_25519_add(acc, acc, t), fiat_25519_carry(acc, acc);
        }
        uint8_t want[32], got[32];
        fiat_25519_to_bytes(want, acc);
        ed_r43_canon(got, l);
        bad += memcmp(want, got, 32) != 0;
        if (ed_r43_ok()) { /* canonical -> 43-bit limbs -> canonical */
            uint64_t v[4];
            memcpy(v, want, 32);
            long m[8];
            ed_r43_from4_store(m, v);
            ed_r43_canon(got, m);
            bad += memcmp(want, got, 32) != 0 || m[6] || m[7];
        }
    }
    CHECK(!bad, "EdDSA radix-2^43 glue: %d mismatches against fiat-crypto", bad);
    printf("  EdDSA radix-2^43 glue vs fiat-crypto: %d random + extreme limb sets%s\n", n,
           ed_r43_ok() ? ", with from4 round trips" : "");
}
#endif

#ifdef JWT_ES8
/* -DJWT_ES8 (crypto/src/cmb_ec/es8.c): crypto_mb's 8-lane field operations and the 8-lane comb against fiat-crypto and the
 * scalar code, on random and edge inputs, and 8-lane batches with one bad signature in each lane position */
void jwt_es8_comb(const void *tg, const void *tq, int nw, int h, const int16_t *const d1[8], const int16_t *const d2[8],
                  uint64_t x[8][4], uint64_t y[8][4], uint64_t z[8][4], unsigned *inf);
unsigned jwt_es8_fe(int op, uint64_t o[8][4], uint64_t ohi[8], const uint64_t a[8][4], const uint64_t b[8][4],
                    const uint64_t ahi[8], const uint64_t bhi[8]);
static const uint64_t P256_2P[5] = { 0xfffffffffffffffe, 0x00000001ffffffff, 0, 0xfffffffe00000002, 1 };
/* x in [0, 2p) as (4 limbs, bit 256): x mod p */
static void mod_p(uint64_t o[4], const uint64_t x[4], uint64_t hi) {
    memcpy(o, x, 32);
    if (hi || !u256_lt(o, P256_P)) u256_sub(o, o, P256_P);
}
static void rand_2p(uint64_t o[4], uint64_t *hi) { /* [0, 2p), with edges: 0, 1, p - 1, p, p + 1, 2p - 1 */
    uint64_t t[4];
    rand_below(t, P256_P);
    *hi = 0;
    switch (rnd() % 10) {
        case 0: memset(t, 0, 32), t[0] = rnd() % 2; break;
        case 1: memcpy(t, P256_P, 32), t[0] -= 1; break;
        case 2: memcpy(t, P256_P, 32), t[0] += rnd() % 2; break; /* p, p + 1 */
        case 3:
            memcpy(t, P256_2P, 32), *hi = 1, t[0] -= 1;
            memcpy(o, t, 32);
            return; /* 2p - 1 */
    }
    if (rnd() % 2 && u256_lt(t, P256_P)) *hi = u256_add(t, t, P256_P); /* t + p: the other representative */
    memcpy(o, t, 32);
}
static void test_es8_field(void) {
    int bad = 0, range = 0, n = 20000;
    uint64_t c4[4] = { 0, 0, 0, 1ull << 60 }; /* 2^252 as a plain integer: fiat_mul(x, c4) = x 2^-4 */
    for (int it = 0; it < n; it++) {
        uint64_t a[8][4], b[8][4], ah[8], bh[8], o[8][4], oh[8];
        for (int l = 0; l < 8; l++) rand_2p(a[l], &ah[l]), rand_2p(b[l], &bh[l]);
        for (int op = 0; op <= 6; op++) {
            if (op == 5) /* to260 takes fiat-domain values < p */
                for (int l = 0; l < 8; l++) rand_below(a[l], P256_P), ah[l] = 0;
            range +=
                __builtin_popcount(jwt_es8_fe(op, o, oh, (const uint64_t(*)[4])a, (const uint64_t(*)[4])b, ah, bh));
            for (int l = 0; l < 8; l++) {
                uint64_t x[4], y[4], want[4], got[4];
                mod_p(x, a[l], ah[l]), mod_p(y, b[l], bh[l]);
                switch (op) {
                    case 0: fiat_p256_mul(want, x, y), fiat_p256_mul(want, want, c4); break;
                    case 1: fiat_p256_square(want, x), fiat_p256_mul(want, want, c4); break;
                    case 2: fiat_p256_add(want, x, y); break;
                    case 3: fiat_p256_sub(want, x, y); break;
                    case 4: fiat_p256_opp(want, x); break;
                    case 5: { /* v 2^256 -> v 2^260 = 16 a */
                        memcpy(want, x, 32);
                        for (int q = 0; q < 4; q++) fiat_p256_add(want, want, want);
                        break;
                    }
                    default: memcpy(want, x, 32); break;
                }
                mod_p(got, o[l], oh[l]);
                bad += memcmp(got, want, 32) != 0;
                if (op == 6) bad += oh[l] || !u256_lt(o[l], P256_P); /* reduce: fully reduced */
            }
        }
    }
    CHECK(!bad && !range, "es8 field ops: %d mismatches, %d results out of range", bad, range);
}
/* the scalar comb (cc_pk_ec.inc's chain) for one lane, as plain integers */
static int comb_c(const cc_pkey_t *k, const int16_t *d1, const int16_t *d2, uint64_t x[4], uint64_t y[4],
                  uint64_t z[4]) {
    p256_jac_t acc;
    acc.inf = 1;
    for (int j = 0; j < P256_NW; j++) {
        p256_add_digit_c(&acc, k->tg[j], d1[j]);
        p256_add_digit_c(&acc, k->tq[j], d2[j]);
    }
    fiat_p256_from_montgomery(x, acc.x), fiat_p256_from_montgomery(y, acc.y), fiat_p256_from_montgomery(z, acc.z);
    return acc.inf;
}
static void rand_digits(int16_t *d, int mode) {
    for (int j = 0; j < P256_NW; j++) {
        int v = (int)(rnd() % (2 * P256_H)) - P256_H + 1;    /* [-H + 1, H] */
        if (mode == 1 && rnd() % 3 == 0) v = 0;              /* sparse */
        if (mode == 2) v = rnd() % 2 ? P256_H : -P256_H + 1; /* the ends of the range */
        if (mode == 3 && j < P256_NW / 2) v = 0;             /* infinity for half the rows */
        d[j] = (int16_t)v;
    }
}
static void test_es8_comb(const cc_pkey_t *k, const char *what, int same) {
    int bad = 0, n = 300, redo_seen = 0;
    for (int it = 0; it < n; it++) {
        int16_t d1[8][P256_NW], d2[8][P256_NW];
        const int16_t *p1[8], *p2[8];
        for (int l = 0; l < 8; l++) {
            rand_digits(d1[l], it % 4), rand_digits(d2[l], (it / 4) % 4);
            if (same && l < 4) /* Q = G: d2 = +-d1 makes acc = +-q at the first G/Q pair: the exceptional cases */
                for (int j = 0; j < P256_NW; j++) d2[l][j] = (int16_t)(l & 1 ? -d1[l][j] : d1[l][j]);
            p1[l] = d1[l], p2[l] = d2[l];
        }
        uint64_t x[8][4], y[8][4], z[8][4];
        unsigned inf;
        jwt_es8_comb(k->tg, k->tq, P256_NW, P256_H, p1, p2, x, y, z, &inf);
        for (int l = 0; l < 8; l++) {
            uint64_t cx[4], cy[4], cz[4];
            int cinf = comb_c(k, d1[l], d2[l], cx, cy, cz);
            int exc = !(inf >> l & 1) && fe_iszero(z[l]);
            redo_seen += exc;
            if (exc) continue; /* es8 hands these back to the scalar code (checked through es_points8 below) */
            if (cinf != (int)(inf >> l & 1)) bad++;
            else if (!cinf) bad += memcmp(x[l], cx, 32) || memcmp(y[l], cy, 32) || memcmp(z[l], cz, 32);
        }
        /* the verdicts through es_points8 (with its scalar redo) against es_points_c, r from the true result */
        int c = 8 + (int)(rnd() % 10), at[24];
        int16_t e1[24][P256_NW], e2[24][P256_NW];
        uint64_t r[24][4];
        uint8_t ok8[24], okc[24];
        for (int i = 0; i < c; i++) {
            memcpy(e1[i], d1[i % 8], sizeof e1[i]), memcpy(e2[i], d2[i % 8], sizeof e2[i]), at[i] = i;
            uint64_t cx[4], cy[4], cz[4];
            int cinf = comb_c(k, e1[i], e2[i], cx, cy, cz);
            memset(r[i], 0, 32), r[i][0] = 1 + rnd() % 7;
            if (!cinf && rnd() % 4) { /* r = x(R) mod n, correct about 3 times in 4 */
                fe_t zm, zi, zi2, xa;
                fiat_p256_to_montgomery(zm, cz), fe_inv(zi, zm), fe_sqr(zi2, zi), fiat_p256_to_montgomery(xa, cx);
                fe_mul(xa, xa, zi2), fiat_p256_from_montgomery(r[i], xa);
                if (!u256_lt(r[i], P256_N)) u256_sub(r[i], r[i], P256_N);
                if (rnd() % 8 == 0) r[i][0] ^= 1;
            }
        }
        memset(ok8, 0, sizeof ok8), memset(okc, 0, sizeof okc); /* both leave a result at infinity unwritten */
        es_points8(k, c, e1, e2, r, at, ok8);
        es_points_c(k, c, e1, e2, r, at, okc);
        bad += memcmp(ok8, okc, (size_t)c) != 0;
    }
    CHECK(!bad, "es8 comb (%s): %d mismatches against the scalar code", what, bad);
    if (same) CHECK(redo_seen > 0, "es8 comb (%s): no exceptional additions were exercised", what);
    printf("  es8 comb (%s): %d x 8 lanes vs the scalar chain; %d lanes handed back to the scalar code\n", what, n,
           redo_seen);
}
static void test_es8(void) {
    if (!(cc_cpu() & JWT_CPU_IFMA)) {
        printf("  es8 (-DJWT_ES8): skipped, this CPU lacks AVX-512 IFMA\n");
        return;
    }
    test_es8_field();
    uint8_t gx[32], gy[32];
    memcpy(gx, P256_GX, 32), memcpy(gy, P256_GY, 32);
    cc_pkey_t *kg = cc_pkey_es256(gx, gy); /* Q = G */
    test_es8_comb(kg, "Q = G, exceptional additions", 1);
    /* Q = 5G, from G's own table */
    uint64_t qx[4], qy[4];
    uint8_t bx[32], by[32];
    fiat_p256_from_montgomery(qx, kg->tg[0][4].x), fiat_p256_from_montgomery(qy, kg->tg[0][4].y);
    for (int i = 0; i < 32; i++)
        bx[i] = (uint8_t)(qx[3 - i / 8] >> (56 - 8 * (i % 8))), by[i] = (uint8_t)(qy[3 - i / 8] >> (56 - 8 * (i % 8)));
    cc_pkey_t *k5 = cc_pkey_es256(bx, by);
    CHECK(k5 != NULL, "es8: 5G rejected as a key");
    if (k5) test_es8_comb(k5, "Q = 5G", 0);
    printf("  es8 (-DJWT_ES8): %s; field ops vs fiat-crypto on 20000 x 8 random + edge lanes\n",
           kg->es8 ? "ACTIVE for batches" : "built, but batches stay scalar (no FAST_ZMM: set JWT_CPU_FORCE_ZMM=1)");
    cc_pkey_free(kg), cc_pkey_free(k5);
}
/* batches of 8 and 16 valid ES256 signatures with one of them broken, in every lane position */
static void es8_lanes(const jwt_pkey_t *k, rv_t *v, int n) {
    int good[64], ng = 0;
    for (int i = 0; i < n && ng < 64; i++)
        if (v[i].expect && v[i].sl == 64) good[ng++] = i;
    if (ng < 16) return;
    for (int bs = 8; bs <= 16; bs += 8)
        for (int pos = 0; pos < bs; pos++)
            for (int how = 0; how < 3; how++) {
                const uint8_t *msg[16], *sig[16];
                int ml[16], sl[16];
                uint8_t ok[16], sb[64], mb[2048];
                for (int i = 0; i < bs; i++) {
                    rv_t *e = &v[good[(pos * 3 + how + i) % ng]];
                    msg[i] = e->msg, ml[i] = e->ml, sig[i] = e->sig, sl[i] = e->sl;
                }
                memcpy(sb, sig[pos], 64);
                if (how == 0) sb[63] ^= 1;                                   /* s */
                if (how == 1) sb[rnd() % 32] ^= (uint8_t)(1 << (rnd() % 8)); /* r */
                if (how == 2 && ml[pos] > 0 && ml[pos] <= (int)sizeof mb) {  /* the message */
                    memcpy(mb, msg[pos], (size_t)ml[pos]), mb[rnd() % ml[pos]] ^= 0x20, msg[pos] = mb;
                } else if (how == 2) {
                    sb[40] ^= 0x80;
                }
                sig[pos] = sb;
                jwt_pk_verify_raw(k, bs, msg, ml, sig, sl, ok);
                for (int i = 0; i < bs; i++)
                    CHECK(ok[i] == (i != pos), "es8 lanes: batch %d, bad token at %d (how %d): lane %d got %d", bs, pos,
                          how, i, ok[i]);
            }
}
#endif

int main(int argc, char **argv) {
    printf("  cpu features 0x%x", jwt_cpu_features());
#ifdef JWT_CRYPTO_MB
    printf(", crypto_mb (AVX-512 IFMA) path: %s",
           cmb_ok() ? "ACTIVE" : "inactive, CPU lacks IFMA (fallback paths run)");
#endif
#ifdef JWT_S2N
#ifdef CC_S2N_ALT
    printf(", s2n-bignum: %s",
           s2n_ok() ? "active" : "P-256 on the ADX-free _alt kernels, RSA on the fallback (CPU lacks BMI2/ADX)");
#else
    printf(", s2n-bignum: %s", s2n_ok() ? "active" : "inactive, CPU lacks BMI2/ADX");
#endif
#endif
#ifdef CC_ED_S2N
    if (ed_r43_ok()) printf(", EdDSA additions: Firedancer r43x6 (AVX-512 IFMA)");
    else printf(", EdDSA additions: s2n-bignum edwards25519_pepadd%s", s2n_ok() ? "" : "_alt");
#endif
    printf("\n");
    test_arith();
#ifdef CC_ED_S2N
    test_r43();
#endif
#ifdef JWT_ES8
    test_es8();
#endif
    FILE *f = fopen(argc > 1 ? argv[1] : "build/pk_vectors.txt", "r");
    if (!f) {
        perror("vectors");
        return 2;
    }
    size_t cap = 1 << 20;
    char *line = malloc(cap), *a = malloc(cap), *b = malloc(cap), *c = malloc(cap), *d = malloc(cap), *e2 = malloc(cap),
         *g = malloc(cap);
    char *gk1 = calloc(2048, 1), *gk2 = calloc(2048, 1);
    int gkind = -1, gn = 0;
    rv_t *grp = calloc(4096, sizeof(rv_t));
    long counts[3] = { 0, 0, 0 }, nrej = 0, nj = 0;
    /* tokens are grouped by key too */
    jt_t *toks = calloc(4096, sizeof(jt_t));
    int tn = 0, tes = 0;
    char *tk1 = calloc(2048, 1), *tk2 = calloc(2048, 1);
    jwt_pkey_t *tkey = NULL;
#define FLUSH_GROUP()                                                                                                  \
    do {                                                                                                               \
        if (gn) run_group(gkind, gk1, gk2, grp, gn, &nrej);                                                            \
        for (int i_ = 0; i_ < gn; i_++) free(grp[i_].msg), free(grp[i_].sig);                                          \
        gn = 0;                                                                                                        \
    } while (0)
#define FLUSH_TOKENS()                                                                                                 \
    do {                                                                                                               \
        if (tn) {                                                                                                      \
            CHECK(tkey != NULL, "token key rejected");                                                                 \
            if (tkey) run_tokens(tkey, toks, tn);                                                                      \
        }                                                                                                              \
        for (int i_ = 0; i_ < tn; i_++) free(toks[i_].tok);                                                            \
        tn = 0;                                                                                                        \
        jwt_pkey_free(tkey), tkey = NULL;                                                                              \
    } while (0)
    int npair = 0, pair_screened = 0;
    while (fgets(line, (int)cap, f)) {
        char kind[8], src[96], alg[8];
        long long x, y, z;
        if (sscanf(line, "%7s", kind) != 1) continue;
        if (!strcmp(kind, "es") || !strcmp(kind, "rs") || !strcmp(kind, "ed")) {
            int es = !strcmp(kind, "es") ? 1 : !strcmp(kind, "ed") ? 2 : 0;
            int got = es == 2 ? sscanf(line, "%*s %95s %s %s %s %lld", src, a, c, d, &x) + 1
                              : sscanf(line, "%*s %95s %s %s %s %s %lld", src, a, b, c, d, &x);
            if (es == 2) strcpy(b, "-");
            if (got != 6) {
                CHECK(0, "bad line");
                continue;
            }
            if (es != gkind || strcmp(a, gk1) || strcmp(b, gk2) || gn == 4096) {
                FLUSH_GROUP();
                gkind = es, strcpy(gk1, a), strcpy(gk2, b);
            }
            rv_t *v = &grp[gn++];
            snprintf(v->src, sizeof v->src, "%s", src);
            v->msg = malloc(strlen(c) / 2 + 64), v->sig = malloc(strlen(d) / 2 + 64);
            v->ml = unhex(c, v->msg), v->sl = unhex(d, v->sig), v->expect = (int)x;
            counts[es]++;
        } else if (!strcmp(kind, "jwt")) {
            char uh[700];
            if (sscanf(line, "%*s %95s %7s %s %s %s %lld %lld %lld %699s", src, alg, a, b, c, &x, &y, &z, uh) != 9) {
                CHECK(0, "bad jwt line");
                continue;
            }
            int es = !strcmp(alg, "ES256") ? 1 : !strcmp(alg, "EdDSA") ? 2 : 0;
            if (!tkey || es != tes || strcmp(a, tk1) || strcmp(b, tk2) || tn == 4096) {
                FLUSH_TOKENS();
                tes = es, strcpy(tk1, a), strcpy(tk2, b);
                tkey = make_key(es, a, b);
            }
            jt_t *t = &toks[tn++];
            snprintf(t->src, sizeof t->src, "%s", src);
            t->len = (int)strlen(c), t->tok = calloc((size_t)t->len + 65, 1), memcpy(t->tok, c, (size_t)t->len);
            t->now = x, t->status = (int)y, t->uid = z;
            int ul = unhex(uh, (uint8_t *)t->user);
            t->user[ul] = 0;
            nj++;
        } else if (!strcmp(kind, "rspair")) {
            if (sscanf(line, "%*s %95s %s %s %s %s %s %s", src, a, b, c, d, e2, g) != 7) {
                CHECK(0, "bad rspair line");
                continue;
            }
            jwt_pkey_t *k = make_key(0, a, b);
            uint8_t *m1 = malloc(strlen(c)), *s1 = malloc(strlen(d)), *m2 = malloc(strlen(e2)), *s2 = malloc(strlen(g));
            const uint8_t *msg[2] = { m1, m2 }, *sig[2] = { s1, s2 };
            int ml[2] = { unhex(c, m1), unhex(e2, m2) }, sl[2] = { unhex(d, s1), unhex(g, s2) };
            uint8_t ok[2];
            jwt_pk_verify_raw(k, 1, msg, ml, sig, sl, ok);
            jwt_pk_verify_raw(k, 1, msg + 1, ml + 1, sig + 1, sl + 1, ok + 1);
            CHECK(!ok[0] && !ok[1], "%s: a mangled signature verified alone", src);
            jwt_pk_verify_raw(k, 2, msg, ml, sig, sl, ok);
#ifdef JWT_RSA_SCREEN
            pair_screened += ok[0] && ok[1]; /* the documented weakness of screening */
#else
            CHECK(!ok[0] && !ok[1], "%s: a mangled pair verified as a batch", src);
            (void)pair_screened;
#endif
            npair++;
            free(m1), free(s1), free(m2), free(s2), jwt_pkey_free(k);
        }
    }
    FLUSH_GROUP();
    FLUSH_TOKENS();
    fclose(f);
    printf(
        "  ES256: %ld raw vectors, RS256: %ld raw vectors (%ld under keys the library refuses), %ld tokens, %d s*x / s/x pairs\n",
        counts[1], counts[0], nrej, nj, npair);
    printf("  EdDSA (Ed25519): %ld raw vectors\n", counts[2]);
#ifdef JWT_RSA_SCREEN
    printf(
        "  screening (-DJWT_RSA_SCREEN) accepted %d of %d mangled pairs batched together (expected: all; see PK.md)\n",
        pair_screened, npair);
#endif
    printf("%s: %d/%d checks passed\n", fails ? "FAILED" : "OK", checks - fails, checks);
    return fails != 0;
}
