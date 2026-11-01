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
        jwt_pkey_t *pk = jwt_pkey_rs256(nb, 256, e3, 3);
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
        jwt_pkey_free(pk);
        printf("  s2n-bignum (-DJWT_S2N): P-256 field ops and RSA-2048 mont mul/sqr cross-checked\n");
    }
#endif
    printf("  P-256 fe_mul/sqr/add/sub (selected and C) vs fiat-crypto, sc_inv: %d random + edge inputs\n", n);
}

int main(int argc, char **argv) {
    printf("  cpu features 0x%x", jwt_cpu_features());
#ifdef JWT_CRYPTO_MB
    printf(", crypto_mb (AVX-512 IFMA) path: %s",
           cmb_ok() ? "ACTIVE" : "inactive, CPU lacks IFMA (fallback paths run)");
#endif
#ifdef JWT_S2N
    printf(", s2n-bignum: %s", s2n_ok() ? "active" : "inactive, CPU lacks BMI2/ADX");
#endif
    printf("\n");
    test_arith();
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
