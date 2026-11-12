/* test_sign.c — signing: exact-output vectors, round trips through the verifiers, and tokens for pyca to check.
 * Unity build: includes jwt.c.
 *   ./test_sign VECTORS     sign_vectors.txt from tests/make_sign_vectors.py (RFC 8032 / 8037 / 7515, pyca), then the
 *                           round trips: batch sizes 1..33, mixed payload lengths, every HMAC engine this CPU runs
 *   ./test_sign emit N      N random HS256 and EdDSA tokens and raw Ed25519 signatures, for tests/check_sign_pyca.py
 * make sign-test runs both. */
#include "jwt.c"
#include <stdio.h>

static int fails, checks;
#define CHECK(cond, ...)                                                                                               \
    do {                                                                                                               \
        checks++;                                                                                                      \
        if (!(cond)) {                                                                                                 \
            fails++;                                                                                                   \
            if (fails < 40)                                                                                            \
                fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__), fprintf(stderr, __VA_ARGS__),                     \
                    fputc('\n', stderr);                                                                               \
        }                                                                                                              \
    } while (0)

static uint64_t rs = 0x9e3779b97f4a7c15ull;
static uint32_t rnd(void) {
    rs ^= rs << 13, rs ^= rs >> 7, rs ^= rs << 17;
    return (uint32_t)(rs >> 16);
}
static int unhex(const char *h, uint8_t *o) {
    if (!strcmp(h, "-")) return 0;
    int n = 0;
    for (; h[0] && h[1]; h += 2) {
        unsigned v;
        sscanf(h, "%2x", &v);
        o[n++] = (uint8_t)v;
    }
    return n;
}

typedef struct {
    const char *name;
    jwt_hmac_fn *fn;
    unsigned need;
} engine_t;
static const engine_t all_engines[] = {
    { "scalar", jwt_hmac_scalar, 0 },
#if defined(JWT_OSSL_SHA256) && defined(__x86_64__) && defined(__ELF__)
    { "ossl", jwt_hmac_ossl, 0 },
#endif
#if defined(__x86_64__)
    { "avx2", jwt_hmac_avx2, JWT_CPU_AVX2 },
    { "shani_1", jwt_hmac_shani_1, JWT_CPU_SHANI },
    { "shani_2", jwt_hmac_shani_2, JWT_CPU_SHANI },
    { "shani_4", jwt_hmac_shani_4, JWT_CPU_SHANI },
    { "avx512", jwt_hmac_avx512, JWT_CPU_AVX512VL },
    { "zmm", jwt_hmac_zmm, JWT_CPU_AVX512VL },
#endif
#if defined(JWT_SHANI_MB) && defined(__x86_64__) && defined(__ELF__)
    { "shani_4r", jwt_hmac_shani_4r, JWT_CPU_SHANI },
    { "x16", jwt_hmac_x16, JWT_CPU_AVX512VL },
    { "shani_x16", jwt_hmac_shani_x16, JWT_CPU_SHANI | JWT_CPU_AVX512VL },
#endif
#if defined(__aarch64__)
    { "neon", jwt_hmac_neon, 0 },
    { "sha2_1", jwt_hmac_sha2_1, JWT_CPU_SHA2 },
    { "sha2_2", jwt_hmac_sha2_2, JWT_CPU_SHA2 },
    { "sha2", jwt_hmac_sha2, JWT_CPU_SHA2 },
#endif
};

/* ---- vectors ---- */
static char line[1 << 17];
static uint8_t A[1 << 15], Bf[1 << 15], C[1 << 15], D[1 << 15];
static char tokbuf[JWT_TOKEN_MAX + 128];

static void sign_hs_one(const uint8_t *key, int kl, const uint8_t *pl, int pn, char *out, int *ol) {
    jwt_key_t k;
    jwt_key_init(&k, key, (size_t)kl);
    const char *p = (const char *)pl;
    jwt_sign_batch(&k, 1, &p, &pn, &out, ol);
}
static void sign_es_one(const uint8_t *d, const uint8_t *pl, int pn, char *out, int *ol) {
    jwt_skey_t *k = jwt_skey_es256(d);
    const char *p = (const char *)pl;
    jwt_sign_batch_pk(k, 1, &p, &pn, &out, ol);
    jwt_skey_free(k);
}
static void sign_ed_one(const uint8_t *seed, const uint8_t *pl, int pn, char *out, int *ol) {
    jwt_skey_t *k = jwt_skey_ed25519(seed);
    const char *p = (const char *)pl;
    jwt_sign_batch_pk(k, 1, &p, &pn, &out, ol);
    jwt_skey_free(k);
}

static void vectors(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) perror(path), exit(2);
    int counts[16] = { 0 };
    static const char *kinds[] = { "ed",     "edjws", "hsjws", "edtok", "hstok", "refuse",
                                   "sha512", "sc",    "b64",   "es",    "estok" };
    enum { NK = (int)(sizeof kinds / sizeof kinds[0]) };
    while (fgets(line, sizeof line, f)) {
        char kind[16], src[64], *f3 = NULL, *f4 = NULL, *f5 = NULL, *f6 = NULL, *f7 = NULL, *f8 = NULL;
        line[strcspn(line, "\n")] = 0;
        char *save, *t = strtok_r(line, " ", &save);
        if (!t) continue;
        snprintf(kind, sizeof kind, "%s", t);
        snprintf(src, sizeof src, "%s", strtok_r(NULL, " ", &save));
        f3 = strtok_r(NULL, " ", &save), f4 = f3 ? strtok_r(NULL, " ", &save) : NULL;
        f5 = f4 ? strtok_r(NULL, " ", &save) : NULL, f6 = f5 ? strtok_r(NULL, " ", &save) : NULL;
        f7 = f6 ? strtok_r(NULL, " ", &save) : NULL, f8 = f7 ? strtok_r(NULL, " ", &save) : NULL;
        int ki = 0;
        while (ki < NK && strcmp(kind, kinds[ki])) ki++;
        counts[ki]++;
        if (!strcmp(kind, "ed")) { /* seed pub msg sig */
            uint8_t sig[64], pub[32], *sp = sig, ok = 0;
            unhex(f3, A), unhex(f4, Bf);
            int ml = unhex(f5, C);
            unhex(f6, D);
            cc_skey_t *k = cc_skey_ed25519(A);
            cc_skey_public(k, pub);
            CHECK(!memcmp(pub, Bf, 32), "%s: public key", src);
            const uint8_t *mp = C;
            cc_sign_batch(k, 1, &mp, &ml, &sp);
            CHECK(!memcmp(sig, D, 64), "%s: signature differs from the vector", src);
            cc_pkey_t *pk = cc_pkey_ed25519(pub);
            const uint8_t *s2 = sig;
            int sl = 64;
            cc_verify_batch(pk, 1, &mp, &ml, &s2, &sl, &ok);
            CHECK(ok == 1, "%s: our verifier rejects the signature", src);
            cc_pkey_free(pk), cc_skey_free(k);
        } else if (!strcmp(kind, "edjws") || !strcmp(kind, "hsjws")) { /* key signing-input token */
            int kl = unhex(f3, A), sl = unhex(f4, C);
            uint8_t sig[64];
            int sb;
            if (kind[0] == 'e') {
                cc_skey_t *k = cc_skey_ed25519(A);
                const uint8_t *mp = C;
                uint8_t *sp = sig;
                cc_sign_batch(k, 1, &mp, &sl, &sp);
                cc_skey_free(k), sb = 64;
            } else {
                cc_hmac_key_t k;
                cc_hmac_key_init(&k, A, (size_t)kl);
                const uint8_t *mp = C;
                cc_hmac_sha256_bytes(&k, 1, &mp, &sl, (uint8_t(*)[32])sig), sb = 32;
            }
            memcpy(tokbuf, C, (size_t)sl);
            tokbuf[sl] = '.';
            int tl = sl + 1 + jwt_b64url_encode(tokbuf + sl + 1, sig, sb);
            tokbuf[tl] = 0;
            CHECK(!strcmp(tokbuf, f5), "%s: token\n  got  %s\n  want %s", src, tokbuf, f5);
        } else if (!strcmp(kind, "edtok") || !strcmp(kind, "hstok")) { /* key payload token */
            int kl = unhex(f3, A), pn = unhex(f4, C), ol = -2;
            CHECK(kind[0] == 'h' ? jwt_sign_size(pn) <= (int)sizeof tokbuf : 1, "%s: size", src);
            if (kind[0] == 'e') sign_ed_one(A, C, pn, tokbuf, &ol);
            else sign_hs_one(A, kl, C, pn, tokbuf, &ol);
            CHECK(ol == (int)strlen(f5) && !strcmp(tokbuf, f5), "%s: token (len %d)\n  got  %s\n  want %s", src, ol,
                  tokbuf, f5);
        } else if (!strcmp(kind, "es")) { /* d x y msg k sig */
            uint8_t d[32], x[32], y[32], gx[32], gy[32], sig[64], want[64], kk[32], *sp = sig, ok = 0;
            unhex(f3, d), unhex(f4, x), unhex(f5, y);
            int ml = unhex(f6, C);
            unhex(f8, want);
            cc_skey_t *k = cc_skey_es256(d);
            CHECK(k != NULL, "%s: key refused", src);
            if (!k) continue;
            cc_skey_es256_public(k, gx, gy);
            CHECK(!memcmp(gx, x, 32) && !memcmp(gy, y, 32), "%s: public key", src);
            const uint8_t *mp = C;
            cc_sign_batch(k, 1, &mp, &ml, &sp);
            CHECK(!memcmp(sig, want, 64), "%s: signature differs from the vector", src);
            if (strcmp(f7, "-")) { /* the RFC 6979 nonce itself */
                uint8_t hb[1][32], h[32];
                uint64_t z[4], kl[4];
                es_drbg g;
                cc_sha256_bytes(1, &mp, &ml, hb);
                es_be_to_limbs(z, hb[0]), es_sub_n_once(z, z), es_limbs_to_be(h, z);
                es_drbg_init(&g, d, h);
                es_drbg_next(&g, kl, 0);
                es_limbs_to_be(kk, kl);
                uint8_t wk[32];
                unhex(f7, wk);
                CHECK(!memcmp(kk, wk, 32), "%s: RFC 6979 nonce k", src);
            }
            cc_pkey_t *pk = cc_pkey_es256(x, y);
            const uint8_t *s2 = sig;
            int sl = 64;
            cc_verify_batch(pk, 1, &mp, &ml, &s2, &sl, &ok);
            CHECK(ok == 1, "%s: our verifier rejects the signature", src);
            cc_pkey_free(pk), cc_skey_free(k);
        } else if (!strcmp(kind, "estok")) { /* d payload token */
            int pn = unhex(f4, C), ol = -2;
            unhex(f3, A);
            sign_es_one(A, C, pn, tokbuf, &ol);
            CHECK(ol == (int)strlen(f5) && !strcmp(tokbuf, f5), "%s: token (len %d)\n  got  %s\n  want %s", src, ol,
                  tokbuf, f5);
        } else if (!strcmp(kind, "refuse")) {
            int pn = unhex(f3, C), o1 = 0, o2 = 0;
            uint8_t seed[32] = { 7 };
            tokbuf[0] = 'x';
            sign_hs_one(seed, 32, C, pn, tokbuf, &o1);
            CHECK(o1 == -1 && tokbuf[0] == 'x', "%s: HS256 issued a token for a refused payload", src);
            tokbuf[0] = 'x';
            sign_ed_one(seed, C, pn, tokbuf, &o2);
            CHECK(o2 == -1 && tokbuf[0] == 'x', "%s: EdDSA issued a token for a refused payload", src);
            tokbuf[0] = 'x', o2 = 0;
            sign_es_one(seed, C, pn, tokbuf, &o2);
            CHECK(o2 == -1 && tokbuf[0] == 'x', "%s: ES256 issued a token for a refused payload", src);
        } else if (!strcmp(kind, "sha512")) {
            int ml = unhex(f3, A);
            uint8_t want[64], got[64];
            unhex(f4, want);
            cc_sha512(A, (size_t)ml, got);
            CHECK(!memcmp(got, want, 64), "%s: sha512 one-shot", src);
            cc_sha512_ctx c; /* the same bytes in random pieces */
            cc_sha512_init(&c);
            for (int o = 0; o < ml;) {
                int k = (int)(rnd() % 140);
                if (k > ml - o) k = ml - o;
                cc_sha512_update(&c, A + o, (size_t)k), o += k;
            }
            cc_sha512_final(&c, got);
            CHECK(!memcmp(got, want, 64), "%s: sha512 streamed", src);
        } else if (!strcmp(kind, "sc")) {
            uint8_t x[64], want[32], got[32];
            sg_sc m;
            unhex(f3, x), unhex(f4, want);
            sg_sc_reduce(m, x);
            sg_sc_bytes(got, m);
            CHECK(!memcmp(got, want, 32), "%s: x mod L", src);
        } else if (!strcmp(kind, "b64")) {
            int n = unhex(f3, A);
            const char *want = strcmp(f4, "-") ? f4 : "";
            int o = jwt_b64url_encode(tokbuf, A, n);
            tokbuf[o] = 0;
            CHECK(!strcmp(tokbuf, want), "%s: base64url %s vs %s", src, tokbuf, want);
            static char sc[1 << 12];
            int o2 = jwt_b64url_encode_scalar(sc, A, n);
            CHECK(o2 == o && !memcmp(sc, tokbuf, (size_t)o), "%s: scalar encoder", src);
            CHECK(jwt_b64url_decode_scalar(Bf, tokbuf, o) == n && !memcmp(Bf, A, (size_t)n), "%s: decode", src);
        } else {
            CHECK(0, "unknown vector kind %s", kind);
        }
    }
    fclose(f);
    printf("vectors:");
    for (int i = 0; i < NK; i++) printf(" %s %d", kinds[i], counts[i]);
    printf("\n");
    CHECK(counts[0] >= 5 && counts[1] == 1 && counts[2] == 1 && counts[9] >= 2, "the RFC vectors are missing");
}

/* ---- round trips ---- */
enum { MAXB = 33 };
static char pls[MAXB][1024], *outs[MAXB], obuf[MAXB][JWT_TOKEN_MAX + 128], ref[MAXB][JWT_TOKEN_MAX + 128];
static int pnl[MAXB], ol[MAXB], uids[MAXB];
static char users[MAXB][64];

static void make_payloads(int n) {
    for (int i = 0; i < n; i++) {
        uids[i] = 1 + (int)(rnd() % 1000000);
        int ul = (int)(rnd() % 40);
        for (int j = 0; j < ul; j++) users[i][j] = (char)('a' + rnd() % 26);
        users[i][ul] = 0;
        int pad = (int)(rnd() % 4 == 0 ? rnd() % 600 : rnd() % 40);
        char padv[700];
        memset(padv, 'p', (size_t)pad), padv[pad] = 0;
        pnl[i] = snprintf(pls[i], sizeof pls[i],
                          "{\"sub\":\"%d\",\"username\":\"%s\",\"iat\":1700000000,\"pad\":\"%s\","
                          "\"exp\":4102444800}",
                          uids[i], users[i], padv);
        outs[i] = obuf[i];
    }
}
/* the same batch into buffers of exactly the advertised size (ASan builds catch any overrun): tokens equal ref[] */
static void exact_size(int n, const jwt_key_t *hk, const jwt_skey_t *sk) {
    char *ex[MAXB];
    const char *pp[MAXB];
    int el[MAXB];
    for (int i = 0; i < n; i++) {
        int sz = hk ? jwt_sign_size(pnl[i]) : jwt_sign_size_pk(sk, pnl[i]);
        CHECK(sz > ol[i], "advertised size %d for a %d-char token", sz, ol[i]);
        ex[i] = malloc((size_t)sz), pp[i] = pls[i];
    }
    if (hk) jwt_sign_batch(hk, n, pp, pnl, ex, el);
    else jwt_sign_batch_pk(sk, n, pp, pnl, ex, el);
    for (int i = 0; i < n; i++) {
        CHECK(el[i] == ol[i] && !strcmp(ex[i], obuf[i]), "exact-size buffer n=%d i=%d", n, i);
        free(ex[i]);
    }
}
static void check_results(const char *what, int n, const jwt_result_t *r) {
    for (int i = 0; i < n; i++)
        CHECK(r[i].status == JWT_OK && r[i].uid == uids[i] && !strcmp(r[i].username, users[i]),
              "%s n=%d i=%d: status %d uid %lld", what, n, i, r[i].status, (long long)r[i].uid);
}

static void roundtrip_hs(void) {
    unsigned f = jwt_cpu_features();
    jwt_key_t k;
    jwt_key_init(&k, "round-trip-secret", 17);
    static jwt_result_t res[MAXB];
    int engines = 0;
    for (int n = 1; n <= MAXB; n++) {
        make_payloads(n);
        const char *pp[MAXB];
        for (int i = 0; i < n; i++) pp[i] = pls[i];
        CHECK(jwt_sign_batch(&k, n, pp, pnl, outs, ol) == n, "hs n=%d: not all issued", n);
        for (int i = 0; i < n; i++) memcpy(ref[i], obuf[i], (size_t)ol[i] + 1);
        const char *tp[MAXB];
        for (int i = 0; i < n; i++) tp[i] = obuf[i];
        jwt_verify_batch(&k, n, tp, ol, 1800000000, res);
        check_results("hs default", n, res);
        exact_size(n, &k, NULL);
        for (size_t e = 0; e < sizeof all_engines / sizeof all_engines[0]; e++) {
            if ((all_engines[e].need & f) != all_engines[e].need) continue;
            engines += n == 1;
            memset(obuf, 0, sizeof obuf[0] * (size_t)n);
            CHECK(sign_impl(&k, n, pp, pnl, outs, ol, all_engines[e].fn) == n, "hs %s n=%d", all_engines[e].name, n);
            for (int i = 0; i < n; i++)
                CHECK(!strcmp(obuf[i], ref[i]), "hs %s n=%d i=%d: token differs from the default engine's",
                      all_engines[e].name, n, i);
            jwt_verify_batch(&k, n, tp, ol, 1800000000, res);
            check_results(all_engines[e].name, n, res);
        }
        /* one token at a time gives the same tokens */
        for (int i = 0; i < n; i++) {
            int o;
            char *op = obuf[i];
            jwt_sign_batch(&k, 1, &pp[i], &pnl[i], &op, &o);
            CHECK(o == ol[i] && !strcmp(obuf[i], ref[i]), "hs n=%d i=%d: batch vs single", n, i);
        }
    }
    printf("round trip HS256: batch 1..%d, %d engines + the default, verified by jwt_verify_batch\n", MAXB, engines);
}

static void roundtrip_ed(void) {
    uint8_t seed[32], pub[32];
    for (int i = 0; i < 32; i++) seed[i] = (uint8_t)rnd();
    jwt_skey_t *k = jwt_skey_ed25519(seed);
    jwt_skey_public(k, pub);
    jwt_pkey_t *pk = jwt_pkey_ed25519(pub);
    CHECK(pk != NULL, "public key does not decode");
    static jwt_result_t res[MAXB];
    for (int n = 1; n <= MAXB; n++) {
        make_payloads(n);
        const char *pp[MAXB], *tp[MAXB];
        for (int i = 0; i < n; i++) pp[i] = pls[i], tp[i] = obuf[i];
        for (int i = 0; i < n; i++) CHECK(jwt_sign_size_pk(k, pnl[i]) <= (int)sizeof obuf[0], "size");
        CHECK(jwt_sign_batch_pk(k, n, pp, pnl, outs, ol) == n, "ed n=%d: not all issued", n);
        jwt_verify_batch_pk(pk, n, tp, ol, 1800000000, res);
        check_results("ed", n, res);
        exact_size(n, NULL, k);
        for (int i = 0; i < n; i++) { /* deterministic: signing alone gives the same token */
            int o;
            char *op = ref[i];
            jwt_sign_batch_pk(k, 1, &pp[i], &pnl[i], &op, &o);
            CHECK(o == ol[i] && !strcmp(ref[i], obuf[i]), "ed n=%d i=%d: batch vs single", n, i);
        }
        /* a refused payload in the middle of a batch leaves the others alone */
        if (n >= 3) { /* (its out[] is NULL: a refused item must not be written to) */
            pnl[1] = 3, outs[1] = NULL;
            CHECK(jwt_sign_batch_pk(k, n, pp, pnl, outs, ol) == n - 1 && ol[1] == -1, "ed n=%d: refused item", n);
            outs[1] = obuf[1];
            jwt_verify_batch_pk(pk, n, tp, ol, 1800000000, res);
            CHECK(res[1].status == JWT_INVALID && res[0].status == JWT_OK && res[2].status == JWT_OK, "ed mixed");
        }
    }
    jwt_pkey_free(pk), jwt_skey_free(k);
    printf("round trip EdDSA: batch 1..%d, verified by jwt_verify_batch_pk, batch == single\n", MAXB);
}

static void roundtrip_es(void) {
    uint8_t d[32], x[32], y[32];
    for (int i = 0; i < 32; i++) d[i] = (uint8_t)rnd();
    d[0] &= 0x7f; /* < n */
    jwt_skey_t *k = jwt_skey_es256(d);
    jwt_skey_es256_public(k, x, y);
    jwt_pkey_t *pk = jwt_pkey_es256(x, y);
    CHECK(k && pk, "ES256 keys");
    static jwt_result_t res[MAXB];
    for (int n = 1; n <= MAXB; n++) {
        make_payloads(n);
        const char *pp[MAXB], *tp[MAXB];
        for (int i = 0; i < n; i++) pp[i] = pls[i], tp[i] = obuf[i];
        CHECK(jwt_sign_batch_pk(k, n, pp, pnl, outs, ol) == n, "es n=%d: not all issued", n);
        jwt_verify_batch_pk(pk, n, tp, ol, 1800000000, res);
        check_results("es", n, res);
        exact_size(n, NULL, k);
        for (int i = 0; i < n; i++) { /* deterministic: signing alone gives the same token */
            int o;
            char *op = ref[i];
            jwt_sign_batch_pk(k, 1, &pp[i], &pnl[i], &op, &o);
            CHECK(o == ol[i] && !strcmp(ref[i], obuf[i]), "es n=%d i=%d: batch vs single", n, i);
        }
    }
    /* verify-after-sign: the same tokens with it on; with a corrupted key (a simulated fault) none is issued */
    CHECK(jwt_skey_verify_after_sign(k, 1) == 0, "verify-after-sign on");
    make_payloads(MAXB);
    const char *pp[MAXB];
    for (int i = 0; i < MAXB; i++) pp[i] = pls[i];
    CHECK(jwt_sign_batch_pk(k, MAXB, pp, pnl, outs, ol) == MAXB, "es with verify-after-sign: not all issued");
    k->cc->es_dm[0] ^= 1;
    CHECK(jwt_sign_batch_pk(k, MAXB, pp, pnl, outs, ol) == 0 && ol[0] == -1 && obuf[0][0] == 0 && ol[MAXB - 1] == -1,
          "es fault: a token was issued");
    k->cc->es_dm[0] ^= 1;
    CHECK(jwt_skey_verify_after_sign(k, 0) == 0, "verify-after-sign off");
    uint8_t seed[32] = { 1 };
    jwt_skey_t *ek = jwt_skey_ed25519(seed);
    CHECK(jwt_skey_verify_after_sign(ek, 1) == -1, "verify-after-sign is ES256 only");
    jwt_skey_free(ek);
    /* d out of range: 0, n, 2^256 - 1 */
    static const uint8_t n_be[32] = { 0xff, 0xff, 0xff, 0xff, 0,    0,    0,    0,    0xff, 0xff, 0xff,
                                      0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17,
                                      0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51 };
    uint8_t z[32] = { 0 }, f[32];
    memset(f, 0xff, 32);
    CHECK(!jwt_skey_es256(z) && !jwt_skey_es256(n_be) && !jwt_skey_es256(f), "ES256 keys out of range accepted");
    jwt_pkey_free(pk), jwt_skey_free(k);
    printf("round trip ES256: batch 1..%d, verified by jwt_verify_batch_pk, batch == single, verify-after-sign\n",
           MAXB);
}

/* the static P-256 table (cc_p256_table.inc) recomputed with the signer's own point arithmetic */
static void p256_table_check(void) {
    int bad = 0;
    es_pt base, acc;
    static const uint64_t one[4] = { 1 };
    memcpy(base.X, CC_P256_GTAB, 32), memcpy(base.Y, CC_P256_GTAB + 4, 32), memcpy(base.Z, ES_ONE_M, 32);
    for (int i = 0; i < 65; i++) {
        memset(&acc, 0, sizeof acc), memcpy(acc.Y, ES_ONE_M, 32);
        for (int j = 1; j <= 8; j++) {
            es_add(&acc, &acc, &base);
            es_fe zi, ax, ay;
            static const uint64_t pm2[4] = { 0xfffffffffffffffdull, 0x00000000ffffffffull, 0, 0xffffffff00000001ull };
            es_fe_pow(zi, acc.Z, pm2);
            fiat_p256_mul(ax, acc.X, zi), fiat_p256_mul(ay, acc.Y, zi);
            bad += memcmp(ax, CC_P256_GTAB + 64 * i + 8 * (j - 1), 32) != 0;
            bad += memcmp(ay, CC_P256_GTAB + 64 * i + 8 * (j - 1) + 4, 32) != 0;
        }
        for (int t = 0; t < 4; t++) es_add(&base, &base, &base); /* 16 base */
    }
    (void)one;
    CHECK(bad == 0, "the static P-256 table: %d entries differ", bad);
    printf("P-256 table: 520 entries recomputed, %s\n", bad ? "MISMATCH" : "all equal");
}

/* ---- tokens for pyca ---- */
static void emit(int n) {
    uint8_t key[64], seed[32], pub[32], msg[400], sig[64];
    for (int i = 0; i < n; i++) {
        int kl = (int)(rnd() % 65);
        for (int j = 0; j < kl; j++) key[j] = (uint8_t)rnd();
        for (int j = 0; j < 32; j++) seed[j] = (uint8_t)rnd();
        make_payloads(1);
        int o;
        jwt_key_t hk;
        jwt_key_init(&hk, key, (size_t)kl);
        const char *pp = pls[0];
        jwt_sign_batch(&hk, 1, &pp, &pnl[0], outs, &o);
        printf("hs ");
        for (int j = 0; j < kl; j++) printf("%02x", key[j]);
        printf("%s %s %d %s\n", kl ? "" : "-", obuf[0], uids[0], users[0][0] ? users[0] : "-");
        jwt_skey_t *sk = jwt_skey_ed25519(seed);
        jwt_skey_public(sk, pub);
        jwt_sign_batch_pk(sk, 1, &pp, &pnl[0], outs, &o);
        printf("ed ");
        for (int j = 0; j < 32; j++) printf("%02x", seed[j]);
        printf(" ");
        for (int j = 0; j < 32; j++) printf("%02x", pub[j]);
        printf(" %s %d %s\n", obuf[0], uids[0], users[0][0] ? users[0] : "-");
        int ml = (int)(rnd() % sizeof msg);
        for (int j = 0; j < ml; j++) msg[j] = (uint8_t)rnd();
        const uint8_t *mp = msg;
        uint8_t *sp = sig;
        cc_sign_batch(sk->cc, 1, &mp, &ml, &sp);
        printf("edraw ");
        for (int j = 0; j < 32; j++) printf("%02x", seed[j]);
        printf(" ");
        for (int j = 0; j < ml; j++) printf("%02x", msg[j]);
        printf("%s ", ml ? "" : "-");
        for (int j = 0; j < 64; j++) printf("%02x", sig[j]);
        printf("\n");
        jwt_skey_free(sk);
        uint8_t d[32], qx[32], qy[32];
        for (int j = 0; j < 32; j++) d[j] = (uint8_t)rnd();
        d[0] &= 0x7f;
        jwt_skey_t *es = jwt_skey_es256(d);
        jwt_skey_es256_public(es, qx, qy);
        jwt_sign_batch_pk(es, 1, &pp, &pnl[0], outs, &o);
        printf("es ");
        for (int j = 0; j < 32; j++) printf("%02x", d[j]);
        printf(" %s %d %s\n", obuf[0], uids[0], users[0][0] ? users[0] : "-");
        cc_sign_batch(es->cc, 1, &mp, &ml, &sp);
        printf("esraw ");
        for (int j = 0; j < 32; j++) printf("%02x", d[j]);
        printf(" ");
        for (int j = 0; j < ml; j++) printf("%02x", msg[j]);
        printf("%s ", ml ? "" : "-");
        for (int j = 0; j < 64; j++) printf("%02x", sig[j]);
        printf("\n");
        (void)qx, (void)qy;
        jwt_skey_free(es);
    }
}

int main(int argc, char **argv) {
    if (argc > 2 && !strcmp(argv[1], "emit")) return emit(atoi(argv[2])), 0;
    printf("cpu features 0x%x, default engine %s\n", jwt_cpu_features(), jwt_engine());
    if (argc > 1) vectors(argv[1]);
    roundtrip_hs();
    roundtrip_ed();
    roundtrip_es();
    p256_table_check();
    printf("test_sign: %d checks, %d failures\n", checks, fails);
    return fails != 0;
}
