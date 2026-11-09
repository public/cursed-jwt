/* bench_pk.c — RS256 / ES256 ns/token vs OpenSSL.  Unity build: includes jwt.c.
 *   ./bench_pk [pk_tokens.txt] [seconds-per-cell]          (tokens from bench/gen_pk_tokens.py)
 * OpenSSL baselines, both with the EVP_PKEY parsed once (what a server holding a JWKS does):
 *   EVP_DigestVerify   one EVP_DigestVerifyInit/Update/Final per token, as jwt-cpp and most libraries call it;
 *   prehashed          SHA256() + EVP_PKEY_verify on one reused EVP_PKEY_CTX: OpenSSL's best case.
 * The ES256 signatures are converted to DER outside the timed loop (a JWT library has to do that per token). */
#include "jwt.c"

#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <time.h>

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e9 + ts.tv_nsec;
}
static int unhex(const char *h, uint8_t *out) {
    int n = (int)strlen(h) / 2;
    for (int i = 0; i < n; i++) {
        unsigned v;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
    return n;
}

enum { MAXT = 4096 };
typedef struct {
    char alg[8];
    int bits, n;
    jwt_pkey_t *k;
    EVP_PKEY *ossl;
    char *tok[MAXT];
    int len[MAXT], mlen[MAXT], slen[MAXT], derlen[MAXT];
    uint8_t *sig[MAXT], *der[MAXT];
} set_t;

static double secs = 0.5;
static volatile int sink;

/* best ns/token of 3 runs of ~secs/3 each, processing the set in batches of bs */
#define TIMEIT(result, bs, body)                                                                                       \
    do {                                                                                                               \
        double best_ = 1e30;                                                                                           \
        for (int run_ = 0; run_ < 3; run_++) {                                                                         \
            long done_ = 0;                                                                                            \
            double t0_ = now_ns(), t1_;                                                                                \
            do {                                                                                                       \
                for (int base = 0; base + (bs) <= S->n; base += (bs)) { body; }                                        \
                done_ += S->n / (bs) * (bs);                                                                           \
                t1_ = now_ns();                                                                                        \
            } while (t1_ - t0_ < secs / 3 * 1e9);                                                                      \
            double v_ = (t1_ - t0_) / done_;                                                                           \
            if (v_ < best_) best_ = v_;                                                                                \
        }                                                                                                              \
        result = best_;                                                                                                \
    } while (0)

static void bench_set(set_t *S) {
    static const int B[] = { 1, 2, 4, 8, 16, 32 };
    printf("\n%s-%d (%d tokens, signing input %d bytes)\n", S->alg, S->bits, S->n, S->mlen[0]);
    /* sanity: everything verifies, a forged one doesn't */
    uint8_t ok[MAXT];
    jwt_pk_verify_raw(S->k, S->n, (const uint8_t *const *)S->tok, S->mlen, (const uint8_t *const *)S->sig, S->slen, ok);
    int nok = 0;
    for (int i = 0; i < S->n; i++) nok += ok[i];
    jwt_result_t *res = malloc(sizeof(jwt_result_t) * S->n);
    jwt_verify_batch_pk(S->k, S->n, (const char *const *)S->tok, S->len, 1850000000, res);
    int nfull = 0;
    for (int i = 0; i < S->n; i++) nfull += res[i].status == JWT_OK;
    S->sig[0][5] ^= 1;
    jwt_pk_verify_raw(S->k, 1, (const uint8_t *const *)S->tok, S->mlen, (const uint8_t *const *)S->sig, S->slen, ok);
    int forged = ok[0];
    S->sig[0][5] ^= 1;
    printf("  check: %d/%d raw, %d/%d full verify OK, forged accepted: %d\n", nok, S->n, nfull, S->n, forged);
    if (nok != S->n || nfull != S->n || forged) {
        printf("  SANITY FAILED\n");
        exit(1);
    }

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(S->ossl, NULL);
    int ed = S->alg[1] == 'd'; /* EdDSA: one-shot only, no message digest, no prehashed mode */
    double t;
    if (ed) {
        TIMEIT(t, 1, {
            EVP_DigestVerifyInit(mctx, NULL, NULL, NULL, S->ossl);
            sink += EVP_DigestVerify(mctx, S->der[base], (size_t)S->derlen[base], (const uint8_t *)S->tok[base],
                                     (size_t)S->mlen[base]);
        });
        printf("  %-34s %8.0f ns/token\n", "openssl EVP_DigestVerify", t);
    } else {
        EVP_PKEY_verify_init(pctx);
        if (S->alg[0] == 'R') EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);
        EVP_PKEY_CTX_set_signature_md(pctx, EVP_sha256());
        TIMEIT(t, 1, {
            EVP_DigestVerifyInit(mctx, NULL, EVP_sha256(), NULL, S->ossl);
            EVP_DigestVerifyUpdate(mctx, S->tok[base], (size_t)S->mlen[base]);
            sink += EVP_DigestVerifyFinal(mctx, S->der[base], (size_t)S->derlen[base]);
        });
        printf("  %-34s %8.0f ns/token\n", "openssl EVP_DigestVerify", t);
    }
    if (!ed)
        TIMEIT(t, 1, {
            uint8_t h[32];
            SHA256((const uint8_t *)S->tok[base], (size_t)S->mlen[base], h);
            sink += EVP_PKEY_verify(pctx, S->der[base], (size_t)S->derlen[base], h, 32);
        });
    if (!ed) printf("  %-34s %8.0f ns/token\n", "openssl prehashed, reused ctx", t);
    printf("  %-34s", "cursed raw verify, batch");
    for (int b = 0; b < 6; b++) printf(" %8d", B[b]);
    printf("\n  %-34s", "");
    for (int b = 0; b < 6; b++) {
        int bs = B[b];
        TIMEIT(t, bs, {
            jwt_pk_verify_raw(S->k, bs, (const uint8_t *const *)S->tok + base, S->mlen + base,
                              (const uint8_t *const *)S->sig + base, S->slen + base, ok);
            sink += ok[0];
        });
        printf(" %8.0f", t);
    }
    printf("  ns/token\n  %-34s", "cursed full verify (claims)");
    for (int b = 0; b < 6; b++) {
        int bs = B[b];
        TIMEIT(t, bs, {
            jwt_verify_batch_pk(S->k, bs, (const char *const *)S->tok + base, S->len + base, 1850000000, res);
            sink += res[0].status;
        });
        printf(" %8.0f", t);
    }
    printf("  ns/token\n");
    EVP_MD_CTX_free(mctx), EVP_PKEY_CTX_free(pctx), free(res);
}

int main(int argc, char **argv) {
    FILE *f = fopen(argc > 1 ? argv[1] : "build/pk_tokens.txt", "r");
    if (!f) {
        perror("tokens");
        return 2;
    }
    if (argc > 2) secs = atof(argv[2]);
    static set_t sets[4];
    int ns = 0;
    static char line[1 << 16], a[8192], b[8192], c[8192], d[8192];
    while (fgets(line, sizeof line, f)) {
        if (!strncmp(line, "key ", 4)) {
            set_t *S = &sets[ns++];
            sscanf(line, "key %7s %8191s %8191s %8191s", S->alg, a, b, c);
            uint8_t k1[600], k2[600], spki[2000];
            int l1 = unhex(a, k1), l2 = unhex(b, k2), ld = unhex(c, spki);
            double t0 = now_ns();
            S->k = S->alg[1] == 'd'   ? jwt_pkey_ed25519(k1)
                   : S->alg[0] == 'E' ? jwt_pkey_es256(k1, k2)
                                      : jwt_pkey_rs256(k1, (size_t)l1, k2, (size_t)l2);
            double t1 = now_ns();
            S->bits = S->alg[1] == 'd' ? 255 : S->alg[0] == 'E' ? 256 : l1 * 8;
            const uint8_t *p = spki;
            S->ossl = d2i_PUBKEY(NULL, &p, ld);
            if (!S->k || !S->ossl) {
                printf("key setup failed\n");
                return 1;
            }
            printf("%s-%d key setup: %.0f us\n", S->alg, S->bits, (t1 - t0) / 1e3);
        } else if (!strncmp(line, "tok ", 4) && ns && sets[ns - 1].n < MAXT) {
            set_t *S = &sets[ns - 1];
            int i = S->n++;
            sscanf(line, "tok %8191s", d);
            int L = (int)strlen(d);
            S->tok[i] = calloc((size_t)L + 65, 1), memcpy(S->tok[i], d, (size_t)L), S->len[i] = L;
            char *d2 = strrchr(S->tok[i], '.');
            S->mlen[i] = (int)(d2 - S->tok[i]);
            S->sig[i] = malloc(600);
            S->slen[i] = jwt_b64url_decode(S->sig[i], d2 + 1, (int)strlen(d2 + 1));
            if (S->alg[0] == 'E' && S->alg[1] == 'S') { /* ES256: r || s -> DER */
                ECDSA_SIG *es = ECDSA_SIG_new();
                ECDSA_SIG_set0(es, BN_bin2bn(S->sig[i], 32, NULL), BN_bin2bn(S->sig[i] + 32, 32, NULL));
                S->der[i] = NULL;
                S->derlen[i] = i2d_ECDSA_SIG(es, &S->der[i]);
                ECDSA_SIG_free(es);
            } else {
                S->der[i] = S->sig[i], S->derlen[i] = S->slen[i];
            }
        }
    }
#ifdef JWT_RSA_SCREEN
    printf("(built with -DJWT_RSA_SCREEN)\n");
#endif
    printf("cpu features 0x%x", jwt_cpu_features());
#ifdef JWT_CRYPTO_MB
    printf(", crypto_mb (AVX-512 IFMA): %s", cmb_ok() ? "active" : "inactive");
#endif
#ifdef JWT_S2N
    printf(", s2n-bignum: %s", s2n_ok() ? "active" : "inactive");
#endif
    printf("\n");
    printf("P-256 comb window W=%d (%d windows, %zu KB of tables per ES256 key)\n", CC_P256_W, P256_NW,
           sizeof(p256_aff_t[P256_NW][P256_H]) * 2 / 1024);
    for (int i = 0; i < ns; i++) bench_set(&sets[i]);
    return 0;
}
