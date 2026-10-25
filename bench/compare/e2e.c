/* e2e.c — end-to-end jwt_verify_batch ns/token for the shoot-out, plus where the time goes.
 * Unity build: includes src/jwt.c.  Build twice: default (strict JSON) and -DJWT_FAST_JSON (simdjson-style).
 *   ./e2e tokens.json */
#include "jwt.c"

#include <stdio.h>
#include <time.h>

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e9 + ts.tv_nsec;
}
static volatile long sink;
static char **toks;
static int *tlen, ntok;

#define BEST(B, ...)                                                            \
    ({                                                                          \
        double best_ = 1e30;                                                    \
        for (int rep_ = 0; rep_ < 7; rep_++) {                                  \
            double t0_ = now_ns();                                              \
            int done_ = 0;                                                      \
            for (int i = 0; i + (B) <= ntok; i += (B), done_ += (B)) { __VA_ARGS__; }  \
            double v_ = (now_ns() - t0_) / done_;                               \
            if (v_ < best_) best_ = v_;                                         \
        }                                                                       \
        best_;                                                                  \
    })

int main(int argc, char **argv) {
    FILE *f = fopen(argc > 1 ? argv[1] : "tokens.json", "rb");
    if (!f) return 2;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(sz + 1);
    if (fread(buf, 1, sz, f) != (size_t)sz) return 2;
    buf[sz] = 0;
    toks = malloc(32768 * sizeof *toks), tlen = malloc(32768 * sizeof *tlen);
    for (char *p = buf; (p = strstr(p, "\"token\":\"")) && ntok < 32768;) {
        char *t = p + 9, *e = strchr(t, '"');
        toks[ntok] = calloc(e - t + 65, 1), memcpy(toks[ntok], t, e - t), tlen[ntok] = (int)(e - t); /* +64 B padding */
        ntok++, p = e;
    }
    const char *sec = getenv("JWT_SECRET") ? getenv("JWT_SECRET") : "cursed-jwt-test-secret";
    jwt_key_t k;
    jwt_key_init(&k, sec, strlen(sec));
    int64_t now = (int64_t)time(NULL);
    static jwt_result_t res[64];

    /* correctness: every test token accepted, a forged one rejected */
    int ok = 0;
    for (int i = 0; i < ntok; i += 8) {
        int m = ntok - i < 8 ? ntok - i : 8;
        jwt_verify_batch(&k, m, (const char *const *)toks + i, tlen + i, now, res);
        for (int j = 0; j < m; j++) ok += res[j].status == JWT_OK && res[j].uid > 0 && res[j].username_len > 0;
    }
    char *forged = calloc(tlen[0] + 65, 1);
    memcpy(forged, toks[0], tlen[0]);
    forged[tlen[0] - 2] = forged[tlen[0] - 2] == 'A' ? 'B' : 'A';
    const char *fp = forged;
    jwt_verify_batch(&k, 1, &fp, &tlen[0], now, res);
#if defined(JWT_FAST_JSON)
    const char *label = "cursed-jwt, simdjson-style JSON";
#elif defined(JWT_LANE_JSON) && !defined(JWT_NO_SHAPE_JSON)
    const char *label = "cursed-jwt, lanes + shape";
#elif defined(JWT_LANE_JSON)
    const char *label = "cursed-jwt, lanes + strict";
#elif !defined(JWT_NO_SHAPE_JSON)
    const char *label = "cursed-jwt, shape JSON (default)";
#else
    const char *label = "cursed-jwt, strict JSON";
#endif
    printf("%s: accepted %d/%d, forged rejected: %s\n", label, ok, ntok, res[0].status == JWT_INVALID ? "yes" : "NO");

    static const int BS[] = {1, 2, 3, 4, 8, 16, 32};
    printf("%-34s", "full verify ns/token, batch:");
    for (int b = 0; b < 7; b++) printf("%7d", BS[b]);
    printf("\n%-34s", label);
    for (int b = 0; b < 7; b++) {
        int B = BS[b];
        double v = BEST(B, jwt_verify_batch(&k, B, (const char *const *)toks + i, tlen + i, now, res); sink += res[0].uid);
        printf("%7.1f", v);
    }
    printf("\n");

    /* pieces, single token at a time, all hot */
    uint8_t out[512];
    jnow_t jn;
    jnow_init(&jn, now);
    int pl0 = 37;
    printf("pieces: sig b64 %.1f | payload b64 %.1f | +fast JSON %.1f | +strict JSON %.1f | +shape JSON %.1f | HMAC 8-batch %.1f ns/token\n",
           BEST(1, sink += jwt_b64url_decode(out, toks[i] + tlen[i] - 43, 43)),
           BEST(1, sink += jwt_b64url_decode(out, toks[i] + pl0, tlen[i] - 44 - pl0)),
           BEST(1, int pn = jwt_b64url_decode(out, toks[i] + pl0, tlen[i] - 44 - pl0); sink += payload_fast(out, pn, &jn, res)),
           BEST(1, int pn = jwt_b64url_decode(out, toks[i] + pl0, tlen[i] - 44 - pl0); sink += payload_check(out, pn, &jn, res)),
           BEST(1, int pn = jwt_b64url_decode(out, toks[i] + pl0, tlen[i] - 44 - pl0); sink += payload_shape(out, pn, &jn, res)),
           ({
               const uint8_t *m[8];
               int l[8];
               uint32_t mac[8][8];
               BEST(8, for (int j = 0; j < 8; j++) m[j] = (const uint8_t *)toks[i + j], l[j] = tlen[i + j] - 44;
                    jwt_hmac_fn *h = hmac_default();
                    h(&k, 8, m, l, mac); sink += mac[0][0]);
           }));
#ifdef JWT_HAVE_LANES
    /* JSON only, on pre-decoded hot payloads: per-token cost by batch size */
    {
        enum { NP = 1024 };
        static uint8_t dp[NP][320];
        static const uint8_t *dpp[NP];
        static int dn[NP];
        for (int i = 0; i < NP; i++) dn[i] = jwt_b64url_decode(dp[i], toks[i] + pl0, tlen[i] - 44 - pl0), dpp[i] = dp[i];
        printf("JSON only ns/token, batch:         ");
        for (int b = 0; b < 7; b++) printf("%7d", BS[b]);
        const char *nm[3] = {"strict", "shape", "lanes"};
        for (int kind = 0; kind < 3; kind++) {
            printf("\n  %-32s", nm[kind]);
            for (int b = 0; b < 7; b++) {
                int B = BS[b] > JL ? JL : BS[b];
                double best = 1e30;
                for (int rep = 0; rep < 7; rep++) {
                    double t0 = now_ns();
                    long done = 0;
                    for (int it = 0; it < 20; it++)
                        for (int i = 0; i + B <= NP; i += B, done += B) {
                            if (kind == 0) for (int j = 0; j < B; j++) sink += payload_check(dp[i + j], dn[i + j], &jn, res);
                            else if (kind == 1) for (int j = 0; j < B; j++) sink += payload_shape(dp[i + j], dn[i + j], &jn, res);
                            else {
                                jlane_t o[JL];
                                json_lanes(B, dpp + i, dn + i, o);
                                for (int j = 0; j < B; j++) sink += json_lane_claims(dp[i + j], &o[j], &jn, res);
                            }
                        }
                    double v = (now_ns() - t0) / done;
                    if (v < best) best = v;
                }
                printf("%7.1f", best);
            }
        }
        printf("\n");
    }
#endif
    return 0;
}
