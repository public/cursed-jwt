/* bench_jwt.c — ns/token per engine and batch size, vs OpenSSL.  Unity build: includes jwt.c.
 *   ./bench_jwt [tokens.json] [seconds-per-cell]
 */
#include "jwt.c"

#include "ossl_min.h"
#include <stdio.h>
#include <time.h>

static const char *SECRET = "cursed-jwt-test-secret";

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e9 + ts.tv_nsec;
}

/* ---- OpenSSL baselines ---- */
/* (a) what a naive server does: HMAC() one-shot, re-deriving the pads every time */
static void hmac_ossl_oneshot(const jwt_key_t *k, int n, const uint8_t *const *msg, const int *len,
                              uint32_t (*mac)[8]) {
    (void)k;
    for (int i = 0; i < n; i++) {
        uint8_t d[32];
        unsigned dl = 32;
        HMAC(EVP_sha256(), SECRET, (int)strlen(SECRET), msg[i], (size_t)len[i], d, &dl);
        for (int j = 0; j < 8; j++) mac[i][j] = be32(d + 4 * j);
    }
}
/* (b) best case for OpenSSL: precomputed ipad/opad SHA256_CTX midstates, copied per token */
static SHA256_CTX ossl_ictx, ossl_octx;
static void ossl_mid_init(void) {
    uint8_t blk[64] = { 0 };
    memcpy(blk, SECRET, strlen(SECRET));
    for (int i = 0; i < 64; i++) blk[i] ^= 0x36;
    SHA256_Init(&ossl_ictx), SHA256_Update(&ossl_ictx, blk, 64);
    for (int i = 0; i < 64; i++) blk[i] ^= 0x36 ^ 0x5c;
    SHA256_Init(&ossl_octx), SHA256_Update(&ossl_octx, blk, 64);
}
static void hmac_ossl_mid(const jwt_key_t *k, int n, const uint8_t *const *msg, const int *len, uint32_t (*mac)[8]) {
    (void)k;
    for (int i = 0; i < n; i++) {
        uint8_t d[32];
        SHA256_CTX c = ossl_ictx;
        SHA256_Update(&c, msg[i], (size_t)len[i]);
        SHA256_Final(d, &c);
        c = ossl_octx;
        SHA256_Update(&c, d, 32);
        SHA256_Final(d, &c);
        for (int j = 0; j < 8; j++) mac[i][j] = be32(d + 4 * j);
    }
}


typedef struct {
    const char *name;
    jwt_hmac_fn *hmac;
    unsigned need; /* JWT_CPU_* bits; engines this CPU lacks are left out */
} hengine_t;
static const hengine_t all_hengines[] = {
    { "openssl-HMAC()", hmac_ossl_oneshot, 0 },
    { "openssl-midstate", hmac_ossl_mid, 0 },
    { "scalar", jwt_hmac_scalar, 0 },
#if defined(JWT_OSSL_SHA256) && defined(__x86_64__) && defined(__ELF__)
    { "ossl-asm-1stream", jwt_hmac_ossl, 0 },
#endif
#ifdef JWT_HAVE_NEON
    { "neon-4lane", jwt_hmac_neon, 0 },
#endif
#if defined(__aarch64__)
    { "sha2-1stream", jwt_hmac_sha2_1, JWT_CPU_SHA2 },
    { "sha2-2stream", jwt_hmac_sha2_2, JWT_CPU_SHA2 },
    { "sha2-4stream", jwt_hmac_sha2_4, JWT_CPU_SHA2 },
#endif
#if defined(__x86_64__)
    { "shani-1stream", jwt_hmac_shani_1, JWT_CPU_SHANI },
    { "shani-2stream", jwt_hmac_shani_2, JWT_CPU_SHANI },
    { "shani-4stream", jwt_hmac_shani_4, JWT_CPU_SHANI },
    { "avx2-8lane", jwt_hmac_avx2, JWT_CPU_AVX2 },
    { "avx2-2x8lane", jwt_hmac_avx2x2, JWT_CPU_AVX2 },
    { "avx512vl-8lane", jwt_hmac_avx512, JWT_CPU_AVX512VL },
    { "avx512vl-2x8lane", jwt_hmac_avx512x2, JWT_CPU_AVX512VL },
    { "avx512-zmm16", jwt_hmac_zmm, JWT_CPU_AVX512VL },
    { "shani+zmm", jwt_hmac_shani_zmm, JWT_CPU_SHANI | JWT_CPU_AVX512VL },
#endif
};
static hengine_t hengines[sizeof all_hengines / sizeof all_hengines[0]];
static int NH;
static void pick_hengines(void) {
    for (size_t i = 0; i < sizeof all_hengines / sizeof all_hengines[0]; i++)
        if ((all_hengines[i].need & jwt_cpu_features()) == all_hengines[i].need) hengines[NH++] = all_hengines[i];
    printf("cpu features 0x%x, default engine %s\n", jwt_cpu_features(), jwt_engine());
}

static char **toks;
static int *tlen, *mlen, ntok;
static const uint8_t **msgs;

static void load(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror(path);
        exit(2);
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(sz + 1);
    if (fread(buf, 1, sz, f) != (size_t)sz) exit(2);
    buf[sz] = 0;
    int cap = 32768;
    toks = malloc(cap * sizeof *toks), tlen = malloc(cap * sizeof *tlen), mlen = malloc(cap * sizeof *mlen);
    msgs = malloc(cap * sizeof *msgs);
    for (char *p = buf; (p = strstr(p, "\"token\":\"")) && ntok < cap;) {
        char *t = p + 9, *e = strchr(t, '"');
        toks[ntok] = calloc(e - t + 65, 1), memcpy(toks[ntok], t, e - t), tlen[ntok] = (int)(e - t); /* +64 B padding */
        msgs[ntok] = (const uint8_t *)toks[ntok], mlen[ntok] = (int)(strrchr(toks[ntok], '.') - toks[ntok]);
        ntok++, p = e;
    }
    free(buf);
}

static double secs = 0.3;
static volatile uint32_t sink;

/* best-of-5 ns/token for f over all tokens in batches of B */
#define TIMEIT(B, call)                                                                                                \
    ({                                                                                                                 \
        double best = 1e30;                                                                                            \
        for (int rep = 0; rep < 5; rep++) {                                                                            \
            long done = 0;                                                                                             \
            double t0 = now_ns(), t1;                                                                                  \
            do {                                                                                                       \
                for (int i = 0; i + (B) <= ntok; i += (B)) { call; }                                                   \
                done += ntok - ntok % (B);                                                                             \
                t1 = now_ns();                                                                                         \
            } while (t1 - t0 < secs * 1e9 / 5);                                                                        \
            double v = (t1 - t0) / done;                                                                               \
            if (v < best) best = v;                                                                                    \
        }                                                                                                              \
        best;                                                                                                          \
    })

int main(int argc, char **argv) {
    load(argc > 1 ? argv[1] : "build/tokens.json");
    if (argc > 2) secs = atof(argv[2]);
    pick_hengines();
    ossl_mid_init();
    jwt_key_t k;
    jwt_key_init(&k, SECRET, strlen(SECRET));
    int64_t now = (int64_t)time(NULL);
    static const int BS[] = { 1, 2, 3, 4, 8, 16, 32 };
    enum { NB = sizeof BS / sizeof BS[0] };
    uint32_t(*mac)[8] = malloc(64 * sizeof *mac);
    jwt_result_t *res = malloc(64 * sizeof *res);

    /* sanity: every engine agrees with OpenSSL on the first 64 tokens */
    {
        uint32_t ref[64][8];
        hmac_ossl_oneshot(&k, 64, msgs, mlen, ref);
        for (int e = 0; e < NH; e++) {
            memset(mac, 0, 64 * sizeof *mac);
            hengines[e].hmac(&k, 64, msgs, mlen, mac);
            if (memcmp(ref, mac, sizeof ref)) printf("!! %s disagrees with OpenSSL\n", hengines[e].name);
        }
    }

    printf("%d tokens, signing input %d..%d bytes\n", ntok, mlen[0], mlen[ntok - 1]);
    printf("\nHMAC-SHA256 only (ns/token)\n%-18s", "engine \\ batch");
    for (int b = 0; b < NB; b++) printf("%8d", BS[b]);
    printf("\n");
    for (int e = 0; e < NH; e++) {
        printf("%-18s", hengines[e].name);
        for (int b = 0; b < NB; b++) {
            int B = BS[b];
            double v = TIMEIT(B, hengines[e].hmac(&k, B, msgs + i, mlen + i, mac); sink += mac[0][0]);
            printf("%8.1f", v);
        }
        printf("\n");
        fflush(stdout);
    }

    printf("\nfull jwt verify (split + header + sig decode + HMAC + payload b64 + JSON) (ns/token)\n%-18s",
           "engine \\ batch");
    for (int b = 0; b < NB; b++) printf("%8d", BS[b]);
    printf("\n");
    for (int e = 0; e < NH; e++) {
        printf("%-18s", hengines[e].name);
        for (int b = 0; b < NB; b++) {
            int B = BS[b];
            double v =
                TIMEIT(B, verify_impl(&k, B, (const char *const *)toks + i, tlen + i, now, res, hengines[e].hmac);
                       sink += res[0].status);
            printf("%8.1f", v);
        }
        printf("\n");
        fflush(stdout);
    }

    /* pieces */
    printf("\npieces (ns/token)\n");
    {
        uint8_t out[512];
        int pl0 = 37, n0 = mlen[0] - 37;
        double v = TIMEIT(1, sink += jwt_b64url_decode(out, toks[i] + pl0, mlen[i] - pl0));
        printf("  payload base64url decode, SIMD   %6.1f  (%d chars)\n", v, n0);
        v = TIMEIT(1, sink += jwt_b64url_decode_scalar(out, toks[i] + pl0, mlen[i] - pl0));
        printf("  payload base64url decode, scalar %6.1f\n", v);
        v = TIMEIT(1, sink += jwt_b64url_decode(out, toks[i] + mlen[i] + 1, 43));
        printf("  signature base64url decode       %6.1f\n", v);
        static uint8_t pb[512];
        jnow_t jn;
        jnow_init(&jn, now);
        v = TIMEIT(1, int pn = jwt_b64url_decode(pb, toks[i] + pl0, mlen[i] - pl0);
                   sink += payload_check(pb, pn, &jn, res));
        printf("  payload b64 + JSON, strict       %6.1f\n", v);
        v = TIMEIT(1, int pn = jwt_b64url_decode(pb, toks[i] + pl0, mlen[i] - pl0);
                   sink += payload_fast(pb, pn, &jn, res));
        printf("  payload b64 + JSON, simdjson     %6.1f\n", v);
    }
    return 0;
}
