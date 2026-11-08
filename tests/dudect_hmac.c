/* dudect_hmac: statistical constant-time tests (the dudect method: Reparaz, Balasch, Verbauwhede, DATE 2017) for the
 * parts valgrind can't check here: the SHA-NI and AVX-512 engines.
 *
 * Each test times one operation (rdtscp) on inputs from two classes, randomly interleaved, then runs Welch's t-test
 * on the raw samples and on samples cropped at several percentiles. |t| > 10 is a leak; |t| < 4.5 is consistent with
 * constant time at this sample size (dudect's thresholds).
 *   key ENGINE BATCH   class 0: one fixed key; class 1: a fresh random key. Same 570-byte messages. The key is
 *                      the HS256 secret.
 *   mac BATCH          a full jwt_verify_batch, the forged MAC wrong in its first byte (0) or its last (1). An
 *                      early-exit compare would separate the classes, but so would input-dependent decoding of the
 *                      (attacker-known) token, since the classes also differ in which character was changed.
 *   mac1 / mac2 BATCH  disambiguation: class 0 wrong in its first (mac1) or last (mac2) byte, class 1 wrong in both. An
 *                      early-exit compare separates mac2 only; input-dependent decoding separates both.
 *   b64                the dispatched base64url decoder on a 43-char signature: one fixed string (0) or random ones (1).
 *                      The token is a credential. In a tight loop the table stays in L1, so this shows branches, not
 *                      cache-line leaks; see test_ct.c's token map for those.
 *   aa ENGINE BATCH    A/A negative control: both classes are copies of the same fixed key from two separate pools. It
 *                      must say ok, or the harness itself is asymmetric.
 *   control            positive control: an early-exit 32-byte compare (deliberately leaky), mismatch at byte 0 (0) or
 *                      byte 31 (1). It must report LEAK, or the harness can't see what it claims to test.
 * Usage: dudect_hmac TEST [ENGINE] [BATCH] [N]; N measurements per test (default 1,000,000). */
#include "jwt.c"
#include <stdio.h>
#include <math.h>
#include <x86intrin.h>

static uint64_t rng = 0x9E3779B97F4A7C15ull;
static uint64_t rnd(void) { return rng ^= rng << 13, rng ^= rng >> 7, rng ^= rng << 17; }
static inline uint64_t cyc(void) {
    unsigned a;
    return __rdtscp(&a);
}

typedef struct {
    double n, mean, m2;
} welch_t;
static void push(welch_t *w, double x) {
    w->n++;
    double d = x - w->mean;
    w->mean += d / w->n, w->m2 += d * (x - w->mean);
}
static double tstat(const welch_t *a, const welch_t *b) {
    double va = a->m2 / (a->n - 1), vb = b->m2 / (b->n - 1);
    return (a->mean - b->mean) / sqrt(va / a->n + vb / b->n);
}
static int cmp_u64(const void *x, const void *y) {
    uint64_t a = *(const uint64_t *)x, b = *(const uint64_t *)y;
    return a < b ? -1 : a > b;
}

/* the operation under test: class c, sample i */
static jwt_hmac_fn *eng;
static int macv; /* mac variant: 0 wrong first vs last byte; 1 first vs both; 2 last vs both */
static int batch;
static jwt_key_t kfix, krand[256], kfixpool[256], kfixpool2[256]; /* equal-sized pools: both classes touch the same
                                                                     amount of memory (dudect's rule) */
static uint8_t msgs[32][600];
static const uint8_t *mp[32];
static int ml[32];
static uint32_t macs[32][8];
static char tokA[32][700], tokB[32][700];
static const char *tp[32];
static int tl[32];
static jwt_result_t res[32];
static char sigfix[44], sigrand[256][44], sigfixpool[256][44];
static uint8_t dec[64];
static int test;
static uint8_t cmpa[32], cmpb0[32], cmpb1[32], cmpcur[32];
static volatile int sink;
__attribute__((noinline)) static int leaky_eq(const uint8_t *a, const uint8_t *b) {
    for (int i = 0; i < 32; i++)
        if (a[i] != b[i]) return 0;
    return 1;
}
/* both classes are copied into the same working buffers before the timed region (dudect's rule: the classes may
 * differ only in the secret, not in where it is read from) */
static jwt_key_t kcur;
static char tokcur[32][700], sigcur[44];
/* branchless on the class: the pool is chosen by arithmetic, so no class-dependent branch enters the branch
 * history that the timed operation's own branches are predicted from */
static const jwt_key_t *kpool[2][2]; /* [aa][class] */
static const char *tpool[2], *spool[2];
static const uint8_t *cpool[2];
static void prepare(int c, int i) {
    if (test == 0 || test == 4) kcur = kpool[test == 4][c][i & 255];
    else if (test == 1) {
        const char *b = tpool[c];
        for (int j = 0; j < batch; j++) memcpy(tokcur[j], b + 700 * j, (size_t)tl[j]);
    } else if (test == 2) memcpy(sigcur, spool[c] + 44 * (i & 255), 43);
    else memcpy(cmpcur, cpool[c], 32);
}
/* a fixed run of perfectly predictable branches: pushes the class out of the global branch history */
static volatile int scrub_sink;
__attribute__((noinline)) static void scrub_history(void) {
    int a = 0;
    for (int i = 0; i < 512; i++) a += i & 1 ? 3 : 5;
    scrub_sink = a;
}
static void op(void) {
    if (test == 0 || test == 4) eng(&kcur, batch, mp, ml, macs);
    else if (test == 1) jwt_verify_batch(&kfix, batch, tp, tl, 0, res);
    else if (test == 2) jwt_b64url_decode(dec, sigcur, 43);
    else sink = leaky_eq(cmpa, cmpcur);
}

int main(int argc, char **argv) {
    const char *t = argc > 1 ? argv[1] : "key", *e = argc > 2 ? argv[2] : "dispatch";
    batch = argc > 3 ? atoi(argv[3]) : 1;
    long N = argc > 4 ? atol(argv[4]) : 1000000;
    macv = !strcmp(t, "mac1") ? 1 : !strcmp(t, "mac2") ? 2 : 0;
    test = !strcmp(t, "key") ? 0 : !strncmp(t, "mac", 3) ? 1 : !strcmp(t, "b64") ? 2 : !strcmp(t, "aa") ? 4 : 3;
    for (int i = 0; i < 32; i++) cmpa[i] = cmpb0[i] = cmpb1[i] = (uint8_t)rnd();
    cmpb0[0] ^= 1, cmpb1[31] ^= 1;
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)rnd();
    jwt_key_init(&kfix, key, 32);
    for (int r = 0; r < 256; r++) {
        for (int i = 0; i < 32; i++) key[i] = (uint8_t)rnd();
        jwt_key_init(&krand[r], key, 32);
        kfixpool[r] = kfixpool2[r] = kfix;
    }
    for (int j = 0; j < 32; j++) {
        for (int i = 0; i < 570; i++) msgs[j][i] = (uint8_t)('A' + rnd() % 26);
        mp[j] = msgs[j], ml[j] = 570;
    }
    unsigned f = jwt_cpu_features();
    eng = jwt_hmac_scalar;
    if (!strcmp(e, "ossl")) eng = jwt_hmac_ossl;
    else if (!strcmp(e, "avx2")) eng = jwt_hmac_avx2;
    else if (!strcmp(e, "avx512") && (f & JWT_CPU_AVX512VL)) eng = jwt_hmac_avx512;
    else if (!strcmp(e, "zmm") && (f & JWT_CPU_AVX512VL)) eng = jwt_hmac_zmm;
    else if (!strcmp(e, "shani_4") && (f & JWT_CPU_SHANI)) eng = jwt_hmac_shani_4;
#if defined(JWT_SHANI_MB)
    else if (!strcmp(e, "shani_4r") && (f & JWT_CPU_SHANI)) eng = jwt_hmac_shani_4r;
    else if (!strcmp(e, "x16") && (f & JWT_CPU_AVX512VL)) eng = jwt_hmac_x16;
    else if (!strcmp(e, "shani_x16") && (f & JWT_CPU_SHANI) && (f & JWT_CPU_AVX512VL)) eng = jwt_hmac_shani_x16;
#endif
    else if (strcmp(e, "scalar") && (test == 0 || test == 4)) {
        printf("%s %s b%d: engine not available on this CPU/build\n", t, e, batch);
        return 0;
    }
    if (test == 1) { /* valid HS256 tokens, then two forgeries per slot: MAC wrong in its first or last byte */
        static const char *hdr = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        for (int j = 0; j < batch; j++) {
            char pl[128], pb[200];
            int pn = snprintf(pl, sizeof pl, "{\"sub\":\"%d\",\"username\":\"u%d\",\"exp\":4102444800}", j + 1, j);
            int bn = 0; /* base64url, unpadded */
            static const char *A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            for (int i = 0; i < pn; i += 3) {
                uint32_t v = (uint32_t)(uint8_t)pl[i] << 16 | (i + 1 < pn ? (uint8_t)pl[i + 1] << 8 : 0) |
                             (i + 2 < pn ? (uint8_t)pl[i + 2] : 0);
                pb[bn++] = A[v >> 18], pb[bn++] = A[v >> 12 & 63];
                if (i + 1 < pn) pb[bn++] = A[v >> 6 & 63];
                if (i + 2 < pn) pb[bn++] = A[v & 63];
            }
            pb[bn] = 0;
            int n0 = snprintf(tokA[j], 700, "%s.%s.", hdr, pb);
            const uint8_t *m1 = (const uint8_t *)tokA[j];
            int l1 = n0 - 1;
            uint32_t mac[1][8];
            jwt_hmac_scalar(&kfix, 1, &m1, &l1, mac);
            uint8_t mb[33];
            for (int w = 0; w < 8; w++)
                for (int b = 0; b < 4; b++) mb[4 * w + b] = (uint8_t)(mac[0][w] >> (24 - 8 * b));
            mb[32] = 0;
            char sg[44];
            int sn = 0;
            for (int i = 0; i < 32; i += 3) {
                uint32_t v = (uint32_t)mb[i] << 16 | (i + 1 < 32 ? mb[i + 1] << 8 : 0) | (i + 2 < 32 ? mb[i + 2] : 0);
                sg[sn++] = A[v >> 18], sg[sn++] = A[v >> 12 & 63];
                if (i + 1 < 32) sg[sn++] = A[v >> 6 & 63];
                if (i + 2 < 32) sg[sn++] = A[v & 63];
            }
            sg[43] = 0;
            memcpy(tokB[j], tokA[j], n0);
            memcpy(tokA[j] + n0, sg, 44), memcpy(tokB[j] + n0, sg, 44);
            /* class 0: wrong first byte (mac, mac1) or last (mac2); class 1: last (mac) or both (mac1, mac2) */
            int af = macv != 2, al = macv == 2, bf = macv != 0;
            if (af) tokA[j][n0] = tokA[j][n0] == 'A' ? 'B' : 'A';           /* first byte of the MAC */
            if (al) tokA[j][n0 + 42] = tokA[j][n0 + 42] == 'A' ? 'E' : 'A'; /* the last char: last byte */
            if (bf) tokB[j][n0] = tokB[j][n0] == 'A' ? 'B' : 'A';
            tokB[j][n0 + 42] = tokB[j][n0 + 42] == 'A' ? 'E' : 'A';
            tl[j] = n0 + 43;
        }
    }
    if (test == 2) {
        static const char *A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        for (int i = 0; i < 42; i++) sigfix[i] = A[rnd() & 63];
        sigfix[42] = 'A';
        for (int r = 0; r < 256; r++) memcpy(sigfixpool[r], sigfix, 44);
        for (int r = 0; r < 256; r++) {
            for (int i = 0; i < 42; i++) sigrand[r][i] = A[rnd() & 63];
            sigrand[r][42] = "AEIMQUYcgkosw048"[rnd() & 15]; /* canonical last char (low 2 bits zero) */
        }
    }
    uint64_t *x = malloc(sizeof *x * N);
    uint8_t *cls = malloc(N);
    for (int j = 0; j < 32; j++) tp[j] = tokcur[j];
    kpool[0][0] = kfixpool, kpool[0][1] = krand, kpool[1][0] = kfixpool, kpool[1][1] = kfixpool2;
    tpool[0] = &tokA[0][0], tpool[1] = &tokB[0][0], spool[0] = &sigfixpool[0][0], spool[1] = &sigrand[0][0];
    cpool[0] = cmpb0, cpool[1] = cmpb1;
    uint8_t *seq = malloc(N); /* the class sequence, drawn before measuring */
    for (long i = 0; i < N; i++) seq[i] = (uint8_t)(rnd() & 1);
    for (long i = 0; i < 10000; i++) prepare((int)(rnd() & 1), (int)i), op(); /* warm up */
    for (long i = 0; i < N; i++) {
        int c = seq[i];
        prepare(c, (int)i);
        scrub_history();
        _mm_mfence(), _mm_lfence(); /* the copy's stores done before the clock starts */
        uint64_t t0 = cyc();
        op();
        uint64_t t1 = cyc();
        x[i] = t1 - t0, cls[i] = (uint8_t)c;
    }
    /* Welch's t on raw samples and on samples below the 50/75/90/95/99th percentile of the whole set */
    uint64_t *s = malloc(sizeof *s * N);
    memcpy(s, x, sizeof *s * N);
    qsort(s, N, sizeof *s, cmp_u64);
    static const double pc[] = { 1.0, 0.5, 0.75, 0.9, 0.95, 0.99 };
    double tmax = 0;
    char detail[256] = "";
    int dn = 0;
    for (int p = 0; p < 6; p++) {
        uint64_t cut = pc[p] >= 1.0 ? ~0ull : s[(long)(pc[p] * (N - 1))];
        welch_t a = { 0 }, b = { 0 };
        for (long i = 0; i < N; i++)
            if (x[i] <= cut) push(cls[i] ? &b : &a, (double)x[i]);
        double tv = tstat(&a, &b);
        if (fabs(tv) > fabs(tmax)) tmax = tv;
        dn += snprintf(detail + dn, sizeof detail - dn, " p%.0f:%+.2f", pc[p] * 100, tv);
    }
    printf("%s %s b%d: N=%ld median %lu cyc, max|t| %.2f %s [%s ]\n", t, e, batch, N, (unsigned long)s[N / 2],
           fabs(tmax),
           fabs(tmax) > 10    ? "LEAK"
           : fabs(tmax) > 4.5 ? "inconclusive"
                              : "ok",
           detail);
    return 0;
}
