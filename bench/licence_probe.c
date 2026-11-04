/* licence_probe.c — does SIMD width slow down the code that runs *after* it (AVX-512 frequency licences)?
 * Each trial: a ~2 ms burst of HMACs on one engine, an optional scalar spin of D µs, then a fixed
 * scalar SHA-256 probe (~20 µs) timed with clock_gettime.  Median over interleaved trials.
 * A probe that's slower after zmm than after scalar means the core downclocked; a slower burst
 * ns/token means the engine itself ran at a lower clock.
 *   gcc -O3 -march=cascadelake -DJWT_AVX512 -Iinclude -Isrc bench/licence_probe.c -o licence_probe && ./licence_probe */
#include "jwt.c"

#include <stdio.h>
#include <time.h>

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e9 + ts.tv_nsec;
}
static volatile uint32_t sink;

static uint32_t pst[8], pw[16];
static void probe_work(int n) { /* scalar, dependent chain of compressions */
    for (int i = 0; i < n; i++) compress_scalar(pst, pw), pw[i & 15] ^= pst[0];
    sink += pst[0];
}
static double spin_scalar_us(double us) {
    double t0 = now_ns();
    while (now_ns() - t0 < us * 1e3) probe_work(4);
    return 0;
}

enum { NT = 64, TRIALS = 300 };
static uint8_t msgbuf[NT][224]; /* >= 64 B slack for JWT_INPUT_PADDED */
static const uint8_t *msg[NT];
static int len[NT];
static uint32_t mac[NT][8];

static double burst(jwt_hmac_fn *f, const jwt_key_t *k, double ms) { /* returns ns/token */
    long done = 0;
    double t0 = now_ns(), t1;
    do {
        f(k, 32, msg, len, mac);
        sink += mac[0][0];
        done += 32;
        t1 = now_ns();
    } while (t1 - t0 < ms * 1e6);
    return (t1 - t0) / done;
}

static int cmpd(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

typedef struct {
    const char *name;
    jwt_hmac_fn *f;
    double delay_us;
    double probe[TRIALS], tok[TRIALS];
} cond_t;

int main(void) {
    jwt_key_t k;
    jwt_key_init(&k, "cursed-jwt-test-secret", 22);
    for (int i = 0; i < NT; i++) {
        for (int j = 0; j < 140; j++) msgbuf[i][j] = (uint8_t)('A' + (i * 7 + j) % 26);
        msg[i] = msgbuf[i], len[i] = 140; /* like a typical token: 3 inner blocks + outer */
    }
    for (int i = 0; i < 16; i++) pw[i] = i * 0x9E3779B9u;
    /* probe size: ~20 µs */
    int pn = 1;
    for (;;) {
        double t0 = now_ns();
        probe_work(pn);
        if (now_ns() - t0 > 20e3) break;
        pn *= 2;
    }
    cond_t c[] = {
        { "scalar", jwt_hmac_scalar, 0 },
        { "avx2 ymm x8", jwt_hmac_avx2, 0 },
        { "avx512vl ymm x8 (default)", jwt_hmac_avx512, 0 },
        { "zmm x16", jwt_hmac_zmm, 0 },
        { "zmm x16, then 200us scalar", jwt_hmac_zmm, 200 },
        { "zmm x16, then 500us scalar", jwt_hmac_zmm, 500 },
        { "zmm x16, then 1000us scalar", jwt_hmac_zmm, 1000 },
        { "zmm x16, then 2000us scalar", jwt_hmac_zmm, 2000 },
        { "avx512vl ymm, then 500us scalar", jwt_hmac_avx512, 500 },
    };
    int nc = sizeof c / sizeof c[0];
    for (int i = 0; i < nc; i++) burst(c[i].f, &k, 5); /* warm up code paths */
    for (int t = 0; t < TRIALS; t++)
        for (int i = 0; i < nc; i++) { /* interleaved so drift hits every condition alike */
            int ci = (i + t) % nc;
            c[ci].tok[t] = burst(c[ci].f, &k, 2.0);
            if (c[ci].delay_us > 0) spin_scalar_us(c[ci].delay_us);
            double t0 = now_ns();
            probe_work(pn);
            c[ci].probe[t] = now_ns() - t0;
        }
    double base = 0;
    printf("probe = %d scalar compressions; %d interleaved trials; 2 ms bursts of 32-token batches\n", pn, TRIALS);
    printf("%-34s %14s %10s %14s\n", "burst engine", "probe median", "vs scalar", "burst ns/token");
    for (int i = 0; i < nc; i++) {
        qsort(c[i].probe, TRIALS, sizeof(double), cmpd);
        qsort(c[i].tok, TRIALS, sizeof(double), cmpd);
        double p = c[i].probe[TRIALS / 2];
        if (i == 0) base = p;
        printf("%-34s %11.0f ns %9.1f%% %14.1f\n", c[i].name, p, 100.0 * (p / base - 1), c[i].tok[TRIALS / 2]);
    }
    return 0;
}
