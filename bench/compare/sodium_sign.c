/* libsodium Ed25519 signing (crypto_sign_detached), for comparison with bench/bench_sign.c: the same seed and the
 * same signing input; ns/token, best of 5 passes.  Build against libsodium 1.0.20 (make compare-sign fetches it). */
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e9 + ts.tv_nsec;
}

int main(void) {
    if (sodium_init() < 0) return 1;
    static const char si[] =
        "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTYiLCJ1c2VybmFtZSI6ImFsaWNlIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjQxMDI0NDQ4MDB9";
    unsigned char seed[32], pk[32], sk[64], sig[64];
    for (int i = 0; i < 32; i++) seed[i] = (unsigned char)(i * 7 + 1);
    crypto_sign_seed_keypair(pk, sk, seed);
    double best = 1e18;
    unsigned sink = 0;
    for (int pass = 0; pass < 5; pass++) {
        long n = 0;
        double t0 = now_ns(), t1;
        do {
            for (int i = 0; i < 64; i++)
                crypto_sign_detached(sig, NULL, (const unsigned char *)si, sizeof si - 1, sk), sink += sig[0];
            n += 64;
        } while ((t1 = now_ns()) - t0 < 2e8);
        if ((t1 - t0) / n < best) best = (t1 - t0) / n;
    }
    printf("  %-34s b1   %9.1f ns/token\n", "libsodium crypto_sign_detached", best);
    return sink == 42;
}
