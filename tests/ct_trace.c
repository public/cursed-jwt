/* ct_trace: constant-time check by trace equivalence, for the engines valgrind can't run here (SHA-NI, AVX-512, and
 * the AArch64 NEON / SHA2 engines on an x86-64 machine).
 *
 * Runs jwt_key_init and one HMAC engine on fixed messages under key 0 or key 1, between two markers: SDE SSC marks on
 * x86-64, calls to ct_trace_begin / ct_trace_end on AArch64. Under Intel SDE's debugtrace (x86-64) or qemu-aarch64's
 * execlog plugin (AArch64), scripts/ct-trace.sh records every executed instruction and every memory address, drops all data
 * values, and requires the two keys' traces to be identical: same control flow and same addresses, so no key-dependent
 * branch or index. An emulator trace is deterministic, so unlike dudect this is a proof for the inputs traced, not a
 * statistic. The "leaky" engine (an early-exit compare on the key) is the positive control and must differ.
 *
 *   ct_trace ENGINE KEY BATCH          (prints the first MAC word)
 *   make test-ct-sde SDE=/path/to/sde64
 *   make test-ct-qemu QEMU=/path/to/qemu-aarch64 EXECLOG=/path/to/libexeclog.so   (cross-builds for AArch64) */
#include "jwt.c"
#include <stdio.h>

#if defined(__x86_64__)
#define SSC_MARK(x) __asm__ volatile("movl %0, %%ebx; .byte 0x64, 0x67, 0x90" ::"i"(x) : "ebx", "memory")
#else
/* elsewhere (AArch64 under qemu): calls to two empty functions, whose addresses ct-trace.sh cuts the trace at */
__attribute__((noinline, used)) void ct_trace_begin(void) { __asm__ volatile("" ::: "memory"); }
__attribute__((noinline, used)) void ct_trace_end(void) { __asm__ volatile("" ::: "memory"); }
#define SSC_MARK(x) ((x) == 0x111 ? ct_trace_begin() : ct_trace_end())
#endif

static uint8_t msg[32][600];

int main(int argc, char **argv) {
    if (argc < 4) return fprintf(stderr, "usage: ct_trace ENGINE KEY BATCH\n"), 2;
    const char *e = argv[1];
    int kk = atoi(argv[2]), n = atoi(argv[3]);
    if (n < 1 || n > 32) return 2;
    uint8_t key[64];
    for (int i = 0; i < 64; i++) key[i] = kk ? (uint8_t)(i * 151 + 77) : (uint8_t)(i * 13 + 1);
    if (!strcmp(e, "leaky")) { /* positive control: an early-exit compare of the key against a constant */
        static const uint8_t ref[64] = { 1 };
        SSC_MARK(0x111);
        int i = 0;
        while (i < 64 && key[i] == ref[i]) i++;
        SSC_MARK(0x222);
        return i == 64;
    }
    static const struct {
        const char *name;
        jwt_hmac_fn *fn;
    } eng[] = {
        { "scalar", jwt_hmac_scalar },
#if defined(JWT_OSSL_SHA256) && defined(__x86_64__) && defined(__ELF__)
        { "ossl", jwt_hmac_ossl },
#endif
#if defined(__x86_64__)
        { "avx2", jwt_hmac_avx2 },       { "avx2x2", jwt_hmac_avx2x2 },     { "shani_1", jwt_hmac_shani_1 },
        { "shani_2", jwt_hmac_shani_2 }, { "shani_4", jwt_hmac_shani_4 },   { "avx512", jwt_hmac_avx512 },
        { "zmm", jwt_hmac_zmm },         { "avx512x2", jwt_hmac_avx512x2 },
#endif
#if defined(__aarch64__)
        { "neon", jwt_hmac_neon },       { "sha2_1", jwt_hmac_sha2_1 },     { "sha2_2", jwt_hmac_sha2_2 },
        { "sha2", jwt_hmac_sha2 },
#endif
    };
    jwt_hmac_fn *f = 0;
    for (size_t i = 0; i < sizeof eng / sizeof eng[0]; i++)
        if (!strcmp(e, eng[i].name)) f = eng[i].fn;
    if (!f) return fprintf(stderr, "ct_trace: no engine %s in this build\n", e), 2;
    const uint8_t *mp[32];
    int ml[32];
    static uint32_t mac[32][8];
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < 600; j++) msg[i][j] = (uint8_t)(j + i);
        mp[i] = msg[i], ml[i] = 570 - 3 * i;
    }
    jwt_key_t k;
    SSC_MARK(0x111);
    jwt_key_init(&k, key, 64);
    f(&k, n, mp, ml, mac);
    SSC_MARK(0x222);
    printf("%08x\n", mac[0][0]);
    return 0;
}
