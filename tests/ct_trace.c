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
 * ENGINE "verify" is cc_hmac_sha256_verify (the dispatched engine, then the tag compare) against key 0's tags: key 0
 * accepts them all and key 1 none, and the traces must still be identical.
 * ENGINE "sign_hs" is HS256 signing: jwt_key_init and jwt_sign_batch (payload checks, the dispatched HMAC, the
 * base64url encoder) of BATCH fixed payloads.  ENGINE "sign_ed" is Ed25519 signing: cc_skey_ed25519 from a 32-byte
 * seed (SHA-512, the scalar reduction, [a] B, the encoding of A), cc_sign_batch of BATCH fixed messages and
 * cc_skey_free.  ENGINE "sign_es" is ES256 signing: cc_skey_es256 (d = the key's first 32 bytes, top bit cleared),
 * cc_sign_batch of BATCH fixed messages (RFC 6979, [k] G, k^-1) and cc_skey_free.  The two keys / seeds differ in
 * every byte.
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
        { "avx2", jwt_hmac_avx2 },         { "shani_1", jwt_hmac_shani_1 }, { "shani_2", jwt_hmac_shani_2 },
        { "shani_4", jwt_hmac_shani_4 },   { "avx512", jwt_hmac_avx512 },   { "zmm", jwt_hmac_zmm },
#endif
#if defined(JWT_SHANI_MB) && defined(__ELF__)
        { "shani_4r", jwt_hmac_shani_4r }, { "x16", jwt_hmac_x16 },         { "shani_x16", jwt_hmac_shani_x16 },
#endif
#if defined(__aarch64__)
        { "neon", jwt_hmac_neon },         { "sha2_1", jwt_hmac_sha2_1 },   { "sha2_2", jwt_hmac_sha2_2 },
        { "sha2", jwt_hmac_sha2 },
#endif
    };
    if (!strcmp(e, "sign_hs") || !strcmp(e, "sign_ed") || !strcmp(e, "sign_es")) {
        static char pl[32][200], out[32][400];
        static const char *pp[32];
        static char *op[32];
        static int pn[32], on[32];
        static uint8_t sig[32][64], *sp[32];
        static const uint8_t *mp[32];
        static int ml[32];
        for (int i = 0; i < n; i++) {
            pn[i] = snprintf(pl[i], sizeof pl[i], "{\"sub\":\"%d\",\"username\":\"user%d\",\"exp\":4102444800}",
                             1000 + i, i);
            pp[i] = pl[i], op[i] = out[i], mp[i] = (const uint8_t *)pl[i], ml[i] = pn[i], sp[i] = sig[i];
        }
        if (e[5] == 'h') {
            jwt_key_t k;
            SSC_MARK(0x111);
            jwt_key_init(&k, key, 64);
            jwt_sign_batch(&k, n, pp, pn, op, on);
            SSC_MARK(0x222);
            printf("%s\n", out[0]);
        } else if (e[6] == 's') {
#ifndef JWT_NO_PK
            key[0] &= 0x7f; /* d < n */
#ifdef CC_ES256_NISTZ
            if (!(cc_cpu() & CC_CPU_BMI2_ADX)) fprintf(stderr, "sign_es: [k] G by ecp_nistz256 (no ADX)\n");
#endif
            SSC_MARK(0x111);
            cc_skey_t *sk = cc_skey_es256(key);
            cc_sign_batch(sk, n, mp, ml, sp);
            cc_skey_free(sk);
            SSC_MARK(0x222);
            printf("%02x%02x\n", sig[0][0], sig[0][63]);
#endif
        } else {
#ifndef JWT_NO_PK
            SSC_MARK(0x111);
            cc_skey_t *sk = cc_skey_ed25519(key);
            cc_sign_batch(sk, n, mp, ml, sp);
            cc_skey_free(sk);
            SSC_MARK(0x222);
            printf("%02x%02x\n", sig[0][0], sig[0][63]);
#endif
        }
        return 0;
    }
    jwt_hmac_fn *f = 0;
    int verify = !strcmp(e, "verify");
    for (size_t i = 0; i < sizeof eng / sizeof eng[0]; i++)
        if (!strcmp(e, eng[i].name)) f = eng[i].fn;
    if (!f && !verify) return fprintf(stderr, "ct_trace: no engine %s in this build\n", e), 2;
    const uint8_t *mp[32];
    int ml[32];
    static uint32_t mac[32][8];
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < 600; j++) msg[i][j] = (uint8_t)(j + i);
        mp[i] = msg[i], ml[i] = 570 - 3 * i;
    }
    jwt_key_t k;
    if (verify) { /* the tags are public: key 0's MACs, computed before the traced region */
        static uint8_t tag[32][32], ok[32];
        uint8_t k0[64];
        for (int i = 0; i < 64; i++) k0[i] = (uint8_t)(i * 13 + 1);
        cc_hmac_key_init(&k, k0, 64);
        cc_hmac_sha256_bytes(&k, n, mp, ml, tag);
        SSC_MARK(0x111);
        cc_hmac_key_init(&k, key, 64);
        int good = cc_hmac_sha256_verify(&k, n, mp, ml, (const uint8_t(*)[32])tag, ok);
        SSC_MARK(0x222);
        printf("%d of %d\n", good, n);
        return 0;
    }
    SSC_MARK(0x111);
    jwt_key_init(&k, key, 64);
    f(&k, n, mp, ml, mac);
    SSC_MARK(0x222);
    printf("%08x\n", mac[0][0]);
    return 0;
}
