/* test_ct: constant-time checks under valgrind memcheck, in the style of SUPERCOP's TIMECOP.
 *
 * Secret bytes are marked "undefined" with VALGRIND_MAKE_MEM_UNDEFINED. Memcheck then reports every conditional jump
 * and every memory address computed from them. Undefined values flowing through arithmetic are not errors; only
 * branches, addresses and system calls are. That is exactly the set of operations whose timing can depend on data.
 *
 *   key      the HS256 secret: jwt_key_init and every HMAC engine this build has and this CPU runs (x86-64 and AArch64), at batch sizes
 *            1..17 and message lengths 0..300. Expect 0 errors: run with --error-exitcode=1. The MACs are declassified
 *            only at the end, to check them against the scalar engine.
 *   token    (report only) the token bytes marked secret, through base64url decoding, a full HS256 verify and the
 *            RS256 / ES256 / EdDSA raw verifies, to map where token data steers branches and addresses. Bearer tokens
 *            are credentials, but all of verification's inputs are public in the cryptographic sense, so
 *            token-dependent timing is expected: cursed-jwt, like OpenSSL, BoringSSL and libsodium, verifies with
 *            variable-time code.
 *
 *   valgrind --error-exitcode=1 ./build/test_ct key
 *   valgrind ./build/test_ct token 2>&1 | grep -A3 'depends on uninitialised'
 * Without valgrind the client requests are no-ops, and the test only checks the MACs. */
#include "jwt.c"
#include <stdio.h>
#include <valgrind/memcheck.h>

static uint32_t mac_ref[17][8], mac_got[17][8];
static uint8_t msgbuf[17][320];
static const uint8_t *mp[17];
static int ml[17];

static int check_engine(const char *name, jwt_hmac_fn *f, const uint8_t *secret, size_t slen) {
    jwt_key_t k;
    uint8_t s[200];
    memcpy(s, secret, slen);
    VALGRIND_MAKE_MEM_UNDEFINED(s, slen); /* the key is secret from here on */
    jwt_key_init(&k, s, slen);
    int bad = 0, runs = 0;
    for (int n = 1; n <= 17; n++)
        for (int len = 0; len <= 300; len += 37 + n) {
            for (int i = 0; i < n; i++) ml[i] = (len + 13 * i) % 301;
            f(&k, n, mp, ml, mac_got);
            jwt_hmac_scalar(&k, n, mp, ml, mac_ref);
            VALGRIND_MAKE_MEM_DEFINED(mac_got, sizeof mac_got); /* declassify the tags, as a verifier's compare does */
            VALGRIND_MAKE_MEM_DEFINED(mac_ref, sizeof mac_ref);
            bad += memcmp(mac_got, mac_ref, sizeof(uint32_t) * 8 * n) != 0;
            runs++;
        }
    printf("  key: %-14s %d runs, %s\n", name, runs, bad ? "MAC MISMATCH" : "MACs match the scalar engine");
    return bad;
}

static int unhex(const char *h, uint8_t *o) {
    int n = 0;
    while (h[0] && h[0] != ' ' && h[0] != '\n') sscanf(h, "%2hhx", o + n++), h += 2;
    return n;
}
/* pk ALG FILE: one (message, signature) pair from a b009-format .prim file, signature marked secret */
static int pk_mode(const char *alg, const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return perror(path), 2;
    static char line[1 << 16];
    static uint8_t k1[600], k2[600], m[8192], sg[600];
    if (!fgets(line, sizeof line, fp)) return 2;
    int n1 = unhex(line, k1), n2 = strchr(line, ' ') ? unhex(strchr(line, ' ') + 1, k2) : 0;
    if (!fgets(line, sizeof line, fp)) return 2;
    int mlen = unhex(line, m), slen = unhex(strchr(line, ' ') + 1, sg);
    fclose(fp);
    jwt_pkey_t *pk = !strcmp(alg, "RS256")   ? jwt_pkey_rs256(k1, n1, k2, n2)
                     : !strcmp(alg, "ES256") ? jwt_pkey_es256(k1, k2)
                                             : jwt_pkey_ed25519(k1);
    if (!pk) return 2;
    VALGRIND_MAKE_MEM_UNDEFINED(sg, slen); /* the signature (part of the bearer token) is "secret" */
    const uint8_t *mp1 = m, *sp1 = sg;
    uint8_t ok = 0;
    printf("== token: %s raw verify, signature marked secret\n", alg);
    jwt_pk_verify_raw(pk, 1, &mp1, &mlen, &sp1, &slen, &ok);
    VALGRIND_MAKE_MEM_DEFINED(&ok, 1);
    printf("test_ct pk %s: verdict %d (memcheck errors above are the signature-dependent operations)\n", alg, ok);
    jwt_pkey_free(pk);
    return ok != 1;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "key";
    if (!strcmp(mode, "pk") && argc > 3) return pk_mode(argv[2], argv[3]);
    unsigned f = jwt_cpu_features();
    for (int i = 0; i < 17; i++) {
        for (int j = 0; j < 320; j++) msgbuf[i][j] = (uint8_t)(j * 7 + i * 31 + 1);
        mp[i] = msgbuf[i];
    }
    if (!strcmp(mode, "key")) {
        uint8_t secret[200];
        for (int i = 0; i < 200; i++) secret[i] = (uint8_t)(i * 73 + 5);
        int bad = 0;
        for (size_t slen = 0; slen <= 130; slen += 65) { /* empty, a short key, and one longer than a block (hashed) */
            printf(" key length %zu:\n", slen);
            bad += check_engine("scalar", jwt_hmac_scalar, secret, slen);
#if defined(JWT_OSSL_SHA256) && defined(__x86_64__) && defined(__ELF__)
            bad += check_engine("ossl", jwt_hmac_ossl, secret, slen);
#endif
#if defined(__x86_64__)
            if (f & JWT_CPU_AVX2) bad += check_engine("avx2", jwt_hmac_avx2, secret, slen);
            if (f & JWT_CPU_SHANI) {
                bad += check_engine("shani_1", jwt_hmac_shani_1, secret, slen);
                bad += check_engine("shani_2", jwt_hmac_shani_2, secret, slen);
                bad += check_engine("shani_4", jwt_hmac_shani_4, secret, slen);
#if defined(JWT_SHANI_MB) && defined(__ELF__)
                bad += check_engine("shani_4r", jwt_hmac_shani_4r, secret, slen);
#endif
            }
            if (f & JWT_CPU_AVX512VL) {
                bad += check_engine("avx512", jwt_hmac_avx512, secret, slen);
                bad += check_engine("zmm", jwt_hmac_zmm, secret, slen);
#if defined(JWT_SHANI_MB) && defined(__ELF__)
                bad += check_engine("x16", jwt_hmac_x16, secret, slen);
                if (f & JWT_CPU_SHANI) bad += check_engine("shani_x16", jwt_hmac_shani_x16, secret, slen);
#endif
            }
#endif
#if defined(__aarch64__)
            bad += check_engine("neon", jwt_hmac_neon, secret, slen);
            if (f & JWT_CPU_SHA2) {
                bad += check_engine("sha2_1", jwt_hmac_sha2_1, secret, slen);
                bad += check_engine("sha2_2", jwt_hmac_sha2_2, secret, slen);
                bad += check_engine("sha2", jwt_hmac_sha2, secret, slen);
            }
#endif
        }
        printf("test_ct key: %s (memcheck reports any key-dependent branch or address above)\n",
               bad ? "FAIL" : "MACs OK");
        return bad != 0;
    }
    /* token: report where token bytes steer branches and addresses (expected; see the header) */
    static const char tok[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                              "eyJzdWIiOiIxMjMiLCJ1c2VybmFtZSI6ImFsaWNlIiwiZXhwIjo0MTAyNDQ0ODAwfQ."
                              "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    char t[sizeof tok];
    uint8_t out[128];
    memcpy(t, tok, sizeof tok);
    VALGRIND_MAKE_MEM_UNDEFINED(t, sizeof tok - 1);
    printf("== token: base64url decoder (dispatched)\n");
    jwt_b64url_decode(out, t + 37, 70);
    printf("== token: base64url decoder (scalar)\n");
    jwt_b64url_decode_scalar(out, t + 37, 70);
    printf("== token: HS256 verify (structure, header, MAC compare, claims)\n");
    jwt_key_t k;
    jwt_key_init(&k, "secret", 6);
    const char *tp = t;
    int tl = (int)sizeof tok - 1;
    jwt_result_t r;
    jwt_verify_batch(&k, 1, &tp, &tl, 0, &r);
    printf("test_ct token: done (memcheck errors above are the token-dependent operations)\n");
    return 0;
}
