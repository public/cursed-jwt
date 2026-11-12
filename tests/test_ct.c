/* test_ct: constant-time checks under valgrind memcheck, in the style of SUPERCOP's TIMECOP.
 *
 * Secret bytes are marked "undefined" with VALGRIND_MAKE_MEM_UNDEFINED. Memcheck then reports every conditional jump
 * and every memory address computed from them. Undefined values flowing through arithmetic are not errors; only
 * branches, addresses and system calls are. That is exactly the set of operations whose timing can depend on data.
 *
 *   key      the HS256 secret: jwt_key_init and every HMAC engine this build has and this CPU runs (x86-64 and AArch64), at batch sizes
 *            1..17 and message lengths 0..300. Expect 0 errors: run with --error-exitcode=1. The MACs are declassified
 *            only at the end, to check them against the scalar engine.  Then cursed-crypto's compares:
 *            cc_hmac_sha256_verify against public tags (right and wrong ones) and cc_tag_eq32 on secret bytes, whose
 *            verdicts are declassified only after the call.
 *   sign     signing: the HS256 key through jwt_key_init and jwt_sign_batch (payload checks, the dispatched HMAC,
 *            the base64url encoder of the MAC), at batch sizes 1..17; the Ed25519 seed through cc_skey_ed25519 (SHA-512,
 *            the scalar reduction, [a] B, the encoding of A), with the key's a and prefix marked secret again before
 *            cc_sign_batch at batch sizes 1..17 (which computes r, [r] B, k and S from them); and the signing
 *            primitives on their own with their inputs secret: SHA-512, the reduction mod L of a 512-bit value (r),
 *            the fixed-base multiplication [r] B and the field inversion.  Only the outputs are declassified, to
 *            check them against a key built from the same bytes left public.  Expect 0 errors.
 *   sign-control  the positive control for `sign`: the verify side's variable-time scalar reduction and signed-digit
 *            recoding (cc_ed25519.inc) on a secret scalar.  Memcheck must report errors here (make test-ct checks
 *            that it does), which shows that the sign path's clean run is not an artifact of the set-up.
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

/* cc_hmac_sha256_verify under a secret key: the MACs it computes are secret, the tags (the token's) are public, and
 * ok[] may be read only by the caller; then cc_tag_eq32 with both sides secret */
static int check_compare(const uint8_t *secret, size_t slen) {
    cc_hmac_key_t k;
    uint8_t s[200], tag[17][32], ok[17], a[32], b[32];
    memcpy(s, secret, slen);
    cc_hmac_key_init(&k, s, slen); /* public copy, for the expected tags */
    int bad = 0, runs = 0;
    for (int n = 1; n <= 17; n++) {
        for (int i = 0; i < n; i++) ml[i] = (40 * n + 13 * i) % 301;
        cc_hmac_sha256_bytes(&k, n, mp, ml, tag);
        for (int i = 0; i < n; i++)
            if (i % 3 == 1) tag[i][(i * 5) % 32] ^= (uint8_t)(1u << (i % 8)); /* a wrong tag, wrong in one bit */
        cc_hmac_key_t ks;
        memcpy(s, secret, slen);
        VALGRIND_MAKE_MEM_UNDEFINED(s, slen);
        cc_hmac_key_init(&ks, s, slen);
        int good = cc_hmac_sha256_verify(&ks, n, mp, ml, (const uint8_t(*)[32])tag, ok);
        VALGRIND_MAKE_MEM_DEFINED(ok, sizeof ok); /* the verdicts are the caller's to branch on */
        VALGRIND_MAKE_MEM_DEFINED(&good, sizeof good);
        int want = 0;
        for (int i = 0; i < n; i++) want += i % 3 != 1, bad += ok[i] != (i % 3 != 1);
        bad += good != want, runs++;
    }
    for (int i = 0; i < 64; i++) {
        for (int j = 0; j < 32; j++) a[j] = b[j] = (uint8_t)(secret[(i + j) % 200] + j);
        if (i & 1) b[i % 32] ^= (uint8_t)(0x80u >> (i % 8));
        VALGRIND_MAKE_MEM_UNDEFINED(a, 32), VALGRIND_MAKE_MEM_UNDEFINED(b, 32);
        int eq = cc_tag_eq32(a, b);
        VALGRIND_MAKE_MEM_DEFINED(&eq, sizeof eq);
        bad += eq != !(i & 1), runs++;
    }
    printf("  compare: verify + tag_eq32 %d runs, %s\n", runs, bad ? "WRONG VERDICT" : "verdicts right");
    return bad;
}

/* ---- sign ---- */
static int sign_hs(const uint8_t *secret, size_t slen) {
    static char pl[17][160], out[17][400], ref[17][400];
    const char *pp[17];
    char *op[17], *rp[17];
    int pn[17], on[17], rn[17], bad = 0, runs = 0;
    for (int i = 0; i < 17; i++) {
        pn[i] = snprintf(pl[i], sizeof pl[i], "{\"sub\":\"%d\",\"username\":\"u%0*d\",\"exp\":4102444800}",
                         i + 1, i * 5, i);
        pp[i] = pl[i], op[i] = out[i], rp[i] = ref[i];
    }
    jwt_key_t kp, ks;
    uint8_t s[200];
    memcpy(s, secret, slen);
    jwt_key_init(&kp, s, slen); /* public copy, for the reference tokens */
    VALGRIND_MAKE_MEM_UNDEFINED(s, slen);
    jwt_key_init(&ks, s, slen);
    for (int n = 1; n <= 17; n++) {
        jwt_sign_batch(&kp, n, pp, pn, rp, rn);
        int got = jwt_sign_batch(&ks, n, pp, pn, op, on);
        VALGRIND_MAKE_MEM_DEFINED(out, sizeof out); /* the tokens are issued: declassify them */
        VALGRIND_MAKE_MEM_DEFINED(on, sizeof on), VALGRIND_MAKE_MEM_DEFINED(&got, sizeof got);
        bad += got != n;
        for (int i = 0; i < n; i++) bad += on[i] != rn[i] || strcmp(out[i], ref[i]) != 0;
        runs++;
    }
    printf("  sign: HS256 jwt_sign_batch %d runs, %s\n", runs, bad ? "TOKEN MISMATCH" : "tokens match");
    return bad;
}
static int sign_ed(void) {
    uint8_t seed[32], pub[32], pubref[32], sig[17][64], ref[17][64], *sp[17], *rp[17];
    const uint8_t *mp[17];
    int bad = 0, runs = 0;
    for (int t = 0; t < 3; t++) {
        for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(i * 29 + 7 * t + (t == 2 ? 0x80 : 0));
        cc_skey_t *kp = cc_skey_ed25519(seed);
        VALGRIND_MAKE_MEM_UNDEFINED(seed, 32); /* the private key is secret from here on */
        cc_skey_t *ks = cc_skey_ed25519(seed);
        /* a and prefix are derived from the seed, so already secret; mark them again, as the contract names them */
        VALGRIND_MAKE_MEM_UNDEFINED(ks->a_m, sizeof ks->a_m), VALGRIND_MAKE_MEM_UNDEFINED(ks->prefix, 32);
        cc_skey_public(ks, pub), cc_skey_public(kp, pubref);
        VALGRIND_MAKE_MEM_DEFINED(pub, 32);
        bad += memcmp(pub, pubref, 32) != 0;
        for (int n = 1; n <= 17; n++) {
            for (int i = 0; i < n; i++) sp[i] = sig[i], rp[i] = ref[i], mp[i] = msgbuf[i], ml[i] = (n * 19 + i * 37) % 301;
            cc_sign_batch(kp, n, mp, ml, rp);
            cc_sign_batch(ks, n, mp, ml, sp);
            VALGRIND_MAKE_MEM_DEFINED(sig, sizeof sig); /* the signatures are output: declassify them */
            for (int i = 0; i < n; i++) bad += memcmp(sig[i], ref[i], 64) != 0;
            runs++;
        }
        cc_skey_free(ks), cc_skey_free(kp);
    }
    printf("  sign: Ed25519 cc_skey_ed25519 + cc_sign_batch %d runs, %s\n", runs, bad ? "SIGNATURE MISMATCH" : "signatures match");
    /* the primitives on their own, inputs secret */
    uint8_t x[64], h1[64], h2[64], r1[32], r2[32];
    for (int t = 0; t < 8; t++) {
        for (int i = 0; i < 64; i++) x[i] = (uint8_t)(i * 97 + t * 31 + (t & 1 ? 0xff : 0));
        cc_sha512(x, 64, h1);
        VALGRIND_MAKE_MEM_UNDEFINED(x, 64);
        cc_sha512(x, 64, h2); /* SHA-512 of a secret */
        sg_sc rm, rm2;
        sg_sc_reduce(rm, h2); /* r = h mod L of a secret h */
        sg_sc_bytes(r2, rm);
        VALGRIND_MAKE_MEM_DEFINED(h1, 64);
        sg_sc_reduce(rm2, h1), sg_sc_bytes(r1, rm2);
        sg_niels(*tab)[8] = malloc(sizeof(sg_niels) * 256);
        sg_table(tab);
        sg_p3 P, Q;
        sg_fe zi, zq;
        uint8_t e1[32], e2[32];
        sg_base_mul(&P, (const sg_niels(*)[8])tab, r2); /* [r] B of a secret r */
        sg_inv(zi, P.Z);                                /* 1 / Z of a secret point */
        sg_encode(e2, &P, zi);
        sg_base_mul(&Q, (const sg_niels(*)[8])tab, r1), sg_inv(zq, Q.Z), sg_encode(e1, &Q, zq);
        VALGRIND_MAKE_MEM_DEFINED(h2, 64), VALGRIND_MAKE_MEM_DEFINED(r2, 32), VALGRIND_MAKE_MEM_DEFINED(e2, 32);
        bad += memcmp(h1, h2, 64) != 0 || memcmp(r1, r2, 32) != 0 || memcmp(e1, e2, 32) != 0;
        free(tab), runs++;
    }
    printf("  sign: SHA-512, mod L, [r] B, inversion on secrets: %s\n", bad ? "MISMATCH" : "outputs match");
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
#ifndef JWT_NO_PK
    if (!strcmp(mode, "sign-control")) {
        uint8_t h[64];
        uint64_t kk[4];
        int16_t d[ED_NW];
        for (int i = 0; i < 64; i++) h[i] = (uint8_t)(i * 53 + 11);
        VALGRIND_MAKE_MEM_UNDEFINED(h, 64);
        sc_reduce512(kk, h); /* verify-side: variable time, so it must be flagged on a secret */
        ed_recode(d, kk);
        VALGRIND_MAKE_MEM_DEFINED(d, sizeof d);
        printf("test_ct sign-control: done (memcheck must have reported errors above)\n");
        return d[0] == 12345;
    }
#endif
    if (!strcmp(mode, "sign")) {
        uint8_t secret[200];
        for (int i = 0; i < 200; i++) secret[i] = (uint8_t)(i * 73 + 5);
        int bad = 0;
        for (size_t slen = 0; slen <= 130; slen += 65) bad += sign_hs(secret, slen);
#ifndef JWT_NO_PK
        bad += sign_ed();
#endif
        printf("test_ct sign: %s (memcheck reports any secret-dependent branch or address above)\n",
               bad ? "FAIL" : "outputs OK");
        return bad != 0;
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
            bad += check_compare(secret, slen);
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
