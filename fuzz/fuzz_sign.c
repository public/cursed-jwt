/* fuzz_sign.c — libFuzzer harness for signing: the payload checks and the base64url encoder (unity build: includes
 * jwt.c).
 *
 * Input: one config byte, then payloads separated by NUL bytes (at most 33).  Config bit 0 adds EdDSA signing of the
 * first payload; bits 1-2 pick the HMAC key's length; bit 3 adds ES256 signing of the first payload.
 * Oracles (any mismatch aborts):
 *   - the encoder equals a table-driven RFC 4648 reference and decodes back to its input;
 *   - the batch and each payload alone give identical tokens and lengths, on every HMAC engine this CPU runs;
 *   - an issued token is the canonical header, the payload's exact bytes in base64url and a MAC that
 *     cc_hmac_sha256_verify accepts; it is NUL-terminated at out_len <= JWT_TOKEN_MAX;
 *   - the verifier agrees with the sign-side check in both directions: an issued token is accepted by
 *     jwt_verify_batch (JWT_OK or JWT_BAD_PAYLOAD) at a time inside [nbf, exp) whenever exp and nbf are integers,
 *     and a refused payload, signed by hand with the same header and key, is JWT_INVALID for the verifier;
 *   - with bit 0 (EdDSA) or bit 3 (ES256), the token verifies with jwt_verify_batch_pk under the derived public key;
 *   - ASan / UBSan find nothing.
 * Build: make fuzz (clang with -fsanitize=fuzzer); without libFuzzer, fuzz/replay.c runs a corpus through it. */
#include "jwt.c"

#include <stdio.h>

#define FZ_ASSERT(c, ...)                                                                                              \
    do {                                                                                                               \
        if (!(c)) {                                                                                                    \
            fprintf(stderr, __VA_ARGS__);                                                                              \
            fputc('\n', stderr);                                                                                       \
            abort();                                                                                                   \
        }                                                                                                              \
    } while (0)

static const struct {
    jwt_hmac_fn *fn;
    unsigned need;
} fz_engines[] = {
    { jwt_hmac_scalar, 0 },
#ifdef CC_HAVE_NEON
    { jwt_hmac_neon, 0 },
#endif
#if defined(__aarch64__)
    { jwt_hmac_sha2, JWT_CPU_SHA2 },
#endif
#if defined(__x86_64__)
    { jwt_hmac_avx2, JWT_CPU_AVX2 },
    { jwt_hmac_shani_4, JWT_CPU_SHANI },
    { jwt_hmac_avx512, JWT_CPU_AVX512VL },
#endif
};
#define NFE ((int)(sizeof fz_engines / sizeof fz_engines[0]))

static int ref_b64(char *dst, const uint8_t *s, int n) {
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    int o = 0, i = 0;
    for (; i + 2 < n; i += 3) {
        uint32_t v = (uint32_t)s[i] << 16 | (uint32_t)s[i + 1] << 8 | s[i + 2];
        dst[o++] = T[v >> 18], dst[o++] = T[v >> 12 & 63], dst[o++] = T[v >> 6 & 63], dst[o++] = T[v & 63];
    }
    if (n - i == 1) dst[o++] = T[s[i] >> 2], dst[o++] = T[(s[i] & 3) << 4];
    else if (n - i == 2)
        dst[o++] = T[s[i] >> 2], dst[o++] = T[(s[i] & 3) << 4 | s[i + 1] >> 4], dst[o++] = T[(s[i + 1] & 15) << 2];
    return o;
}

/* a time inside [nbf, exp) when the payload's exp (and nbf, if any) are plain integers: 1 and *now, else 0 */
static int live_time(const uint8_t *pl, int n, int64_t *now) {
    jcur_t c = { pl, pl + n };
    const uint8_t *s;
    int len, esc, isint, have_exp = 0, have_nbf = 0;
    int64_t exp = 0, nbf = 0;
    jws(&c);
    if (c.p >= c.e || *c.p++ != '{') return 0;
    for (;;) {
        jws(&c);
        if (!jstr(&c, &s, &len, &esc)) return 0;
        int key = jkey(s, len, esc);
        jws(&c);
        if (c.p >= c.e || *c.p++ != ':') return 0;
        jws(&c);
        if (key == K_EXP || key == K_NBF) {
            if (!jnum(&c, &s, &len, &isint) || !isint) return 0;
            int64_t v = jint(s, len);
            if (key == K_EXP) exp = v, have_exp = 1;
            else nbf = v, have_nbf = 1;
        } else if (!jskip(&c, 1)) {
            return 0;
        }
        jws(&c);
        if (c.p >= c.e) return 0;
        if (*c.p == ',') {
            c.p++;
            continue;
        }
        break;
    }
    /* the verifier compares a now <= 0 by value, a positive one by digits: keep to now >= 1 */
    if (!have_exp || exp <= 1 || (have_nbf && nbf > exp - 1)) return 0;
    *now = exp - 1;
    return 1;
}

enum { MAXN = 33 };
static char outb[MAXN][JWT_TOKEN_MAX + 128], one[JWT_TOKEN_MAX + 128];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 || size > 64 * 1024) return 0;
    uint8_t cfg = data[0];
    const char *pl[MAXN];
    int pn[MAXN], n = 0;
    size_t i = 1;
    while (i <= size && n < MAXN) {
        size_t j = i;
        while (j < size && data[j]) j++;
        pl[n] = (const char *)data + i, pn[n] = (int)(j - i), n++;
        i = j + 1;
    }
    /* the encoder */
    static char e1[96 * 1024], e2[96 * 1024];
    int l1 = jwt_b64url_encode(e1, data, (int)size), l2 = ref_b64(e2, data, (int)size);
    FZ_ASSERT(l1 == l2 && !memcmp(e1, e2, (size_t)l1), "encoder differs from the reference at size %zu", size);
    l1 = jwt_b64url_encode_scalar(e1, data, (int)size);
    FZ_ASSERT(l1 == l2 && !memcmp(e1, e2, (size_t)l1), "scalar encoder differs from the reference at size %zu", size);
    static uint8_t back[64 * 1024 + 64];
    FZ_ASSERT(jwt_b64url_decode_scalar(back, e1, l1) == (int)size && !memcmp(back, data, size), "encode/decode");

    static const uint8_t keyb[100] = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    static const int klen[4] = { 0, 6, 64, 100 };
    jwt_key_t k;
    jwt_key_init(&k, keyb, (size_t)klen[cfg >> 1 & 3]);
    char *op[MAXN];
    int ol[MAXN], ol1;
    for (int t = 0; t < n; t++) op[t] = outb[t];
    int issued = jwt_sign_batch(&k, n, pl, pn, op, ol), cnt = 0;
    for (int t = 0; t < n; t++) {
        char *o1 = one;
        jwt_sign_batch(&k, 1, &pl[t], &pn[t], &o1, &ol1);
        FZ_ASSERT(ol1 == ol[t] && (ol1 < 0 || !strcmp(one, outb[t])), "batch vs single, item %d", t);
        cnt += ol[t] >= 0;
    }
    FZ_ASSERT(cnt == issued, "count");
    unsigned f = jwt_cpu_features();
    for (int e = 0; e < NFE; e++) {
        if ((fz_engines[e].need & f) != fz_engines[e].need) continue;
        static char eb[MAXN][JWT_TOKEN_MAX + 128];
        char *ep[MAXN];
        int el[MAXN];
        for (int t = 0; t < n; t++) ep[t] = eb[t];
        sign_impl(&k, n, pl, pn, ep, el, fz_engines[e].fn);
        for (int t = 0; t < n; t++)
            FZ_ASSERT(el[t] == ol[t] && (el[t] < 0 || !strcmp(eb[t], outb[t])), "engine %d item %d", e, t);
    }
    for (int t = 0; t < n; t++) {
        int64_t now = 1800000000;
        int live = live_time((const uint8_t *)pl[t], pn[t], &now);
        jwt_result_t r;
        if (ol[t] >= 0) {
            const char *tok = outb[t];
            FZ_ASSERT(ol[t] <= JWT_TOKEN_MAX && (int)strlen(tok) == ol[t], "length");
            FZ_ASSERT(!memcmp(tok, canon_hdr, 36) && tok[36] == '.', "header");
            const char *d2 = strrchr(tok, '.');
            int p64 = (int)(d2 - tok - 37);
            FZ_ASSERT(jwt_b64url_decode_scalar(back, tok + 37, p64) == pn[t] && !memcmp(back, pl[t], (size_t)pn[t]),
                      "payload bytes");
            uint8_t tag[64], okv;
            FZ_ASSERT(jwt_b64url_decode_scalar(tag, d2 + 1, 43) == 32, "MAC encoding");
            const uint8_t *mp = (const uint8_t *)tok;
            int ml = (int)(d2 - tok);
            FZ_ASSERT(cc_hmac_sha256_verify(&k, 1, &mp, &ml, (const uint8_t(*)[32])tag, &okv) == 1, "MAC");
            if (live) {
                jwt_verify_batch(&k, 1, &tok, &ol[t], now, &r);
                FZ_ASSERT(r.status != JWT_INVALID, "issued token %d rejected by the verifier at %lld", t,
                          (long long)now);
            }
        } else if (sign_token_len(pn[t], 32) >= 0) {
            /* refused: sign it by hand; the verifier must reject it too */
            char *o = one;
            memcpy(o, canon_hdr, 36), o[36] = '.';
            int L = 37 + jwt_b64url_encode(o + 37, (const uint8_t *)pl[t], pn[t]);
            const uint8_t *mp = (const uint8_t *)o;
            uint8_t mac[32];
            cc_hmac_sha256_bytes(&k, 1, &mp, &L, (uint8_t(*)[32])mac);
            o[L] = '.';
            int tl = L + 1 + jwt_b64url_encode(o + L + 1, mac, 32);
            const char *tp = o;
            jwt_verify_batch(&k, 1, &tp, &tl, now, &r);
            FZ_ASSERT(r.status == JWT_INVALID, "refused payload %d accepted by the verifier (status %d)", t, r.status);
        }
    }
#ifndef JWT_NO_PK
    if (cfg & 1 && n) {
        static jwt_skey_t *sk;
        static jwt_pkey_t *pk;
        if (!sk) {
            uint8_t seed[32], pub[32];
            for (int b = 0; b < 32; b++) seed[b] = (uint8_t)(b * 7 + 3);
            sk = jwt_skey_ed25519(seed);
            jwt_skey_public(sk, pub);
            pk = jwt_pkey_ed25519(pub);
        }
        char *o1 = one;
        jwt_sign_batch_pk(sk, 1, &pl[0], &pn[0], &o1, &ol1);
        FZ_ASSERT((ol1 >= 0) == (ol[0] >= 0), "EdDSA and HS256 disagree on payload 0");
        int64_t now = 1800000000;
        if (ol1 >= 0 && live_time((const uint8_t *)pl[0], pn[0], &now)) {
            jwt_result_t r;
            const char *tp = one;
            jwt_verify_batch_pk(pk, 1, &tp, &ol1, now, &r);
            FZ_ASSERT(r.status != JWT_INVALID, "EdDSA token rejected by the verifier");
        }
    }
    if (cfg & 8 && n) {
        static jwt_skey_t *ek;
        static jwt_pkey_t *epk;
        if (!ek) {
            uint8_t d[32], x[32], y[32];
            for (int b = 0; b < 32; b++) d[b] = (uint8_t)(b * 13 + 1);
            ek = jwt_skey_es256(d);
            jwt_skey_es256_public(ek, x, y);
            epk = jwt_pkey_es256(x, y);
        }
        char *o1 = one;
        jwt_sign_batch_pk(ek, 1, &pl[0], &pn[0], &o1, &ol1);
        FZ_ASSERT((ol1 >= 0) == (ol[0] >= 0), "ES256 and HS256 disagree on payload 0");
        int64_t now = 1800000000;
        if (ol1 >= 0 && live_time((const uint8_t *)pl[0], pn[0], &now)) {
            jwt_result_t r;
            const char *tp = one;
            jwt_verify_batch_pk(epk, 1, &tp, &ol1, now, &r);
            FZ_ASSERT(r.status != JWT_INVALID, "ES256 token rejected by the verifier");
        }
    }
#endif
    return 0;
}
