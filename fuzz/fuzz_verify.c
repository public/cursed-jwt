/* fuzz_verify.c — libFuzzer harness for HS256 verification (unity build: includes jwt.c).
 *
 * Input: one config byte, then tokens separated by '\n' (at most 64).  Config bit 0 re-signs every token with
 * OpenSSL's HMAC under the test secret, so the fuzzer gets past the MAC and into the JSON and claims code; bits 1-3
 * pick `now` around the generated tokens' exp.
 * Oracles (any mismatch aborts):
 *   - every engine, on the whole batch and on each token alone, gives identical results (status, uid, username,
 *     escape flag);
 *   - the shape matcher agrees with the strict parser whenever it answers;
 *   - on JWT_OK: uid >= 1, username_len <= JWT_USERNAME_MAX, ubuf NUL-terminated at username_len;
 *   - ASan / UBSan find nothing.
 * Build: make fuzz (clang with -fsanitize=fuzzer); without libFuzzer, fuzz/replay.c runs a corpus through it. */
#include "jwt.c"

#include "ossl_min.h"
#include <stdio.h>

static const char SECRET[] = "cursed-jwt-test-secret";

typedef void verify_fn(const jwt_key_t *, int, const char *const *, const int *, int64_t, jwt_result_t *);
static const struct {
    verify_fn *fn;
    unsigned need;
} fz_engines[] = {
    { jwt_verify_batch, 0 },
    { jwt_verify_batch_scalar, 0 },
#ifdef CC_HAVE_NEON
    { jwt_verify_batch_neon, 0 },
#endif
#if defined(__aarch64__)
    { jwt_verify_batch_sha2, JWT_CPU_SHA2 },
#endif
#if defined(__x86_64__)
    { jwt_verify_batch_avx2, JWT_CPU_AVX2 },
    { jwt_verify_batch_avx512, JWT_CPU_AVX512VL },
#endif
};
#define NFE ((int)(sizeof fz_engines / sizeof fz_engines[0]))

static int same(const jwt_result_t *a, const jwt_result_t *b) {
    if (a->status != b->status) return 0;
    if (a->status != JWT_OK) return 1;
    return a->uid == b->uid && a->username_len == b->username_len && a->username_escape == b->username_escape &&
           !memcmp(a->ubuf, b->ubuf, a->username_len);
}
#define FZ_ASSERT(c, ...)                                                                                              \
    do {                                                                                                               \
        if (!(c)) {                                                                                                    \
            fprintf(stderr, __VA_ARGS__);                                                                              \
            fputc('\n', stderr);                                                                                       \
            abort();                                                                                                   \
        }                                                                                                              \
    } while (0)

static void b64u_enc(char *dst, const uint8_t *s, int n) {
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    int o = 0, i = 0;
    for (; i + 2 < n; i += 3) {
        uint32_t v = (uint32_t)s[i] << 16 | (uint32_t)s[i + 1] << 8 | s[i + 2];
        dst[o++] = T[v >> 18], dst[o++] = T[v >> 12 & 63], dst[o++] = T[v >> 6 & 63], dst[o++] = T[v & 63];
    }
    if (n - i == 1) {
        uint32_t v = (uint32_t)s[i] << 16;
        dst[o++] = T[v >> 18], dst[o++] = T[v >> 12 & 63];
    } else if (n - i == 2) {
        uint32_t v = (uint32_t)s[i] << 16 | (uint32_t)s[i + 1] << 8;
        dst[o++] = T[v >> 18], dst[o++] = T[v >> 12 & 63], dst[o++] = T[v >> 6 & 63];
    }
    dst[o] = 0;
}

/* the decoded payload of a token, if it has one: the JSON paths are compared on it directly */
static void json_oracle(const char *t, int L, const jnow_t *jn) {
    const char *d1 = memchr(t, '.', L);
    if (!d1) return;
    const char *d2 = memchr(d1 + 1, '.', L - (d1 + 1 - t));
    int pl = (int)((d2 ? d2 : t + L) - d1 - 1);
    static uint8_t pb[JWT_TOKEN_MAX * 3 / 4 + 128];
    int pn = jwt_b64url_decode(pb, d1 + 1, pl);
    if (pn < 0) return;
    memset(pb + pn, 0, 64); /* the slack the real call sites have */
    jwt_result_t rs, rp;
    memset(&rs, 0, sizeof rs), memset(&rp, 0, sizeof rp);
    rs.username = rs.ubuf, rp.username = rp.ubuf;
    rs.status = (uint8_t)payload_check(pb, pn, jn, &rs);
    int sp = payload_shape(pb, pn, jn, &rp);
    if (sp >= 0) {
        rp.status = (uint8_t)sp;
        FZ_ASSERT(same(&rp, &rs), "shape %d vs strict %d on %.*s", sp, rs.status, pn, (const char *)pb);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    enum { MAXT = 64 };
    static jwt_key_t key;
    static int init;
    if (!init) jwt_key_init(&key, SECRET, sizeof SECRET - 1), init = 1;
    if (size < 1 || size > 64 * 1024) return 0;
    uint8_t cfg = data[0];
    int64_t now = 1800000000 + (int64_t)((cfg >> 1) & 7) * 1800 - 3600;
    static char store[MAXT][JWT_TOKEN_MAX + 200];
    const char *tok[MAXT];
    int len[MAXT], n = 0;
    const uint8_t *p = data + 1, *e = data + size;
    while (p <= e && n < MAXT) {
        const uint8_t *nl = memchr(p, '\n', (size_t)(e - p));
        if (!nl) nl = e;
        int L = (int)(nl - p);
        if (L > JWT_TOKEN_MAX + 100) L = JWT_TOKEN_MAX + 100;
        memcpy(store[n], p, (size_t)L);
        if (cfg & 1) { /* re-sign: keep header.payload, replace the signature with a valid one */
            const char *d1 = memchr(store[n], '.', (size_t)L);
            const char *d2 = d1 ? memchr(d1 + 1, '.', (size_t)(L - (d1 + 1 - store[n]))) : NULL;
            int si = d2 ? (int)(d2 - store[n]) : L;
            if (si + 1 + 43 <= JWT_TOKEN_MAX + 100) {
                uint8_t mac[32];
                unsigned ml = 32;
                HMAC(EVP_sha256(), SECRET, (int)sizeof SECRET - 1, (const uint8_t *)store[n], (size_t)si, mac, &ml);
                store[n][si] = '.';
                b64u_enc(store[n] + si + 1, mac, 32);
                L = si + 1 + 43;
            }
        }
        if (L < 0) L = 0; /* cannot happen; tells gcc's -Warray-bounds so */
        memset(store[n] + L, 0, 64);
        tok[n] = store[n], len[n] = L, n++;
        p = nl + 1;
    }
    jnow_t jn;
    jnow_init(&jn, now);
    static jwt_result_t ref[MAXT], got[MAXT];
    jwt_verify_batch_scalar(&key, 1, tok, len, now, ref); /* token 0 alone, scalar: the reference */
    for (int i = 1; i < n; i++) jwt_verify_batch_scalar(&key, 1, tok + i, len + i, now, ref + i);
    for (int i = 0; i < n; i++) {
        if (ref[i].status == JWT_OK) {
            FZ_ASSERT(ref[i].uid >= 1 && ref[i].username_len <= JWT_USERNAME_MAX &&
                          ref[i].ubuf[ref[i].username_len] == 0,
                      "bad JWT_OK result for %.*s", len[i], tok[i]);
            FZ_ASSERT(ref[i].username == ref[i].ubuf, "username does not point into ubuf");
        }
        json_oracle(tok[i], len[i], &jn);
    }
    for (int e2 = 0; e2 < NFE; e2++) {
        if ((fz_engines[e2].need & jwt_cpu_features()) != fz_engines[e2].need) continue;
        fz_engines[e2].fn(&key, n, tok, len, now, got);
        for (int i = 0; i < n; i++)
            FZ_ASSERT(same(&got[i], &ref[i]), "engine %d batch %d token %d: %d vs %d on %.*s", e2, n, i, got[i].status,
                      ref[i].status, len[i], tok[i]);
    }
    return 0;
}
