/* test_jwt.c — every engine vs OpenSSL HMAC, plus the claim rules.  Unity build: includes jwt.c.
 *   ./test_jwt [tokens.json [hmac_vectors.txt]]   (make test / make test-vectors build both)
 */
#include "jwt.c"

#include "ossl_min.h"
#include <stdio.h>
#include <time.h>

static const char *SECRET = "cursed-jwt-test-secret"; /* must match the Makefile's token generation */
static int fails, checks;
static int quick; /* JWT_TEST_QUICK=1: fewer random iterations, same token/crafted coverage */
#define CHECK(cond, ...)                                                                                               \
    do {                                                                                                               \
        checks++;                                                                                                      \
        if (!(cond)) {                                                                                                 \
            fails++;                                                                                                   \
            if (fails < 40)                                                                                            \
                fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__), fprintf(stderr, __VA_ARGS__),                     \
                    fputc('\n', stderr);                                                                               \
        }                                                                                                              \
    } while (0)

/* ---- the AVX-512 template, executed with a scalar emulation of vpternlogd/vprord ---- */
static inline uint32_t tl_emu(uint32_t a, uint32_t b, uint32_t c, int imm) {
    uint32_t r = 0;
    for (int i = 0; i < 32; i++) {
        int idx = (int)((a >> i & 1) << 2 | (b >> i & 1) << 1 | (c >> i & 1));
        r |= (uint32_t)(imm >> idx & 1) << i;
    }
    return r;
}
#define MB(name)       name##_tlemu
#define MB_LANES       1
#define V              uint32_t
#define VSET1(x)       ((uint32_t)(x))
#define VADD(a, b)     ((a) + (b))
#define VXOR(a, b)     ((a) ^ (b))
#define VSHR(x, n)     ((x) >> (n))
#define VROR(x, n)     ROR32(x, n)
#define VXOR3(a, b, c) tl_emu(a, b, c, JWT_TL_XOR3)
#define VCH(e, f, g)   tl_emu(e, f, g, JWT_TL_CH)
#define VMAJ(a, b, c)  tl_emu(a, b, c, JWT_TL_MAJ)
#define VSEL(m, x, y)  tl_emu(m, x, y, JWT_TL_CH)
#define VMASK(arr)     ((arr)[0])
#define MB_LOAD16(ptr, w)                                                                                              \
    do {                                                                                                               \
        for (int i_ = 0; i_ < 16; i_++) (w)[i_] = be32((ptr)[0] + 4 * i_);                                             \
    } while (0)
#define MB_STORE8(s, out)                                                                                              \
    do {                                                                                                               \
        for (int i_ = 0; i_ < 8; i_++) (out)[0][i_] = (s)[i_];                                                         \
    } while (0)
#define MB_MIN_LANES 1
#include "jwt_mb.inc"

/* ---- helpers ---- */
static void ossl_hmac(const uint8_t *m, int n, uint32_t out[8]) {
    uint8_t d[32];
    unsigned dl = 32;
    HMAC(EVP_sha256(), SECRET, (int)strlen(SECRET), m, (size_t)n, d, &dl);
    for (int i = 0; i < 8; i++) out[i] = be32(d + 4 * i);
}

static const char B64U[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static int b64u_enc(char *dst, const uint8_t *s, int n) {
    int o = 0, i = 0;
    for (; i + 3 <= n; i += 3) {
        uint32_t v = (uint32_t)s[i] << 16 | (uint32_t)s[i + 1] << 8 | s[i + 2];
        dst[o++] = B64U[v >> 18], dst[o++] = B64U[v >> 12 & 63], dst[o++] = B64U[v >> 6 & 63], dst[o++] = B64U[v & 63];
    }
    if (n - i == 1) {
        uint32_t v = (uint32_t)s[i] << 16;
        dst[o++] = B64U[v >> 18], dst[o++] = B64U[v >> 12 & 63];
    } else if (n - i == 2) {
        uint32_t v = (uint32_t)s[i] << 16 | (uint32_t)s[i + 1] << 8;
        dst[o++] = B64U[v >> 18], dst[o++] = B64U[v >> 12 & 63], dst[o++] = B64U[v >> 6 & 63];
    }
    dst[o] = 0;
    return o;
}

/* sign(header, payload) with SECRET (or a different key) -> malloc'd token */
static char *sign_with(const char *hdr, const char *pl, const char *key) {
    size_t hl = strlen(hdr), pll = strlen(pl);
    char *t = malloc((hl + pll) * 2 + 128);
    int o = b64u_enc(t, (const uint8_t *)hdr, (int)hl);
    t[o++] = '.';
    o += b64u_enc(t + o, (const uint8_t *)pl, (int)pll);
    uint8_t d[32];
    unsigned dl = 32;
    HMAC(EVP_sha256(), key, (int)strlen(key), (uint8_t *)t, (size_t)o, d, &dl);
    t[o++] = '.';
    b64u_enc(t + o, d, 32);
    return t;
}
static const char *HS = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
static char *sign(const char *pl) { return sign_with(HS, pl, SECRET); }

static char *fmt(const char *f, ...) __attribute__((format(printf, 1, 2)));
static char *fmt(const char *f, ...) {
    va_list ap;
    va_start(ap, f);
    char *s = NULL;
    if (vasprintf(&s, f, ap) < 0) abort();
    va_end(ap);
    return s;
}

#if defined(JWT_OSSL_SHA256) && defined(__x86_64__) && defined(__ELF__)
/* OpenSSL's extracted block function dispatches on jwt_ossl_ia32cap_P: run each path the CPU has, by masking the
 * capability word to that path's bits (shaext only where SHA-NI exists; otherwise it falls through to the next). */
#define OSSL_PATH(fn, m0, m1, m2)                                                                                      \
    static void fn(const jwt_key_t *k, int n, const uint8_t *const *msg, const int *len, uint32_t(*mac)[8]) {          \
        unsigned sv[4];                                                                                                \
        memcpy(sv, jwt_ossl_ia32cap_P, sizeof sv);                                                                     \
        jwt_ossl_ia32cap_P[0] &= (m0), jwt_ossl_ia32cap_P[1] &= (m1), jwt_ossl_ia32cap_P[2] &= (m2);                   \
        jwt_hmac_ossl(k, n, msg, len, mac);                                                                            \
        memcpy(jwt_ossl_ia32cap_P, sv, sizeof sv);                                                                     \
    }
OSSL_PATH(hmac_ossl_shaext, ~0u, ~0u, 1u << 29)
OSSL_PATH(hmac_ossl_avx2, ~0u, ~0u, 1u << 8 | 1u << 5 | 1u << 3)
OSSL_PATH(hmac_ossl_avx, 1u << 30, 1u << 28 | 1u << 9, 0)
OSSL_PATH(hmac_ossl_ssse3, 0, 1u << 9, 0)
OSSL_PATH(hmac_ossl_x86, 0, 0, 0)
#endif

typedef struct {
    const char *name;
    jwt_hmac_fn *hmac;
    void (*verify)(const jwt_key_t *, int, const char *const *, const int *, int64_t, jwt_result_t *);
    unsigned need; /* JWT_CPU_* bits the engine needs; engines the CPU lacks are skipped (and listed) */
} engine_t;

static const engine_t all_engines[] = {
    { "scalar", jwt_hmac_scalar, jwt_verify_batch_scalar, 0 },
#ifdef JWT_HAVE_NEON
    { "neon4", jwt_hmac_neon, jwt_verify_batch_neon, 0 },
#endif
#if defined(__aarch64__)
    { "sha2x1", jwt_hmac_sha2_1, NULL, JWT_CPU_SHA2 },
    { "sha2(default)", jwt_hmac_sha2, jwt_verify_batch_sha2, JWT_CPU_SHA2 },
    { "sha2x2", jwt_hmac_sha2_2, NULL, JWT_CPU_SHA2 },
#endif
#if defined(__x86_64__)
    { "shani1", jwt_hmac_shani_1, NULL, JWT_CPU_SHANI },
    { "shani2", jwt_hmac_shani_2, NULL, JWT_CPU_SHANI },
    { "shani4", jwt_hmac_shani_4, NULL, JWT_CPU_SHANI },
    { "avx2", jwt_hmac_avx2, jwt_verify_batch_avx2, JWT_CPU_AVX2 },
    { "avx2x2", jwt_hmac_avx2x2, NULL, JWT_CPU_AVX2 },
    { "avx512", jwt_hmac_avx512, jwt_verify_batch_avx512, JWT_CPU_AVX512VL },
    { "avx512x2", jwt_hmac_avx512x2, NULL, JWT_CPU_AVX512VL },
    { "zmm", jwt_hmac_zmm, NULL, JWT_CPU_AVX512VL },
#endif
#if defined(JWT_OSSL_SHA256) && defined(__x86_64__) && defined(__ELF__)
    { "ossl", jwt_hmac_ossl, NULL, 0 },
    { "ossl-shaext", hmac_ossl_shaext, NULL, 0 },
    { "ossl-avx2", hmac_ossl_avx2, NULL, 0 },
    { "ossl-avx", hmac_ossl_avx, NULL, 0 },
    { "ossl-ssse3", hmac_ossl_ssse3, NULL, 0 },
    { "ossl-x86", hmac_ossl_x86, NULL, 0 },
#endif
    { "tlemu", jwt_hmac_tlemu, NULL, 0 },
    { "default", NULL, jwt_verify_batch, 0 },
};
static engine_t engines[sizeof all_engines / sizeof all_engines[0]];
static int NENG;
static void pick_engines(void) {
    unsigned f = jwt_cpu_features();
    printf("cpu features 0x%x, default engine %s; skipped (CPU lacks them):", f, jwt_engine());
    for (size_t i = 0; i < sizeof all_engines / sizeof all_engines[0]; i++) {
        if ((all_engines[i].need & f) == all_engines[i].need) engines[NENG++] = all_engines[i];
        else printf(" %s", all_engines[i].name);
    }
    printf("\n");
}

/* ---- tokens.json ---- */
typedef struct {
    int id;
    char *name, *tok;
} seedtok_t;
static seedtok_t *load_tokens(const char *path, int *count) {
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
    fclose(f);
    int cap = 1024, n = 0;
    seedtok_t *v = malloc(cap * sizeof *v);
    for (char *p = buf; (p = strstr(p, "{\"id\":"));) {
        if (n == cap) v = realloc(v, (cap *= 2) * sizeof *v);
        v[n].id = atoi(p + 6);
        char *u = strstr(p, "\"username\":\"") + 12, *ue = strchr(u, '"');
        char *t = strstr(p, "\"token\":\"") + 9, *te = strchr(t, '"');
        v[n].name = strndup(u, ue - u), v[n].tok = calloc(te - t + 65, 1), memcpy(v[n].tok, t, te - t);
        n++, p = te;
    }
    *count = n;
    return v;
}

static uint64_t rng = 0x9E3779B97F4A7C15ull;
static uint32_t rnd(void) {
    rng ^= rng << 13, rng ^= rng >> 7, rng ^= rng << 17;
    return (uint32_t)(rng >> 16);
}

/* ---- tests ---- */
static void test_ternlog_immediates(void) {
    for (int i = 0; i < 1000; i++) {
        uint32_t a = rnd() ^ rnd() << 16, b = rnd() ^ rnd() << 16, c = rnd() ^ rnd() << 16;
        CHECK(tl_emu(a, b, c, JWT_TL_XOR3) == (a ^ b ^ c), "xor3");
        CHECK(tl_emu(a, b, c, JWT_TL_CH) == ((a & b) | (~a & c)), "ch");
        CHECK(tl_emu(a, b, c, JWT_TL_MAJ) == ((a & b) ^ (a & c) ^ (b & c)), "maj");
    }
}

static void test_jint(void) {
    char b[32];
    for (int it = 0; it < (quick ? 20000 : 200000); it++) {
        int digits = 1 + (int)(rnd() % 18);
        uint64_t v = ((uint64_t)rnd() << 32 | rnd() << 16 | rnd()) % 1000000000000000000ull;
        uint64_t p = 1;
        for (int i = 0; i < digits; i++) p *= 10;
        v %= p;
        int neg = rnd() & 1;
        int n = snprintf(b, sizeof b, "%s%llu", neg ? "-" : "", (unsigned long long)v);
        CHECK(jint((const uint8_t *)b, n) == (neg ? -(int64_t)v : (int64_t)v), "jint %s", b);
    }
}

static void test_b64(void) {
    uint8_t a[600], b[600];
    char s[600];
    for (int it = 0; it < (quick ? 3000 : 20000); it++) {
        int n = (int)(rnd() % 300);
        for (int i = 0; i < n; i++) s[i] = B64U[rnd() & 63];
        int mode = (int)(rnd() % 4);
        if (mode == 1 && n) s[rnd() % n] = (char)(rnd() & 255); /* random garbage byte */
        if (mode == 2 && n) s[rnd() % n] = "=+/. \x80\xff"[rnd() % 7];
        int ra = jwt_b64url_decode_scalar(a, s, n), rb = jwt_b64url_decode(b, s, n);
        CHECK(ra == rb && (ra < 0 || !memcmp(a, b, ra)), "b64 simd/scalar mismatch n=%d ra=%d rb=%d", n, ra, rb);
        if (mode == 0) CHECK((n & 3) == 1 ? ra < 0 : (ra >= 0 || (n & 3)), "b64 valid rejected n=%d", n);
    }
    /* round trip */
    for (int n = 0; n < 200; n++) {
        uint8_t in[200];
        for (int i = 0; i < n; i++) in[i] = (uint8_t)rnd();
        int m = b64u_enc(s, in, n);
        CHECK(jwt_b64url_decode(a, s, m) == n && !memcmp(a, in, n), "b64 roundtrip %d", n);
    }
    CHECK(jwt_b64url_decode(a, "QQ", 2) == 1 && a[0] == 'A', "QQ");
    CHECK(jwt_b64url_decode(a, "QR", 2) < 0, "non-canonical QR");
    CHECK(jwt_b64url_decode(a, "QUI", 3) == 2, "QUI");
    CHECK(jwt_b64url_decode(a, "QUJ", 3) < 0, "non-canonical QUJ");
    CHECK(jwt_b64url_decode(a, "QQ==", 4) < 0, "padding");
}

static void test_hmac_random(void) {
    enum { MAXN = 70 };
    static uint8_t data[MAXN + 1][768]; /* row slack: JWT_INPUT_PADDED reads up to 64 B past a message */
    const uint8_t *msg[MAXN];
    int len[MAXN];
    uint32_t ref[MAXN][8], got[MAXN][8];
    jwt_key_t k;
    jwt_key_init(&k, SECRET, strlen(SECRET));
    for (int it = 0; it < (quick ? 400 : 3000); it++) {
        int n = 1 + (int)(rnd() % MAXN);
        int mode = (int)(rnd() % 3); /* 0: uniform-ish token lengths, 1: wild, 2: block boundaries */
        for (int i = 0; i < n; i++) {
            len[i] = mode == 0   ? 130 + (int)(rnd() % 60)
                     : mode == 1 ? (int)(rnd() % 700)
                                 : 64 * (int)(rnd() % 5) + (int)(rnd() % 3) - 1 + 55 - 55 * (int)(rnd() & 1);
            if (len[i] < 0) len[i] = 0;
            if (len[i] > 699) len[i] = 699;
            for (int j = 0; j < len[i]; j++) data[i][j] = (uint8_t)rnd();
            msg[i] = data[i];
            ossl_hmac(msg[i], len[i], ref[i]);
        }
        for (int e = 0; e < NENG; e++) {
            if (!engines[e].hmac) continue;
            memset(got, 0, sizeof got);
            engines[e].hmac(&k, n, msg, len, got);
            for (int i = 0; i < n; i++)
                CHECK(!memcmp(ref[i], got[i], 32), "hmac %s it=%d n=%d i=%d len=%d", engines[e].name, it, n, i, len[i]);
        }
    }
    /* long keys get hashed (RFC 2104) */
    const char *lk = "a-secret-that-is-definitely-longer-than-sixty-four-bytes-0123456789-abcdefghijklmnop";
    jwt_key_t k2;
    jwt_key_init(&k2, lk, strlen(lk));
    uint8_t d[32];
    unsigned dl;
    static const uint8_t hello[80] = "hello";
    const uint8_t *m0 = hello;
    int l0 = 5;
    HMAC(EVP_sha256(), lk, (int)strlen(lk), m0, 5, d, &dl);
    jwt_hmac_scalar(&k2, 1, &m0, &l0, got);
    for (int i = 0; i < 8; i++) ref[0][i] = be32(d + 4 * i);
    CHECK(!memcmp(ref[0], got[0], 32), "long key");
}


/* plain SHA-256 (the RS256 / ES256 signing-input hash) on every engine vs OpenSSL, random batches of 1-40 messages
 * of 0-1,100 bytes with block boundaries over-represented, so ragged groups and leftover single streams both run */
static void test_sha256_raw(void) {
    static const struct {
        const char *name;
        jwt_sha256_fn *fn;
        unsigned need;
    } se[] = {
        { "scalar", jwt_sha256_scalar, 0 },
        { "default", jwt_sha256_batch, 0 },
#ifdef JWT_HAVE_NEON
        { "neon4", jwt_sha256_neon, 0 },
#endif
#if defined(__aarch64__)
        { "sha2x4", jwt_sha256_sha2, JWT_CPU_SHA2 },
#endif
#if defined(__x86_64__)
        { "avx2", jwt_sha256_avx2, JWT_CPU_AVX2 },
        { "avx512", jwt_sha256_avx512, JWT_CPU_AVX512VL },
#endif
    };
    static uint8_t data[40][1100 + 64];
    const uint8_t *msg[40];
    int len[40], nmsg = 0;
    uint32_t got[40][8];
    for (int it = 0; it < (quick ? 300 : 3000); it++) {
        int n = 1 + (int)(rnd() % 40);
        for (int i = 0; i < n; i++) {
            len[i] =
                rnd() & 1 ? (int)(rnd() % 1101) : 64 * (int)(rnd() % 6) + (int)(rnd() % 3) - 1 + 55 * (int)(rnd() & 1);
            if (len[i] < 0) len[i] = 0;
            if (len[i] > 1100) len[i] = 1100;
            for (int j = 0; j < len[i]; j++) data[i][j] = (uint8_t)rnd();
            msg[i] = data[i];
        }
        for (int e = 0; e < (int)(sizeof se / sizeof se[0]); e++) {
            if ((se[e].need & jwt_cpu_features()) != se[e].need) continue;
            se[e].fn(n, msg, len, got);
            for (int i = 0; i < n; i++) {
                uint8_t d[32];
                SHA256_CTX c;
                SHA256_Init(&c), SHA256_Update(&c, msg[i], (size_t)len[i]), SHA256_Final(d, &c);
                int ok = 1;
                for (int j = 0; j < 8; j++) ok &= got[i][j] == be32(d + 4 * j);
                CHECK(ok, "sha256 %s n=%d i=%d len=%d", se[e].name, n, i, len[i]);
            }
        }
        nmsg += n;
    }
    printf("  plain SHA-256 (RS256/ES256 signing inputs): %d messages x %d engines vs OpenSSL\n", nmsg,
           (int)(sizeof se / sizeof se[0]));
}

/* shape matcher vs the strict parser on fuzzed payloads: whenever the matcher answers (>= 0) it must agree with
 * payload_check exactly. */
static void test_json_diff(int64_t now) {
    static const char *base[] = {
        "{\"sub\":\"1\",\"username\":\"golden_ember_1\",\"iat\":1792832174,\"exp\":2108192174}",
        "{\"sub\":\"20000\",\"username\":\"swift_nebula_20000\",\"iat\":1792832174,\"exp\":2108192174}",
        "{\"exp\":2108192174.5,\"nbf\":100,\"username\":\"a b\",\"sub\":\"007\",\"x\":true,\"y\":null,\"z\":false}",
        " {\"sub\" : \"9223372036854775807\" ,\"username\":\"\", \"exp\" : 4.1e9 } ",
        "{\"sub\":\"1\",\"username\":\"n\",\"exp\":1}",
        "{\"sub\":1,\"username\":\"n\",\"exp\":2108192174}",
        "{\"sub\":\"1\",\"username\":0,\"exp\":2108192174}",
        "{\"sub\":\"1\",\"username\":\"n\",\"exp\":2108192174,\"a\":[1,2],\"b\":{\"c\":1}}",
    };
    static const char alpha[] = "{}[]:,\"\\ \t\n\r0123456789-+.eEtrufalsn_abcxyz\x01\x7f\xc3\xa9";
    uint8_t a[400], b[400];
    int total = 0, shaped = 0;
    jnow_t jn;
    jnow_init(&jn, now);
    for (int it = 0; it < (quick ? 30000 : 300000); it++) {
        const char *src = base[rnd() % (sizeof base / sizeof *base)];
        int n = (int)strlen(src);
        memcpy(a, src, n);
        int muts = (int)(rnd() % 4);
        for (int m = 0; m < muts; m++) {
            int op = (int)(rnd() % 3), pos = n ? (int)(rnd() % (n + 1)) : 0;
            char ch = alpha[rnd() % (sizeof alpha - 1)];
            if (op == 0 && n < 300) memmove(a + pos + 1, a + pos, n - pos), a[pos] = (uint8_t)ch, n++;
            else if (op == 1 && pos < n) memmove(a + pos, a + pos + 1, n - pos - 1), n--;
            else if (pos < n) a[pos] = (uint8_t)ch;
        }
        memcpy(b, a, n);
        jwt_result_t rs;
        memset(&rs, 0, sizeof rs);
        int ss = payload_check(b, n, &jn, &rs);
        jwt_result_t rp;
        memset(&rp, 0, sizeof rp);
        int sp = payload_shape(a, n, &jn, &rp);
        total++;
        if (sp >= 0) {
            shaped++;
            int okp = sp == ss;
            if (okp && sp == JWT_OK)
                okp = rp.uid == rs.uid && rp.username_len == rs.username_len &&
                      !memcmp(rp.ubuf, rs.ubuf, rp.username_len) && rp.username_escape == rs.username_escape;
            CHECK(okp, "json diff: shape %d strict %d on '%.*s'", sp, ss, n, (const char *)b);
        }
    }
    printf("  json shape matcher: decided %d of %d fuzzed payloads, all agreed with the strict parser\n", shaped,
           total);
    CHECK(shaped > total / 20, "shape matcher decided too few (%d/%d)", shaped, total);
}


static void test_seed(seedtok_t *t, int n, int64_t now) {
    jwt_key_t k;
    jwt_key_init(&k, SECRET, strlen(SECRET));
    const char **tok = malloc(n * sizeof *tok);
    const uint8_t **msg = malloc(n * sizeof *msg);
    int *len = malloc(n * sizeof *len), *mlen = malloc(n * sizeof *mlen);
    uint32_t(*ref)[8] = malloc(n * sizeof *ref), (*got)[8] = malloc(n * sizeof *got);
    jwt_result_t *res = malloc(n * sizeof *res);
    for (int i = 0; i < n; i++) {
        tok[i] = t[i].tok, len[i] = (int)strlen(t[i].tok);
        msg[i] = (const uint8_t *)t[i].tok, mlen[i] = (int)(strrchr(t[i].tok, '.') - t[i].tok);
        ossl_hmac(msg[i], mlen[i], ref[i]);
    }
    for (int e = 0; e < NENG; e++) {
        if (engines[e].hmac) {
            engines[e].hmac(&k, n, msg, mlen, got);
            int bad = 0;
            for (int i = 0; i < n; i++) bad += memcmp(ref[i], got[i], 32) != 0;
            CHECK(bad == 0, "seed hmac %s: %d/%d mismatches", engines[e].name, bad, n);
        }
        if (!engines[e].verify) continue;
        static const int bs[] = { 1, 8, 32, 3, 4, 16, 64, 100 };
        for (int b = 0; b < (quick ? 3 : (int)(sizeof bs / sizeof bs[0])); b++) {
            int bad = 0;
            memset(res, 0xA5, n * sizeof *res);
            for (int i = 0; i < n; i += bs[b]) {
                int m = n - i < bs[b] ? n - i : bs[b];
                engines[e].verify(&k, m, tok + i, len + i, now, res + i);
            }
            for (int i = 0; i < n; i++) {
                jwt_result_t *r = &res[i];
                int ok = r->status == JWT_OK && r->uid == t[i].id && r->username == r->ubuf &&
                         r->username_len == strlen(t[i].name) && !memcmp(r->username, t[i].name, r->username_len) &&
                         r->username_escape == 0 && r->username[r->username_len] == 0;
                bad += !ok;
            }
            CHECK(bad == 0, "seed verify %s batch=%d: %d/%d wrong", engines[e].name, bs[b], bad, n);
        }
    }
    free(tok), free(msg), free(len), free(mlen), free(ref), free(got), free(res);
}

typedef struct {
    char *tok;
    int status;
    int64_t uid;
    const char *name; /* expected decoded username for OK */
    int esc;
    const char *what;
} case_t;

static void test_cases(int64_t now) {
    case_t c[256];
    int n = 0;
#define ADD(t, st, u, nm, e, w) (c[n++] = (case_t){ (t), (st), (u), (nm), (e), (w) })
#define OKC(pl, u, nm, e)       ADD(sign(pl), JWT_OK, u, nm, e, pl)
#define BAD(pl)                 ADD(sign(pl), JWT_INVALID, 0, NULL, 0, pl)
#define BADP(pl)                ADD(sign(pl), JWT_BAD_PAYLOAD, 0, NULL, 0, pl)
    long long fut = now + 3600, past = now - 3600;
    char *good = sign(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"iat\":%lld,\"exp\":%lld}", (long long)now, fut));
    ADD(good, JWT_OK, 7, "bob", 0, "good");
    /* typical API test-suite cases */
    ADD(strdup("abc"), JWT_INVALID, 0, NULL, 0, "garbage");
    {
        char *t = strdup(good);
        char *d = strrchr(t, '.');
        d[1] = 0;
        ADD(fmt("%s%s", t, "c2lnbmF0dXJlLWlzLW5vdC12YWxpZC1hdC1hbGwtYXQtYWxsLTEyMzQ"), JWT_INVALID, 0, NULL, 0,
            "bad signature");
        char hb[64];
        b64u_enc(hb, (const uint8_t *)"{\"alg\":\"none\",\"typ\":\"JWT\"}", 26);
        char *p1 = strchr(good, '.') + 1, *p2 = strrchr(good, '.');
        ADD(fmt("%s.%.*s.", hb, (int)(p2 - p1), p1), JWT_INVALID, 0, NULL, 0, "alg=none");
        /* alg=none, signature copied from the good token */
        ADD(fmt("%s.%.*s%s", hb, (int)(p2 - p1), p1, p2), JWT_INVALID, 0, NULL, 0, "alg=none, real sig");
        free(t);
    }
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"iat\":%lld,\"exp\":%lld}", past - 3600, past));
    BADP(fmt("{\"sub\":\"abc\",\"username\":\"bob\",\"iat\":%lld,\"exp\":%lld}", (long long)now, fut));
    BADP(fmt("{\"sub\":\"7\",\"iat\":%lld,\"exp\":%lld}", (long long)now, fut));
    /* sub variants, as other implementations' test suites check them */
    const char *subs[] = { "0",    "1",      "true",   "\"0\"",  "\"-1\"", "\"1.5\"", "\"abc\"",
                           "null", "\"\"",   "\" 1\"", "\"1 \"", "\"+1\"", "\"1e3\"", "\"9223372036854775808\"",
                           "{}",   "[\"1\"]" };
    for (int i = 0; i < (int)(sizeof subs / sizeof *subs); i++)
        BADP(fmt("{\"sub\":%s,\"username\":\"bob\",\"exp\":%lld}", subs[i], fut));
    OKC(fmt("{\"sub\":\"9223372036854775807\",\"username\":\"bob\",\"exp\":%lld}", fut), INT64_MAX, "bob", 0);
    OKC(fmt("{\"sub\":\"007\",\"username\":\"bob\",\"exp\":%lld}", fut), 7, "bob", 0);
    OKC(fmt("{\"sub\":\"\\u0031\\u0032\",\"username\":\"bob\",\"exp\":%lld}", fut), 12, "bob", 0);
    const char *names[] = { "0", "true", "null", "{}", "[]", "false", "1.5" };
    for (int i = 0; i < (int)(sizeof names / sizeof *names); i++)
        BADP(fmt("{\"sub\":\"7\",\"username\":%s,\"exp\":%lld}", names[i], fut));
    /* time claims */
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bob\"}"));
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"exp\":0}"));
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"exp\":\"3000000000\"}"));
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"exp\":null}"));
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"exp\":true}"));
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"exp\":[%lld]}", fut));
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"exp\":%lld}", (long long)now));
    OKC(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"exp\":%lld}", (long long)now + 1), 7, "bob", 0);
    OKC(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"exp\":%lld.25}", (long long)now), 7, "bob", 0);
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"exp\":%lld.75}", (long long)now - 1));
    OKC(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"exp\":%.6f}", (double)fut + 0.123456), 7, "bob", 0);
    OKC(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"exp\":4.1e9}"), 7, "bob", 0);
    OKC(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"exp\":99999999999999999999999}"), 7, "bob", 0);
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"exp\":-99999999999999999999999}"));
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"exp\":1e3}"));
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"exp\":%lld,\"nbf\":%lld}", fut, fut));
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"exp\":%lld,\"nbf\":\"bad\"}", fut));
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"exp\":%lld,\"nbf\":null}", fut));
    OKC(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"exp\":%lld,\"nbf\":%lld}", fut, (long long)now), 7, "bob", 0);
    OKC(fmt("{\"nbf\":%lld,\"exp\":%lld,\"username\":\"bob\",\"sub\":\"7\"}", past, fut), 7, "bob", 0);
    /* expired beats bad payload */
    BAD(fmt("{\"sub\":\"abc\",\"exp\":%lld}", past));
    /* iat and unknown claims are ignored but must be valid JSON */
    OKC(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"iat\":\"whenever\",\"x\":[1,{\"a\":[]},\"\\n\"],\"exp\":%lld}", fut),
        7, "bob", 0);
    /* duplicates and escaped keys */
    BAD(fmt("{\"sub\":\"7\",\"sub\":\"8\",\"username\":\"bob\",\"exp\":%lld}", fut));
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"username\":\"eve\",\"exp\":%lld}", fut));
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"exp\":%lld,\"exp\":%lld}", fut, fut));
    BAD(fmt("{\"sub\":\"7\",\"\\u0073ub\":\"8\",\"username\":\"bob\",\"exp\":%lld}", fut));
    OKC(fmt("{\"\\u0073ub\":\"8\",\"user\\u006eame\":\"bob\",\"\\u0065xp\":%lld}", fut), 8, "bob", 0);
    /* usernames */
    OKC(fmt("{\"sub\":\"7\",\"username\":\"\",\"exp\":%lld}", fut), 7, "", 0);
    OKC(fmt("{\"sub\":\"7\",\"username\":\"a\\\"b\",\"exp\":%lld}", fut), 7, "a\"b", 1);
    OKC(fmt("{\"sub\":\"7\",\"username\":\"a\\\\b\",\"exp\":%lld}", fut), 7, "a\\b", 1);
    OKC(fmt("{\"sub\":\"7\",\"username\":\"tab\\there\",\"exp\":%lld}", fut), 7, "tab\there", 1);
    OKC(fmt("{\"sub\":\"7\",\"username\":\"sl\\/ash\",\"exp\":%lld}", fut), 7, "sl/ash", 0);
    OKC(fmt("{\"sub\":\"7\",\"username\":\"caf\\u00e9\",\"exp\":%lld}", fut), 7, "caf\xc3\xa9", 0);
    OKC(fmt("{\"sub\":\"7\",\"username\":\"caf\xc3\xa9 \xf0\x9f\x92\xa9\",\"exp\":%lld}", fut), 7,
        "caf\xc3\xa9 \xf0\x9f\x92\xa9", 0);
    OKC(fmt("{\"sub\":\"7\",\"username\":\"\\ud83d\\udca9\",\"exp\":%lld}", fut), 7, "\xf0\x9f\x92\xa9", 0);
    OKC(fmt("{\"sub\":\"7\",\"username\":\"x\\ud83dy\",\"exp\":%lld}", fut), 7, "x\xef\xbf\xbdy", 0);
    OKC(fmt("{\"sub\":\"7\",\"username\":\"nul\\u0000\",\"exp\":%lld}", fut), 7, "nul", 1); /* len checked below */
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bad\xc3\",\"exp\":%lld}", fut));                 /* truncated UTF-8 */
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bad\xc0\xaf\",\"exp\":%lld}", fut));             /* overlong */
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bad\xed\xa0\x80\",\"exp\":%lld}", fut));         /* raw surrogate */
    BAD(fmt("{\"sub\":\"7\",\"username\":\"ctl\x01\",\"exp\":%lld}", fut));
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bad\\x\",\"exp\":%lld}", fut));
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bad\\u12\",\"exp\":%lld}", fut));
    {
        char longname[400];
        memset(longname, 'n', sizeof longname - 1), longname[sizeof longname - 1] = 0;
        BADP(fmt("{\"sub\":\"7\",\"username\":\"%s\",\"exp\":%lld}", longname, fut));
        longname[JWT_USERNAME_MAX] = 0;
        OKC(fmt("{\"sub\":\"7\",\"username\":\"%s\",\"exp\":%lld}", longname, fut), 7, strdup(longname), 0);
        /* big payload: many blocks, mixed into a batch with short tokens */
        char *pad = malloc(3001);
        memset(pad, 'p', 3000), pad[3000] = 0;
        OKC(fmt("{\"sub\":\"7\",\"pad\":\"%s\",\"username\":\"bob\",\"exp\":%lld}", pad, fut), 7, "bob", 0);
        free(pad);
    }
    /* malformed JSON */
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"exp\":%lld,}", fut));
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"exp\":%lld}x", fut));
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"exp\":%lld", fut));
    BAD(fmt("[\"sub\",\"7\"]"));
    BAD(fmt("\"just a string\""));
    BAD(fmt("{\"sub\":\"7\" \"username\":\"bob\",\"exp\":%lld}", fut));
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"exp\":0%lld}", fut));
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"exp\":+%lld}", fut));
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"exp\":%lld.}", fut));
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"x\":tru,\"exp\":%lld}", fut));
    BAD(fmt("{\"sub\":\"7\",\"username\":\"bob\",\"x\":NaN,\"exp\":%lld}", fut));
    BAD(fmt("{'sub':\"7\",\"username\":\"bob\",\"exp\":%lld}", fut));
    BAD(fmt(
        "{\"x\":[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]],\"sub\":\"7\",\"username\":\"bob\",\"exp\":%lld}",
        fut));
    BAD(strdup(""));
    OKC(fmt(" \n{ \"sub\" : \"7\" ,\t\"username\" :\"bob\" , \"exp\" : %lld } \r\n", fut), 7, "bob", 0);
    /* headers */
    char *pl = fmt("{\"sub\":\"7\",\"username\":\"bob\",\"exp\":%lld}", fut);
    ADD(sign_with("{\"typ\":\"JWT\",\"alg\":\"HS256\"}", pl, SECRET), JWT_OK, 7, "bob", 0, "typ first");
    ADD(sign_with("{\"alg\":\"HS256\"}", pl, SECRET), JWT_OK, 7, "bob", 0, "alg only");
    ADD(sign_with(" { \"alg\" : \"HS\\u0032\\u00356\", \"kid\":[1,2] } ", pl, SECRET), JWT_OK, 7, "bob", 0,
        "escaped alg");
    ADD(sign_with("{\"alg\":\"none\"}", pl, SECRET), JWT_INVALID, 0, NULL, 0, "alg none (signed)");
    ADD(sign_with("{\"alg\":\"HS512\"}", pl, SECRET), JWT_INVALID, 0, NULL, 0, "HS512");
    ADD(sign_with("{\"alg\":\"hs256\"}", pl, SECRET), JWT_INVALID, 0, NULL, 0, "hs256");
    ADD(sign_with("{\"alg\":0}", pl, SECRET), JWT_INVALID, 0, NULL, 0, "alg 0");
    ADD(sign_with("{}", pl, SECRET), JWT_INVALID, 0, NULL, 0, "{}");
    ADD(sign_with("{\"typ\":\"JWT\"}", pl, SECRET), JWT_INVALID, 0, NULL, 0, "no alg");
    ADD(sign_with("{\"alg\":\"HS256\",\"alg\":\"HS256\"}", pl, SECRET), JWT_INVALID, 0, NULL, 0, "dup alg");
    ADD(sign_with("{\"alg\":\"HS256\"", pl, SECRET), JWT_INVALID, 0, NULL, 0, "hdr truncated");
    ADD(sign_with("[\"alg\",\"HS256\"]", pl, SECRET), JWT_INVALID, 0, NULL, 0, "hdr array");
    ADD(sign_with(HS, pl, "wrong-secret"), JWT_INVALID, 0, NULL, 0, "wrong secret");
    /* structural damage on the good token */
    {
        int L = (int)strlen(good);
        char *t;
        t = strdup(good), t[L - 1] = t[L - 1] == 'A' ? 'B' : 'A';
        ADD(t, JWT_INVALID, 0, NULL, 0, "last sig char changed");
        /* same top 4 bits, different (non-zero) low 2 bits: identical MAC bytes, non-canonical */
        t = strdup(good);
        {
            int v = (int)(strchr(B64U, t[L - 1]) - B64U);
            t[L - 1] = B64U[v | 1];
        }
        ADD(t, JWT_INVALID, 0, NULL, 0, "non-canonical sig");
        t = strdup(good), t[3] ^= 1;
        ADD(t, JWT_INVALID, 0, NULL, 0, "header bit flip");
        t = strdup(good), t[40] = t[40] == 'x' ? 'y' : 'x';
        ADD(t, JWT_INVALID, 0, NULL, 0, "payload char changed");
        ADD(fmt("%s=", good), JWT_INVALID, 0, NULL, 0, "sig padding");
        ADD(fmt("%s.", good), JWT_INVALID, 0, NULL, 0, "trailing dot");
        ADD(fmt("%sA", good), JWT_INVALID, 0, NULL, 0, "sig too long");
        ADD(strndup(good, L - 1), JWT_INVALID, 0, NULL, 0, "sig too short");
        ADD(fmt("x.%s", good), JWT_INVALID, 0, NULL, 0, "extra segment");
        ADD(fmt(".%s", strchr(good, '.') + 1), JWT_INVALID, 0, NULL, 0, "empty header");
        ADD(fmt("%.36s..%s", good, strrchr(good, '.') + 1), JWT_INVALID, 0, NULL, 0, "empty payload");
        ADD(fmt("Bearer %s", good), JWT_INVALID, 0, NULL, 0, "with Bearer prefix");
        t = strdup(good), t[37] = '+';
        ADD(t, JWT_INVALID, 0, NULL, 0, "base64 (not url) char");
        t = strdup(good), t[10] = '\0';
        ADD(t, JWT_INVALID, 0, NULL, 0, "NUL inside (len says full)");
        c[n - 1].what = "nul";
    }
    /* payload not valid base64url but correctly signed: the MAC covers the raw text */
    {
        char *raw = fmt("%s.%s", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "e30*");
        uint8_t d[32];
        unsigned dl;
        HMAC(EVP_sha256(), SECRET, (int)strlen(SECRET), (uint8_t *)raw, strlen(raw), d, &dl);
        char sg[64];
        b64u_enc(sg, d, 32);
        ADD(fmt("%s.%s", raw, sg), JWT_INVALID, 0, NULL, 0, "signed garbage payload");
    }

    int lens[256];
    const char *toks[256];
    jwt_key_t k;
    jwt_key_init(&k, SECRET, strlen(SECRET));
    for (int i = 0; i < n; i++) {
        size_t tl = strlen(c[i].tok) > strlen(good) ? strlen(c[i].tok) : strlen(good);
        char *padded = calloc(tl + 65, 1); /* JWT_INPUT_PADDED contract */
        memcpy(padded, c[i].tok, strlen(c[i].tok));
        toks[i] = padded;
        lens[i] = (int)strlen(c[i].tok);
        if (!strcmp(c[i].what, "nul")) memcpy((char *)toks[i], c[i].tok, strlen(good)), lens[i] = (int)strlen(good);
    }
    for (int e = 0; e < NENG; e++) {
        if (!engines[e].verify) continue;
        for (int bsz = 1; bsz <= n; bsz = bsz < 8 && !quick ? bsz + 1 : bsz * 3) {
            jwt_result_t res[256];
            for (int i = 0; i < n; i += bsz)
                engines[e].verify(&k, n - i < bsz ? n - i : bsz, toks + i, lens + i, now, res + i);
            for (int i = 0; i < n; i++) {
                jwt_result_t *r = &res[i];
                int ok = r->status == c[i].status;
                if (ok && r->status == JWT_OK) {
                    size_t el = strlen(c[i].name);
                    if (!strcmp(c[i].name, "nul")) el = 4;
                    ok = r->uid == c[i].uid && r->username_len == el && !memcmp(r->username, c[i].name, el) &&
                         r->username_escape == c[i].esc;
                }
                if (ok && r->status != JWT_OK) ok = r->uid == 0 && r->username_len == 0;
                CHECK(ok, "case %d [%s] engine %s batch %d: got status %d uid %lld name '%.*s' esc %d, want %d", i,
                      c[i].what, engines[e].name, bsz, r->status, (long long)r->uid, r->username_len, r->username,
                      r->username_escape, c[i].status);
            }
        }
    }
    printf("  %d crafted cases\n", n);
}

/* ---- external vectors (make test-vectors): RFC 4231, NIST CAVP HMAC.rsp [L=32], Wycheproof hmac_sha256,
 * random cases from pyca/cryptography, and the RFC 7515 A.1 JWS. Built by tests/make_vectors.py, which first
 * checks every parsed vector against cryptography. Each HMAC vector runs on every engine in a batch of 1-24
 * messages under its key (the others random, checked against OpenSSL), at a random lane position. */
static int unhex(const char *h, uint8_t *out) {
    if (!strcmp(h, "-")) return 0;
    int n = (int)strlen(h) / 2;
    for (int i = 0; i < n; i++) {
        unsigned v;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
    return n;
}
static void test_vectors(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        perror(path);
        exit(2);
    }
    size_t cap = 1 << 16;
    char *line = malloc(cap);
    static uint8_t key[4096], tag[64];
    uint8_t *vmsg = malloc(8192), *fill[24];
    for (int i = 0; i < 24; i++) fill[i] = malloc(800 + 64);
    long nh = 0, nbad = 0, nj = 0;
    while (fgets(line, (int)cap, f)) {
        char kind[8], src[128], a[9000], b[9000], c[200];
        long long x, y;
        if (sscanf(line, "%7s", kind) != 1) continue;
        if (!strcmp(kind, "hmac")) {
            if (sscanf(line, "%*s %127s %8999s %8999s %199s %lld", src, a, b, c, &x) != 5) {
                CHECK(0, "bad vector line");
                continue;
            }
            int kl = unhex(a, key), ml = unhex(b, vmsg), tl = unhex(c, tag), expect = (int)x;
            memset(vmsg + ml, 0x5a, 64);
            jwt_key_t k;
            jwt_key_init(&k, key, (size_t)kl);
            nh++;
            nbad += !expect;
            for (int e = 0; e < NENG; e++) {
                if (!engines[e].hmac) continue;
                int bs = 1 + (int)(rnd() % 24), at = (int)(rnd() % bs);
                const uint8_t *msg[24];
                int len[24];
                uint32_t mac[24][8];
                for (int i = 0; i < bs; i++) {
                    if (i == at) {
                        msg[i] = vmsg, len[i] = ml;
                        continue;
                    }
                    len[i] = (int)(rnd() % 800);
                    for (int j = 0; j < len[i]; j++) fill[i][j] = (uint8_t)rnd();
                    msg[i] = fill[i];
                }
                engines[e].hmac(&k, bs, msg, len, mac);
                uint8_t d[32];
                for (int j = 0; j < 8; j++)
                    d[4 * j] = mac[at][j] >> 24, d[4 * j + 1] = mac[at][j] >> 16, d[4 * j + 2] = mac[at][j] >> 8,
                          d[4 * j + 3] = mac[at][j];
                CHECK((memcmp(d, tag, (size_t)tl) == 0) == expect, "vector %s, engine %s: tag %s", src, engines[e].name,
                      expect ? "mismatch" : "accepted");
                for (int i = 0; i < bs; i++) { /* the other lanes, against OpenSSL with the same key */
                    if (i == at) continue;
                    uint8_t r[32];
                    unsigned rl = 32;
                    HMAC(EVP_sha256(), key, kl, msg[i], (size_t)len[i], r, &rl);
                    int ok = 1;
                    for (int j = 0; j < 8; j++) ok &= mac[i][j] == be32(r + 4 * j);
                    CHECK(ok, "vector %s, engine %s: filler lane %d wrong", src, engines[e].name, i);
                }
            }
        } else if (!strcmp(kind, "jws")) {
            if (sscanf(line, "%*s %127s %8999s %8999s %lld %lld", src, a, b, &x, &y) != 5) {
                CHECK(0, "bad jws line");
                continue;
            }
            int kl = unhex(a, key);
            jwt_key_t k;
            jwt_key_init(&k, key, (size_t)kl);
            char *tok = calloc(strlen(b) + 65, 1);
            memcpy(tok, b, strlen(b));
            const char *tp[1] = { tok };
            int tlen[1] = { (int)strlen(b) };
            nj++;
            for (int e = 0; e < NENG; e++) {
                if (!engines[e].verify) continue;
                jwt_result_t r[1];
                engines[e].verify(&k, 1, tp, tlen, (int64_t)x, r);
                CHECK(r[0].status == (int)y, "%s, engine %s: status %d, want %lld", src, engines[e].name, r[0].status,
                      y);
            }
            free(tok);
        }
    }
    fclose(f);
    free(line);
    free(vmsg);
    for (int i = 0; i < 24; i++) free(fill[i]);
    printf("  external vectors: %ld HMAC-SHA256 (%ld with invalid tags) x every engine, %ld JWS checks\n", nh, nbad,
           nj);
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "build/tokens.json";
    int n;
    seedtok_t *t = load_tokens(path, &n);
    int64_t now = (int64_t)time(NULL);
    quick = getenv("JWT_TEST_QUICK") != NULL;
    pick_engines();
    printf("engines:");
    for (int e = 0; e < NENG; e++) printf(" %s", engines[e].name);
    printf("\n");
#if defined(JWT_OSSL_SHA256) && defined(__x86_64__) && defined(__ELF__)
    printf("  OpenSSL sha256 paths this CPU can run: shaext %d, avx2+bmi2 %d, avx %d, ssse3 %d, x86-64 1\n",
           !!(jwt_ossl_ia32cap_P[2] & 1u << 29), (jwt_ossl_ia32cap_P[2] & 0x128) == 0x128,
           (jwt_ossl_ia32cap_P[0] >> 30 & 1) && (jwt_ossl_ia32cap_P[1] & (1u << 28 | 1u << 9)) == (1u << 28 | 1u << 9),
           !!(jwt_ossl_ia32cap_P[1] & 1u << 9));
#endif
    test_ternlog_immediates();
    test_b64();
    test_jint();
    test_hmac_random();
    test_sha256_raw();
    printf("  %d generated tokens\n", n);
    test_seed(t, n, now);
    test_cases(now);
    test_json_diff(now);
    if (argc > 2) test_vectors(argv[2]);
    printf("%s: %d/%d checks passed\n", fails ? "FAILED" : "OK", checks - fails, checks);
    return fails != 0;
}
