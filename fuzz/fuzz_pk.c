/* fuzz_pk.c — libFuzzer harness for the RS256 / ES256 prototype (-DJWT_PK), with OpenSSL as the oracle.
 *
 * At start-up it makes one P-256 and one RSA-2048 key with OpenSSL.  Each input picks an algorithm, a message and a
 * list of mutations; the message is signed with OpenSSL, the signature is mutated (byte XORs, ECDSA's other valid s,
 * r or s forced to 0 / 1 / n-1 / n / n+1 / 2^256-1), and then:
 *   - jwt_pk_verify_raw on it alone must equal OpenSSL's verdict (EVP_DigestVerify; for ES256, r || s must also be
 *     in [1, n-1], as JWS requires);
 *   - the same, placed among 0-15 genuinely signed filler messages in one batch, which must all verify. This covers
 *     the shared inversion and, built with -DJWT_RSA_SCREEN, the screening fallback.
 * ASan / UBSan run throughout.  Build: make fuzz. */
#include "jwt.c"

#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <stdio.h>

static EVP_PKEY *ek, *rk;
static jwt_pkey_t *jek, *jrk;
static const uint8_t N256[32] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51};

static int bn_bytes(EVP_PKEY *k, const char *name, uint8_t *out, int width) {
    BIGNUM *b = NULL;
    if (!EVP_PKEY_get_bn_param(k, name, &b)) abort();
    int n = width ? BN_bn2binpad(b, out, width) : BN_bn2bin(b, out);
    BN_free(b);
    return n;
}
static void setup(void) {
    ek = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    rk = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    if (!ek || !rk) abort();
    uint8_t x[32], y[32], n[256], e[8];
    bn_bytes(ek, OSSL_PKEY_PARAM_EC_PUB_X, x, 32), bn_bytes(ek, OSSL_PKEY_PARAM_EC_PUB_Y, y, 32);
    int nl = bn_bytes(rk, OSSL_PKEY_PARAM_RSA_N, n, 0), el = bn_bytes(rk, OSSL_PKEY_PARAM_RSA_E, e, 0);
    jek = jwt_pkey_es256(x, y), jrk = jwt_pkey_rs256(n, (size_t)nl, e, (size_t)el);
    if (!jek || !jrk) abort();
}

/* sign with OpenSSL; ES256 comes back as JOSE r || s */
static int sign(int rsa, const uint8_t *m, size_t ml, uint8_t *sig) {
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    uint8_t der[300];
    size_t dl = sizeof der;
    if (!EVP_DigestSignInit(c, NULL, EVP_sha256(), NULL, rsa ? rk : ek) || !EVP_DigestSign(c, der, &dl, m, ml)) abort();
    EVP_MD_CTX_free(c);
    if (rsa) { memcpy(sig, der, dl); return (int)dl; }
    const uint8_t *p = der;
    ECDSA_SIG *es = d2i_ECDSA_SIG(NULL, &p, (long)dl);
    BN_bn2binpad(ECDSA_SIG_get0_r(es), sig, 32), BN_bn2binpad(ECDSA_SIG_get0_s(es), sig + 32, 32);
    ECDSA_SIG_free(es);
    return 64;
}
static int in_range(const uint8_t v[32]) { /* 0 < v < n */
    int nz = 0;
    for (int i = 0; i < 32; i++) nz |= v[i];
    return nz && memcmp(v, N256, 32) < 0;
}
static int ossl_ok(int rsa, const uint8_t *m, size_t ml, const uint8_t *sig, int sl) {
    uint8_t der[300];
    const uint8_t *s = sig;
    size_t dl = (size_t)sl;
    if (!rsa) {
        if (sl != 64 || !in_range(sig) || !in_range(sig + 32)) return 0;
        ECDSA_SIG *es = ECDSA_SIG_new();
        ECDSA_SIG_set0(es, BN_bin2bn(sig, 32, NULL), BN_bin2bn(sig + 32, 32, NULL));
        uint8_t *q = der;
        dl = (size_t)i2d_ECDSA_SIG(es, &q), s = der;
        ECDSA_SIG_free(es);
    }
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    int r = EVP_DigestVerifyInit(c, NULL, EVP_sha256(), NULL, rsa ? rk : ek) == 1 && EVP_DigestVerify(c, s, dl, m, ml) == 1;
    EVP_MD_CTX_free(c);
    return r;
}

/* sub-into-place helpers on 32-byte big-endian numbers */
static void be_sub(uint8_t r[32], const uint8_t a[32], const uint8_t b[32]) {
    int bw = 0;
    for (int i = 31; i >= 0; i--) { int d = a[i] - b[i] - bw; bw = d < 0; r[i] = (uint8_t)d; }
}
static void set_edge(uint8_t v[32], int which) {
    static const uint8_t one[32] = {[31] = 1};
    switch (which % 6) {
    case 0: memset(v, 0, 32); break;
    case 1: memcpy(v, one, 32); break;
    case 2: be_sub(v, N256, one); break;
    case 3: memcpy(v, N256, 32); break;
    case 4: memcpy(v, N256, 32), v[31] += 1; break;
    default: memset(v, 0xff, 32); break;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static int init;
    if (!init) setup(), init = 1;
    if (size < 2) return 0;
    int rsa = data[0] & 1, nfill = (data[0] >> 1) & 15, ml = data[1] % 200;
    if ((size_t)ml + 2 > size) ml = (int)size - 2;
    const uint8_t *m = data + 2, *ops = data + 2 + ml, *end = data + size;
    uint8_t sig[256];
    int sl = sign(rsa, m, (size_t)ml, sig);
    for (const uint8_t *o = ops; o + 3 <= end; o += 3) { /* (kind, a, b) */
        int kind = o[0] % 8, pos = (o[1] << 8 | o[2]) % sl;
        if (kind < 5) sig[pos] ^= o[1] | 1;                      /* byte flips (most ops) */
        else if (rsa) sig[pos] ^= 0x80;
        else if (kind == 5) be_sub(sig + 32, N256, sig + 32);  /* the other valid s */
        else set_edge(kind == 6 ? sig : sig + 32, o[2]);     /* r or s at an edge value */
    }
    const jwt_pkey_t *k = rsa ? jrk : jek;
    int want = ossl_ok(rsa, m, (size_t)ml, sig, sl);
    const uint8_t *mp[16], *sp[16];
    int mlen[16], slen[16];
    uint8_t ok[16], fsig[16][256], fmsg[16][8];
    mp[0] = m, sp[0] = sig, mlen[0] = ml, slen[0] = sl;
    jwt_pk_verify_raw(k, 1, mp, mlen, sp, slen, ok);
    if (ok[0] != want) { fprintf(stderr, "%s alone: cursed %d, OpenSSL %d\n", rsa ? "RS256" : "ES256", ok[0], want); abort(); }
    int n = 1 + nfill, at = ml % n;
    for (int i = 0, f = 0; i < n; i++) {
        if (i == at) { mp[i] = m, sp[i] = sig, mlen[i] = ml, slen[i] = sl; continue; }
        memcpy(fmsg[f], "filler", 6), fmsg[f][6] = (uint8_t)f, fmsg[f][7] = data[0];
        slen[i] = sign(rsa, fmsg[f], 8, fsig[f]), mp[i] = fmsg[f], sp[i] = fsig[f], mlen[i] = 8, f++;
    }
    jwt_pk_verify_raw(k, n, mp, mlen, sp, slen, ok);
    for (int i = 0; i < n; i++)
        if (ok[i] != (i == at ? want : 1)) { fprintf(stderr, "%s batch of %d, lane %d: cursed %d, want %d\n", rsa ? "RS256" : "ES256", n, i, ok[i], i == at ? want : 1); abort(); }
    return 0;
}
