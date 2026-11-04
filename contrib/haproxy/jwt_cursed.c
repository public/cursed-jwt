/*
 * jwt_verify's signature checks through cursed-jwt, for HAProxy 3.4 (contrib/haproxy/haproxy-3.4.7.patch).
 *
 * Kept in its own translation unit: cursed-jwt's jwt.h and HAProxy's
 * haproxy/jwt.h share a prefix, so the two are never included together.
 */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/obj_mac.h>

#include "jwt.h" /* cursed-jwt */

#define JWT_CURSED_FALLBACK -1

int jwt_cursed_enabled = 1;

#if defined(__x86_64__) && defined(__ELF__)
/* single message: OpenSSL's sha256_block_data_order, extracted (cursed-jwt built with -DJWT_OSSL_SHA256) */
jwt_hmac_fn jwt_hmac_ossl;
#define HMAC1 jwt_hmac_ossl
#else
#define HMAC1 jwt_hmac_scalar
#endif

/* The HMAC key midstates of the last secret seen by this thread. jwt_verify
 * gets the secret as a string on every call (it may come from a variable), so
 * the cache is keyed on its bytes. Secrets longer than this are not cached. */
#define HS_CACHE_MAX 256
static __thread struct {
    size_t len;
    jwt_key_t key;
    unsigned char secret[HS_CACHE_MAX];
} hs_cache;

int jwt_cursed_hs256(const char *key, size_t klen, const char *msg, size_t mlen, const unsigned char *sig,
                     size_t slen) {
    jwt_key_t local, *k = &local;
    const uint8_t *m = (const uint8_t *)msg;
    int ml = (int)mlen;
    uint32_t mac[1][8];
    unsigned char out[32];
    int i;

    if (klen <= HS_CACHE_MAX) {
        k = &hs_cache.key;
        if (hs_cache.len != klen || memcmp(hs_cache.secret, key, klen) != 0) {
            jwt_key_init(k, key, klen);
            memcpy(hs_cache.secret, key, klen);
            hs_cache.len = klen;
        }
    } else jwt_key_init(k, key, klen);

    HMAC1(k, 1, &m, &ml, mac);
    for (i = 0; i < 8; i++) {
        out[4 * i] = mac[0][i] >> 24;
        out[4 * i + 1] = mac[0][i] >> 16;
        out[4 * i + 2] = mac[0][i] >> 8;
        out[4 * i + 3] = mac[0][i];
    }
    /* same test as jwt_jwsverify_hmac(): length, then CRYPTO_memcmp */
    return slen == 32 && CRYPTO_memcmp(out, sig, 32) == 0;
}

int jwt_cursed_b64url(char *dst, size_t dsz, const char *src, size_t n) {
    /* the SIMD stores overrun: (n/4)*3 + 3 bytes of output plus 32 of slack */
    if (n > (size_t)JWT_TOKEN_MAX * 4 || (n / 4) * 3 + 3 + 32 > dsz) return -1;
    return jwt_b64url_decode((uint8_t *)dst, src, (int)n);
}

struct cursed_pkey {
    jwt_pkey_t *k;
    int is_ecdsa;
    int sig_bytes;
};

static int bn_param(EVP_PKEY *pkey, const char *name, unsigned char *buf, int len) {
    BIGNUM *bn = NULL;
    int ret = -1;

    if (EVP_PKEY_get_bn_param(pkey, name, &bn) == 1) ret = (len ? BN_bn2binpad(bn, buf, len) : BN_bn2bin(bn, buf));
    BN_free(bn);
    return ret;
}

void *jwt_cursed_pkey_new(EVP_PKEY *pkey) {
    struct cursed_pkey *ck;
    jwt_pkey_t *k = NULL;
    unsigned char n[512], e[8], x[32], y[32];
    char group[64];
    int is_ecdsa = 0, sig_bytes = 0;

    if (EVP_PKEY_get_id(pkey) == EVP_PKEY_RSA) {
        int bits = EVP_PKEY_get_bits(pkey);
        int nlen, elen;
        BIGNUM *ebn = NULL;

        if (bits < 2048 || bits > 4096) return NULL;
        if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &ebn) != 1) return NULL;
        elen = BN_num_bytes(ebn);
        BN_free(ebn);
        if (elen > (int)sizeof(e)) return NULL;
        nlen = bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, n, 0);
        elen = bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, e, 0);
        if (nlen <= 0 || elen <= 0) return NULL;
        k = jwt_pkey_rs256(n, nlen, e, elen);
        sig_bytes = nlen;
    } else if (EVP_PKEY_get_id(pkey) == EVP_PKEY_EC) {
        size_t glen = 0;

        if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof(group), &glen) != 1 ||
            strcmp(group, SN_X9_62_prime256v1) != 0)
            return NULL;
        if (bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, x, 32) != 32 ||
            bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, y, 32) != 32)
            return NULL;
        k = jwt_pkey_es256(x, y);
        is_ecdsa = 1;
        sig_bytes = 64;
    }
    if (!k) return NULL;
    ck = calloc(1, sizeof(*ck));
    if (!ck) {
        jwt_pkey_free(k);
        return NULL;
    }
    ck->k = k;
    ck->is_ecdsa = is_ecdsa;
    ck->sig_bytes = sig_bytes;
    return ck;
}

void jwt_cursed_pkey_free(void *p) {
    struct cursed_pkey *ck = p;

    if (!ck) return;
    jwt_pkey_free(ck->k);
    free(ck);
}

int jwt_cursed_pk_verify(const void *p, int is_ecdsa, const char *msg, size_t mlen, const unsigned char *sig,
                         size_t slen) {
    const struct cursed_pkey *ck = p;
    const uint8_t *m = (const uint8_t *)msg, *s = sig;
    int ml = (int)mlen, sl = (int)slen;
    uint8_t ok = 0;

    /* OpenSSL decides the odd cases: an algorithm that does not fit the key
	 * (it fails), and signatures of another length (ES256 R||S halves with
	 * leading zeros pass through BN_bin2bn, so OpenSSL can accept them). */
    if (ck->is_ecdsa != is_ecdsa || sl != ck->sig_bytes || mlen > (size_t)JWT_TOKEN_MAX) return JWT_CURSED_FALLBACK;
    jwt_pk_verify_raw(ck->k, 1, &m, &ml, &s, &sl, &ok);
    return ok;
}
