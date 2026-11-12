/* cc_sign_rs256.inc — RS256 (RSASSA-PKCS1-v1_5 with SHA-256) signing, #included by cc_sign.c.  Part of cursed-jwt, MIT
 * licence (see LICENSE).
 *
 * Delegated to OpenSSL's libcrypto, and so only in a -DJWT_OPENSSL build (link -lcrypto); elsewhere cc_skey_rs256
 * returns NULL.  The private-key operation is libcrypto's: CRT with blinding, constant-time Montgomery exponentiation,
 * and its own check of the CRT result against the public key (a fault defence).  Its timing is libcrypto's, not
 * checked by this library's constant-time tests.  PKCS#1 v1.5 is deterministic: the same key and message give the
 * same signature, byte for byte, as OpenSSL's or any other conforming implementation's. */

#ifdef CC_OPENSSL
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

cc_skey_t *cc_skey_rs256(const uint8_t *key, size_t len) {
    EVP_PKEY *pk = NULL;
    if (len > 10 && !memcmp(key, "-----BEGIN", 10)) { /* PEM: PKCS#8 or PKCS#1 ("RSA PRIVATE KEY") */
        BIO *b = BIO_new_mem_buf(key, (int)len);
        if (b) pk = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL), BIO_free(b);
    } else if (len <= (size_t)INT32_MAX) { /* DER: PKCS#8 or PKCS#1 */
        const unsigned char *p = key;
        pk = d2i_AutoPrivateKey(NULL, &p, (long)len);
    }
    ERR_clear_error();
    if (!pk) return NULL;
    int bits = EVP_PKEY_get_bits(pk);
    if (EVP_PKEY_get_base_id(pk) != EVP_PKEY_RSA || bits < 2048 || bits > 4096) {
        EVP_PKEY_free(pk);
        return NULL;
    }
    cc_skey_t *k = calloc(1, sizeof *k);
    if (!k) {
        EVP_PKEY_free(pk);
        return NULL;
    }
    k->alg = CC_PK_RS256, k->rs_pkey = pk, k->rs_bytes = EVP_PKEY_get_size(pk);
    return k;
}
/* the modulus and public exponent, big-endian, as cc_pkey_rs256 takes them; returns the modulus length or -1 */
int cc_skey_rs256_public(const cc_skey_t *k, uint8_t *n, size_t ncap, uint8_t *e, size_t ecap, size_t *elen) {
    if (k->alg != CC_PK_RS256) return -1;
    BIGNUM *bn = NULL, *be = NULL;
    int r = -1;
    if (EVP_PKEY_get_bn_param((EVP_PKEY *)k->rs_pkey, "n", &bn) &&
        EVP_PKEY_get_bn_param((EVP_PKEY *)k->rs_pkey, "e", &be) && (size_t)BN_num_bytes(bn) <= ncap &&
        (size_t)BN_num_bytes(be) <= ecap) {
        r = BN_bn2bin(bn, n);
        *elen = (size_t)BN_bn2bin(be, e);
    }
    BN_free(bn), BN_free(be);
    return r;
}
static void rs_free(cc_skey_t *k) { EVP_PKEY_free((EVP_PKEY *)k->rs_pkey); }
static int rs_sign_batch(const cc_skey_t *k, int n, const uint8_t *const *msg, const int *len, uint8_t *const *sig) {
    int bad = 0;
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    for (int i = 0; i < n; i++) {
        size_t sl = (size_t)k->rs_bytes;
        if (!c || EVP_DigestSignInit(c, NULL, EVP_sha256(), NULL, (EVP_PKEY *)k->rs_pkey) != 1 ||
            EVP_DigestSign(c, sig[i], &sl, msg[i], (size_t)len[i]) != 1 || sl != (size_t)k->rs_bytes) {
            memset(sig[i], 0, (size_t)k->rs_bytes), bad++; /* (libcrypto refused or failed: no signature) */
            ERR_clear_error();
        }
        if (c) EVP_MD_CTX_reset(c);
    }
    EVP_MD_CTX_free(c);
    return bad;
}
#else
cc_skey_t *cc_skey_rs256(const uint8_t *key, size_t len) {
    (void)key, (void)len;
    return NULL; /* RS256 signing needs -DJWT_OPENSSL */
}
int cc_skey_rs256_public(const cc_skey_t *k, uint8_t *n, size_t ncap, uint8_t *e, size_t ecap, size_t *elen) {
    (void)k, (void)n, (void)ncap, (void)e, (void)ecap, (void)elen;
    return -1;
}
static void rs_free(cc_skey_t *k) { (void)k; }
static int rs_sign_batch(const cc_skey_t *k, int n, const uint8_t *const *msg, const int *len, uint8_t *const *sig) {
    (void)k, (void)n, (void)msg, (void)len, (void)sig;
    return n; /* unreachable: there are no RS256 keys in this build */
}
#endif
