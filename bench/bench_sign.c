/* bench_sign.c — signing ns/token vs OpenSSL.  Unity build: includes jwt.c.
 *   ./bench_sign [seconds-per-cell]
 * One claims set (the same JSON bytes everywhere), batch 1 and 16:
 *   cursed-jwt   jwt_sign_batch (HS256) / jwt_sign_batch_pk (EdDSA): payload check, base64url, MAC or signature,
 *                the whole token
 *   raw          cc_hmac_sha256_bytes / cc_sign_batch of the signing input only (the crypto alone)
 *   OpenSSL      HMAC() (key set per call), EVP_MAC (key set once, re-initialised per token) and EVP_DigestSign
 *                (Ed25519, the EVP_PKEY parsed once) of the same signing input: the crypto alone, as a JWT library
 *                built on OpenSSL calls it per token */
#include "jwt.c"

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/hmac.h>
#include <openssl/params.h>
#include <stdio.h>
#include <time.h>

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e9 + ts.tv_nsec;
}
static volatile unsigned sink;
enum { B = 16 };
static const char PL[] = "{\"sub\":\"123456\",\"username\":\"alice\",\"iat\":1700000000,\"exp\":4102444800}";
static char outs[B][512], *op[B], si[512];
static const char *pp[B];
static int pn[B], on[B], sil;

#define CELL(name, batch, body)                                                                                        \
    do {                                                                                                               \
        long it = 0;                                                                                                   \
        double t0 = now_ns(), t1;                                                                                      \
        do {                                                                                                           \
            for (int r_ = 0; r_ < 64; r_++) { body; }                                                                  \
            it += 64;                                                                                                  \
        } while ((t1 = now_ns()) - t0 < secs * 1e9);                                                                   \
        printf("  %-34s b%-3d %9.1f ns/token\n", name, batch, (t1 - t0) / ((double)it * (batch)));                     \
    } while (0)

int main(int argc, char **argv) {
    double secs = argc > 1 ? atof(argv[1]) : 1.0;
    for (int i = 0; i < B; i++) pp[i] = PL, pn[i] = (int)sizeof PL - 1, op[i] = outs[i];
    printf("cpu features 0x%x, HMAC engine %s; payload %d bytes\n", jwt_cpu_features(), jwt_engine(),
           (int)sizeof PL - 1);
    jwt_key_t hk;
    jwt_key_init(&hk, "bench-secret-0123456789abcdef0123", 33);
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(i * 7 + 1);
    jwt_skey_t *sk = jwt_skey_ed25519(seed);
    /* the signing input, for the raw cells */
    jwt_sign_batch(&hk, 1, pp, pn, op, on);
    sil = (int)(strrchr(outs[0], '.') - outs[0]);
    memcpy(si, outs[0], (size_t)sil);
    const uint8_t *mp[B];
    int ml[B];
    uint8_t mac[B][32], sig[B][64], *sp[B];
    for (int i = 0; i < B; i++) mp[i] = (const uint8_t *)si, ml[i] = sil, sp[i] = sig[i];
    EVP_PKEY *ek = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
    EVP_MD_CTX *mc = EVP_MD_CTX_new();
    const char *hkey = "bench-secret-0123456789abcdef0123";

    printf("HS256\n");
    for (int b = 1; b <= B; b += B - 1) {
        CELL("cursed-jwt jwt_sign_batch", b, sink += (unsigned)jwt_sign_batch(&hk, b, pp, pn, op, on));
        CELL("raw cc_hmac_sha256_bytes", b, (cc_hmac_sha256_bytes(&hk, b, mp, ml, mac), sink += mac[0][0]));
    }
    CELL("OpenSSL HMAC() (key set per call)", 1, {
        unsigned dl = 32;
        HMAC(EVP_sha256(), hkey, 33, (const uint8_t *)si, (size_t)sil, mac[0], &dl);
        sink += mac[0][0];
    });
    {
        EVP_MAC *m = EVP_MAC_fetch(NULL, "HMAC", NULL);
        EVP_MAC_CTX *c = EVP_MAC_CTX_new(m);
        OSSL_PARAM prm[] = { OSSL_PARAM_construct_utf8_string("digest", (char *)"SHA256", 0),
                             OSSL_PARAM_construct_end() };
        EVP_MAC_init(c, (const uint8_t *)hkey, 33, prm);
        CELL("OpenSSL EVP_MAC (key set once)", 1, {
            size_t ol = 32;
            EVP_MAC_init(c, NULL, 0, NULL);
            EVP_MAC_update(c, (const uint8_t *)si, (size_t)sil);
            EVP_MAC_final(c, mac[0], &ol, 32);
            sink += mac[0][0];
        });
        EVP_MAC_CTX_free(c), EVP_MAC_free(m);
    }
    printf("EdDSA (Ed25519)\n");
    for (int b = 1; b <= B; b += B - 1) {
        CELL("cursed-jwt jwt_sign_batch_pk", b, sink += (unsigned)jwt_sign_batch_pk(sk, b, pp, pn, op, on));
        CELL("raw cc_sign_batch", b, (cc_sign_batch(sk->cc, b, mp, ml, sp), sink += sig[0][0]));
    }
    CELL("OpenSSL EVP_DigestSign", 1, {
        size_t sl = 64;
        EVP_DigestSignInit(mc, NULL, NULL, NULL, ek);
        EVP_DigestSign(mc, sig[0], &sl, (const uint8_t *)si, (size_t)sil);
        sink += sig[0][0];
    });
    {
        long it = 0;
        double t0 = now_ns(), t1;
        do {
            jwt_skey_free(jwt_skey_ed25519(seed));
            it++;
        } while ((t1 = now_ns()) - t0 < secs * 1e9);
        printf("  %-34s      %9.1f ns/key\n", "jwt_skey_ed25519 (key setup)", (t1 - t0) / (double)it);
    }
    EVP_MD_CTX_free(mc), EVP_PKEY_free(ek), jwt_skey_free(sk);
    return 0;
}
