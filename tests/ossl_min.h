/* ossl_min.h — the few OpenSSL symbols the tests and benchmarks use (OpenSSL is a test/bench dependency only).  Real headers when installed; otherwise
 * minimal declarations so a box with only the runtime libcrypto.so.3 (no libssl-dev) can build
 * them (link with -l:libcrypto.so.3).  SHA256_CTX matches OpenSSL 1.1/3.x's public layout. */
#ifndef OSSL_MIN_H
#define OSSL_MIN_H
#if defined(__has_include)
#if __has_include(<openssl/hmac.h>)
#define OSSL_MIN_REAL 1
#endif
#endif
#ifdef OSSL_MIN_REAL
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#else
#include <stddef.h>
typedef struct evp_md_st EVP_MD;
const EVP_MD *EVP_sha256(void);
unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len, const unsigned char *data, size_t data_len,
                    unsigned char *md, unsigned int *md_len);
typedef struct SHA256state_st {
    unsigned int h[8];
    unsigned int Nl, Nh;
    unsigned int data[16];
    unsigned int num, md_len;
} SHA256_CTX;
int SHA256_Init(SHA256_CTX *c);
int SHA256_Update(SHA256_CTX *c, const void *data, size_t len);
int SHA256_Final(unsigned char *md, SHA256_CTX *c);
#endif
#endif
