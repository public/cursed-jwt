/* cc_jwt_names.inc — cursed-jwt's original names for the crypto entry points (jwt_key_init, jwt_hmac_*,
 * jwt_sha256_*, jwt_cpu_features, jwt_engine), still exported for existing callers: on ELF as aliases of the cc_
 * functions (the same code, the same address), elsewhere as one-line wrappers.  #included by cursed_crypto.c;
 * -DCC_NO_JWT_NAMES leaves them out. */
#if defined(__ELF__)
#define CC_JWT_ALIAS(old, new) extern __typeof__(new) old __attribute__((alias(#new)));
#define CC_JWT_HMAC(e)         CC_JWT_ALIAS(jwt_hmac_##e, cc_hmac_sha256_##e)
#define CC_JWT_SHA(e)          CC_JWT_ALIAS(jwt_sha256_##e, cc_sha256_##e)
CC_JWT_ALIAS(jwt_key_init, cc_hmac_key_init)
CC_JWT_ALIAS(jwt_cpu_features, cc_cpu_features)
CC_JWT_ALIAS(jwt_engine, cc_engine)
CC_JWT_ALIAS(jwt_sha256_batch, cc_sha256_batch)
#else
#define CC_JWT_HMAC(e)                                                                                                 \
    void jwt_hmac_##e(const cc_hmac_key_t *k, int n, const uint8_t *const *msg, const int *len, uint32_t(*mac)[8]) {   \
        cc_hmac_sha256_##e(k, n, msg, len, mac);                                                                       \
    }
#define CC_JWT_SHA(e)                                                                                                  \
    void jwt_sha256_##e(int n, const uint8_t *const *msg, const int *len, uint32_t(*dig)[8]) {                         \
        cc_sha256_##e(n, msg, len, dig);                                                                               \
    }
void jwt_key_init(cc_hmac_key_t *k, const void *secret, size_t len) { cc_hmac_key_init(k, secret, len); }
unsigned jwt_cpu_features(void) { return cc_cpu_features(); }
const char *jwt_engine(void) { return cc_engine(); }
CC_JWT_SHA(batch)
#endif
CC_JWT_HMAC(scalar)
CC_JWT_SHA(scalar)
#if defined(CC_HAVE_NEON)
CC_JWT_HMAC(neon)
CC_JWT_SHA(neon)
#endif
#if defined(CC_ARM_SHA2)
CC_JWT_HMAC(sha2)
CC_JWT_HMAC(sha2_1)
CC_JWT_HMAC(sha2_2)
CC_JWT_SHA(sha2)
#endif
#if defined(CC_OSSL_SHA256) && defined(__x86_64__) && defined(__ELF__)
CC_JWT_HMAC(ossl)
#endif
#if defined(CC_X86)
CC_JWT_HMAC(avx2)
CC_JWT_HMAC(shani_1)
CC_JWT_HMAC(shani_2)
CC_JWT_HMAC(shani_4)
CC_JWT_HMAC(avx512)
CC_JWT_HMAC(zmm)
CC_JWT_SHA(avx2)
CC_JWT_SHA(avx512)
#if defined(CC_SHANI_MB) && defined(__ELF__)
CC_JWT_HMAC(shani_4r)
CC_JWT_HMAC(x16)
CC_JWT_HMAC(shani_x16)
#endif
#endif
#undef CC_JWT_HMAC
#undef CC_JWT_SHA
#undef CC_JWT_ALIAS
