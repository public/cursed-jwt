/* pyshim.c — the library as a shared object for tests/test_hypothesis.py (ctypes).  Unity build: includes jwt.c,
 * with -DJWT_PK, so the property tests reach every HS256 engine the target has and the RS256 / ES256 prototype.
 *   jt_engines()                      number of full-verify engines
 *   jt_engine_name(i)                 its name
 *   jt_verify(i, key, n, tok, len, now, out)   jwt_verify_batch on engine i
 * plus jwt_key_init, jwt_pkey_es256 / jwt_pkey_rs256 / jwt_pkey_free and jwt_verify_batch_pk, unchanged. */
#include "jwt.c"

typedef void verify_fn(const jwt_key_t *, int, const char *const *, const int *, int64_t, jwt_result_t *);
static const struct {
    const char *name;
    verify_fn *fn;
} shim_engines[] = {
    {"default", jwt_verify_batch},
    {"scalar", jwt_verify_batch_scalar},
#ifdef JWT_HAVE_NEON
    {"neon", jwt_verify_batch_neon},
#endif
#if defined(__ARM_FEATURE_SHA2)
    {"sha2", jwt_verify_batch_sha2},
#endif
#if defined(__AVX2__)
    {"avx2", jwt_verify_batch_avx2},
#endif
#if defined(JWT_AVX512) && defined(__AVX512VL__)
    {"avx512", jwt_verify_batch_avx512},
#endif
};

int jt_engines(void) { return (int)(sizeof shim_engines / sizeof shim_engines[0]); }
const char *jt_engine_name(int i) { return shim_engines[i].name; }
void jt_verify(int i, const jwt_key_t *k, int n, const char *const *tok, const int *len, int64_t now, jwt_result_t *out) {
    shim_engines[i].fn(k, n, tok, len, now, out);
}
size_t jt_sizeof_key(void) { return sizeof(jwt_key_t); }
size_t jt_sizeof_result(void) { return sizeof(jwt_result_t); }
