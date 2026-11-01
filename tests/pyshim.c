/* pyshim.c — the library as a shared object for tests/test_hypothesis.py (ctypes).  Unity build: includes jwt.c,
 * so the property tests reach every HS256 engine the target has and RS256 / ES256 / EdDSA.
 *   jt_engines()                      number of full-verify engines
 *   jt_engine_name(i)                 its name
 *   jt_verify(i, key, n, tok, len, now, out)   jwt_verify_batch on engine i
 * plus jwt_key_init, jwt_pkey_es256 / jwt_pkey_rs256 / jwt_pkey_free and jwt_verify_batch_pk, unchanged. */
#include "jwt.c"

typedef void verify_fn(const jwt_key_t *, int, const char *const *, const int *, int64_t, jwt_result_t *);
static const struct {
    const char *name;
    verify_fn *fn;
    unsigned need;
} all_shim[] = {
    { "default", jwt_verify_batch, 0 },
    { "scalar", jwt_verify_batch_scalar, 0 },
#ifdef JWT_HAVE_NEON
    { "neon", jwt_verify_batch_neon, 0 },
#endif
#if defined(__aarch64__)
    { "sha2", jwt_verify_batch_sha2, JWT_CPU_SHA2 },
#endif
#if defined(__x86_64__)
    { "avx2", jwt_verify_batch_avx2, JWT_CPU_AVX2 },
    { "avx512", jwt_verify_batch_avx512, JWT_CPU_AVX512VL },
#endif
};
static int shim_idx[16], shim_n = -1;
static void shim_pick(void) {
    if (shim_n >= 0) return;
    shim_n = 0;
    for (int i = 0; i < (int)(sizeof all_shim / sizeof all_shim[0]); i++)
        if ((all_shim[i].need & jwt_cpu_features()) == all_shim[i].need) shim_idx[shim_n++] = i;
}
#define shim_engines(i) all_shim[shim_idx[i]]

int jt_engines(void) {
    shim_pick();
    return shim_n;
}
const char *jt_engine_name(int i) { return shim_engines(i).name; }
void jt_verify(int i, const jwt_key_t *k, int n, const char *const *tok, const int *len, int64_t now,
               jwt_result_t *out) {
    shim_engines(i).fn(k, n, tok, len, now, out);
}
size_t jt_sizeof_key(void) { return sizeof(jwt_key_t); }
size_t jt_sizeof_result(void) { return sizeof(jwt_result_t); }
