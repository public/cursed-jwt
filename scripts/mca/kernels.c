// kernels.c - the SHA-256 block functions of src/jwt.c as llvm-mca regions (scripts/mca/mca.sh): one compress of
// one 64-byte block per lane, per engine. Region names carry the lane count ("x8_avx2" = 8 messages per call), so
// mca.sh reports cycles per byte per message. Built once per architecture: jwt.c's own target regions give each
// engine its ISA. kbench.c times the same functions (scripts/mca/validate.sh).
#include "../../src/jwt.c"

#if defined(__aarch64__)
#define MCA(name, ...) do { __asm volatile("// LLVM-MCA-BEGIN " name ::: "memory"); __VA_ARGS__; __asm volatile("// LLVM-MCA-END " name ::: "memory"); } while (0)
#else
#define MCA(name, ...) do { __asm volatile("# LLVM-MCA-BEGIN " name ::: "memory"); __VA_ARGS__; __asm volatile("# LLVM-MCA-END " name ::: "memory"); } while (0)
#endif
#define K __attribute__((noinline, flatten)) void   // flatten: the whole compress inside the region, not a call
// state s: 8 vectors (st0/st1 on the SHA2-instruction engine), message w: 16 vectors; both 64-byte aligned

K k_empty(void *s, void *w) { MCA("empty", ((uint32_t *)s)[0] ^= ((uint32_t *)w)[0]); }   // call overhead (kbench.c)
K k_x1_scalar(void *s, void *w) { MCA("x1_scalar", compress_scalar((uint32_t *)s, (uint32_t *)w)); }
#if defined(JWT_X86)
JWT_BEGIN_AVX2
K k_x8_avx2(void *s, void *w) { MCA("x8_avx2", compress_avx2((__m256i *)s, (__m256i *)w)); }
K k_x16_avx2x2(void *s, void *w) { MCA("x16_avx2x2", compress_avx2x2((v2_t *)s, (v2_t *)w)); }
JWT_END_TARGET
JWT_BEGIN_AVX512
K k_x8_avx512(void *s, void *w) { MCA("x8_avx512", compress_avx512((__m256i *)s, (__m256i *)w)); }
K k_x16_avx512x2(void *s, void *w) { MCA("x16_avx512x2", compress_avx512x2((v2_t *)s, (v2_t *)w)); }
K k_x16_zmm(void *s, void *w) { MCA("x16_zmm", compress_zmm((__m512i *)s, (__m512i *)w)); }
JWT_END_TARGET
#endif
#if defined(JWT_HAVE_NEON)
K k_x4_neon(void *s, void *w) { MCA("x4_neon", compress_neon((uint32x4_t *)s, (uint32x4_t *)w)); }
#endif
#if defined(JWT_ARM_SHA2)
JWT_BEGIN_SHA2
// S interleaved streams: st0[S], st1[S] in s; m[S][4] in w
#define KCE(S) K k_x##S##_sha2(void *s, void *w) { uint32x4_t *st = (uint32x4_t *)s; \
  MCA("x" #S "_sha2", ce_compress(S, st, st + S, (uint32x4_t (*)[4])w)); }
KCE(1)
KCE(2)
KCE(4)
JWT_END_SHA2
#endif
