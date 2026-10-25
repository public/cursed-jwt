// kbench.c - measures what mca.sh estimates: back-to-back calls of one kernel of kernels.c on L1-hot state, so
// that `perf stat -e cycles` / calls - the k_empty baseline compares with the region's block rthroughput.
//   cc -O3 -Iinclude scripts/mca/kbench.c -o kbench && perf stat -e cycles ./kbench x8_avx2 10000000 [chain|indep]
// chain (default): each call's state feeds the next, as the blocks of one message (latency-bound);
// indep: 4 state buffers in turn, independent calls, which is what mca's block rthroughput assumes.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kernels.c"

int main(int argc, char **argv) {
  static const struct { const char *n; void (*f)(void *, void *); int lanes; } K_[] = {
    {"empty", k_empty, 1}, {"x1_scalar", k_x1_scalar, 1},
#if defined(JWT_X86)
    {"x8_avx2", k_x8_avx2, 8}, {"x16_avx2x2", k_x16_avx2x2, 16},
    {"x8_avx512", k_x8_avx512, 8}, {"x16_avx512x2", k_x16_avx512x2, 16}, {"x16_zmm", k_x16_zmm, 16},
#endif
#if defined(JWT_HAVE_NEON)
    {"x4_neon", k_x4_neon, 4},
#endif
#if defined(JWT_ARM_SHA2)
    {"x1_sha2", k_x1_sha2, 1}, {"x2_sha2", k_x2_sha2, 2}, {"x4_sha2", k_x4_sha2, 4},
#endif
  };
  if (argc < 3) { fprintf(stderr, "usage: %s KERNEL CALLS [chain|indep]\n", argv[0]); return 2; }
  int indep = argc > 3 && !strcmp(argv[3], "indep");
  void (*f)(void *, void *) = NULL;
  for (size_t i = 0; i < sizeof K_ / sizeof *K_; i++) if (!strcmp(K_[i].n, argv[1])) f = K_[i].f;
  if (!f) { printf("%s: not in this build\n", argv[1]); return 3; }
  long calls = atol(argv[2]);
  static uint32_t s[4][8 * 16] __attribute__((aligned(64))), w[16 * 16] __attribute__((aligned(64)));
  for (int b = 0; b < 4; b++) for (int i = 0; i < 8 * 16; i++) s[b][i] = 0x6a09e667u * (uint32_t)(i + 1 + b);
  for (int i = 0; i < 16 * 16; i++) w[i] = 0x9e3779b9u * (uint32_t)(i + 7);
  if (indep) for (long i = 0; i < calls; i++) f(s[i & 3], w);
  else for (long i = 0; i < calls; i++) f(s[0], w);
  printf("%s %ld calls (%08x)\n", argv[1], calls, s[0][0] ^ s[3][0]);
  return 0;
}
