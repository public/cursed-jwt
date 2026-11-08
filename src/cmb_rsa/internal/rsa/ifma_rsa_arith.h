/* cursed-jwt's stand-in for crypto_mb's internal/rsa/ifma_rsa_arith.h: only what the three vendored RSA-2048
 * public-exponent files use (no OpenSSL, no crypto_mb status codes) */
#ifndef IFMA_RSA_ARITH_H
#define IFMA_RSA_ARITH_H
#include <internal/common/ifma_defs.h>
#include <internal/common/ifma_math.h>
typedef int64u (*pint64u_x8)[8];
#define RSA_1K (1024)
#define RSA_2K (2 * RSA_1K)
EXTERN_C void ifma_amm52x40_mb8(int64u *out_mb8, const int64u *inpA_mb8, const int64u *inpB_mb8, const int64u *inpM_mb8,
                                const int64u *k0_mb8);
EXTERN_C void AMS52x40_diagonal_mb8(int64u *out_mb8, const int64u *inpA_mb8, const int64u *inpM_mb8,
                                    const int64u *k0_mb8);
EXTERN_C void EXP52x40_pub65537_mb8(int64u out[][8], const int64u base[][8], const int64u modulus[][8],
                                    const int64u toMont[][8], const int64u k0[8], int64u work_buffer[][8]);
#endif
