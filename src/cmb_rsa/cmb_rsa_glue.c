/* cmb_rsa_glue.c: the one crypto_mb helper the three vendored RSA files call that isn't among them (-DJWT_RSAZ8) */
#include <stdint.h>
#include <string.h>
void zero_mb8(uint64_t (*out)[8], int len) { memset(out, 0, (size_t)len * sizeof *out); }
