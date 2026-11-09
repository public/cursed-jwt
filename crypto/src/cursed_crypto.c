/* cursed_crypto.c — cursed-crypto as one translation unit: CPU dispatch and the SHA-256 / HMAC-SHA256 engines
 * (cc_sha256.c), then RS256 / ES256 / Ed25519 verification (cc_pk.c; -DCC_NO_PK leaves it out), then cursed-jwt's
 * original names for them (cc_jwt_names.inc).  Part of cursed-jwt, MIT licence (see LICENSE).  Build it on its own
 * (the Makefile's build/libcursedcrypto.a), or let src/jwt.c #include it for a one-unit build of the whole library. */
#include "cc_internal.h"

#include "cc_sha256.c"
#ifndef CC_NO_PK
#include "cc_pk.c"
#endif
#ifndef CC_NO_JWT_NAMES
#include "cc_jwt_names.inc"
#endif
