/* cursed_crypto.c — cursed-crypto as one translation unit: CPU dispatch and the SHA-256 / HMAC-SHA256 engines
 * (cc_sha256.c), then RS256 / ES256 / EdDSA verification (cc_pk.c; -DJWT_NO_PK leaves it out).  Part of cursed-jwt,
 * MIT licence (see LICENSE).  src/jwt.c #includes this file, so the JWT layer and the crypto compile as one unit. */
#include "../../include/jwt.h"

#include "cc_sha256.c"
#ifndef JWT_NO_PK
#include "cc_pk.c"
#endif
