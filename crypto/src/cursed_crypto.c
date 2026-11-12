/* cursed_crypto.c — cursed-crypto as one translation unit: CPU dispatch and the SHA-256 / HMAC-SHA256 engines
 * (cc_sha256.c), SHA-512 (cc_sha512.c), then RS256 / ES256 / Ed25519 verification (cc_pk.c) and Ed25519 signing
 * (cc_sign.c; -DCC_NO_PK leaves both out).  Part of cursed-jwt, MIT licence (see LICENSE).  Build it on its own (the Makefile's build/libcursedcrypto.a, whose every export is
 * cc_*), or let src/jwt.c #include it for a one-unit build of the whole library. */
#include "cc_internal.h"

#include "cc_sha256.c"
#include "cc_sha512.c"
#ifndef CC_NO_PK
#include "cc_pk.c"
#include "cc_sign.c"
#endif
