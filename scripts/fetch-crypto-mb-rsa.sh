#!/bin/sh
# fetch-crypto-mb-rsa.sh: three files of Intel's crypto_mb (cryptography-primitives, Apache-2.0) for 8-lane RSA-2048
# public-key exponentiation with AVX-512 IFMA (EXP52x40_pub65537_mb8, ifma_amm52x40_mb8, AMS52x40_diagonal_mb8),
# plus the five headers they read, into third_party/crypto-mb-rsa (git-ignored), each checked against a pinned
# SHA-256.  Compiled on their own, without crypto_mb's build system or its OpenSSL dependency
# (crypto/src/cmb_rsa/internal/rsa/ifma_rsa_arith.h stands in for the one header that needs OpenSSL).  Only the
# -DJWT_RSAZ8 build uses them (crypto/src/cc_pk.c, PK.md).
# Also crypto_mb's 8-lane P-256 field arithmetic (ifma_arith_p256.c / ifma_arith_m256.c and their header), which
# crypto/src/cmb_ec/es8.c #includes for the -DJWT_ES8 build's 8-token ES256 comb additions.
#   github.com/intel/cryptography-primitives @ 316ce55
set -e
cd "$(dirname "$0")/.."
D=third_party/crypto-mb-rsa
C=316ce5567e44d3633bfb559706dddd3dba60f3e2
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
get() { # path-in-repo sha256  (kept at the same relative path under $D)
  f="${D:?}/${1:?}"
  mkdir -p "$(dirname "$f")"
  if [ -f "$f" ] && [ "$(sha "$f")" = "$2" ]; then return; fi
  echo "$1: fetching cryptography-primitives $C"
  curl -fsSL "https://raw.githubusercontent.com/intel/cryptography-primitives/$C/$1" -o "$f.tmp"
  got=$(sha "$f.tmp")
  [ "$got" = "$2" ] || {
    echo "$1: SHA-256 mismatch (got $got, want $2)" >&2
    rm -f "${f:?}.tmp"
    exit 1
  }
  mv "$f.tmp" "$f"
}
get LICENSE 30452bdf81f0c9aa4d9d797b3946c79d220b69478e4655966eb2b519e3e0b32c
get sources/ippcp/crypto_mb/include/crypto_mb/defs.h b4e1e22784272b25e576b42b410ae6b5034706444cf54154b6bd159dda82a12a
get sources/ippcp/crypto_mb/include/internal/common/internal_defs.h 552fe6fc92dce9c3f2cb7fa177b32da688b01072a8902dc076e8ee249afa829d
get sources/ippcp/crypto_mb/include/internal/common/ifma_defs.h d4d0d6d1b637156bfb184e62d1e7800384db14f34fdd8000a34be6feeea67ba3
get sources/ippcp/crypto_mb/include/internal/common/ifma_math.h 8a74fab48f282fc186ee1b4e835217411a4b5b501a93746b0ae6fb1145485a7b
get sources/ippcp/crypto_mb/include/internal/common/memory_clear.h b330a918ce86703b9e88801304f35c81cd6b65bf0f72e277c77b7938deb0b32c
get sources/ippcp/crypto_mb/src/rsa/ifma_exp52x40_65537_mb8.c 174105ab80268638d2b8a0f39f993adfca433d70f03c796b8d705a1e1e16f869
get sources/ippcp/crypto_mb/src/rsa/internal_avx512/ifma_amm52x40_mb8.c feef4574e4f542a3cd8e23a0da0d2fb01bf21d784819d4c4e1b401af32439da7
get sources/ippcp/crypto_mb/src/rsa/internal_avx512/ifma_ams52x40_diagonal_mb8.c 72d356da1f67d1381e1dabf1273c7b79e6fb5e69d6fa545dd147eb1f23566137
get sources/ippcp/crypto_mb/include/internal/ecnist/ifma_arith_p256.h e3f23b5a77a77133b713eb94569d1a6dda127401c96a5815d04c3b50e5af60c8
get sources/ippcp/crypto_mb/src/ecnist/low_level_arith/ifma_arith_p256.c 986224af971bb454a8fdc84c6d71c7ab1f6fe0a1a2fbe578139be2b166dbc224
get sources/ippcp/crypto_mb/src/ecnist/low_level_arith/ifma_arith_m256.c 93453428cefea9c5057c623ed921d0450ae19620c84a69de8ef7a14b9e1f8bbd
echo "crypto_mb rsa + p256 @ $C: OK"
