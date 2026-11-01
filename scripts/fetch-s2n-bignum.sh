#!/bin/sh
# fetch-s2n-bignum.sh: AWS s2n-bignum's formally verified P-256 field and RSA-2048 Montgomery kernels (assembly) into
# third_party/s2n-bignum (git-ignored), each file checked against a pinned SHA-256.  Licence: Apache-2.0 OR ISC OR
# MIT-0 (used under MIT-0).  Only the -DJWT_PK -DJWT_S2N build uses them (src/jwt_pk.inc, PK.md).
#   github.com/awslabs/s2n-bignum @ 3306729
# The x86 versions need BMI2 + ADX (mulx / adcx / adox); the arm versions need plain ARMv8.
set -e
cd "$(dirname "$0")/.."
D=third_party/s2n-bignum
C=330672965f9ee29eaa27df14c484806d7b8ef0bc
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
get() { # path-in-repo sha256  (kept at the same relative path under $D)
  f="${D:?}/${1:?}"
  mkdir -p "$(dirname "$f")"
  if [ -f "$f" ] && [ "$(sha "$f")" = "$2" ]; then return; fi
  echo "$1: fetching s2n-bignum $C"
  curl -fsSL "https://raw.githubusercontent.com/awslabs/s2n-bignum/$C/$1" -o "$f.tmp"
  got=$(sha "$f.tmp")
  [ "$got" = "$2" ] || {
    echo "$1: SHA-256 mismatch (got $got, want $2)" >&2
    rm -f "${f:?}.tmp"
    exit 1
  }
  mv "$f.tmp" "$f"
}
get LICENSE 41c6380384dc6065456d01405ef0b43e5fe39ba1bccc4ec67801cc66142728e5
get include/_internal_s2n_bignum_arm.h 1cb6d1fedc55ae2ab2f8fad1efd349be2fc2284ea7b5558a787a23448047475b
get include/_internal_s2n_bignum_x86.h 32e93f25e504f9aef6d16250e4eaf0e6214ca00c6312d44d909d6be13a0c249d
get arm/p256/bignum_montmul_p256.S eb892a473af5ea1933912732b5036cff6b54a5c75af774223b71d57d0d884fc1
get arm/p256/bignum_montsqr_p256.S 24d868666a7d9483ce0e8dc50bc0902e7a6f229150ba4f1b7b6db69f2e646f28
get arm/p256/bignum_add_p256.S 139964a49ff6fa29c083fe25b3764efaa86baf106167bd9e15f5ba447b78a4cc
get arm/p256/bignum_sub_p256.S 17cf78d4f40b4d9c05295f984371e13f1bb6c74dea11936cd914099610d6e8f5
get arm/fastmul/bignum_kmul_32_64.S a3b0e1e7f869277b0d085b7a13845db081ca6f06c8fe37096fcfbb660acc9a22
get arm/fastmul/bignum_ksqr_32_64.S 5c54506e52a5318c1e64ea298127182a3922f85a6ebc3d2563cb083a427ef426
get arm/fastmul/bignum_emontredc_8n.S 3857968d4ea098bc90f1a8d0148bb71715432a15bd5ff24f49b48dd7ed5f1c49
get x86/p256/bignum_montmul_p256.S 67054aa23bc758c6c63126d4b72653a9a8bce9edf3fb5920daacb12a965f5920
get x86/p256/bignum_montsqr_p256.S d2423a6d39fb9e118a4f10f8a8f3cd9bca5d833474a67a6ab194f4cb300d3fd8
get x86/p256/bignum_add_p256.S ea02371a7025d462b2210e35966b304318a67bc9226558111c0e4026f1c34aed
get x86/p256/bignum_sub_p256.S daf9e19b257d3403b2653ad63e64a8fa3ec16718e5e1459468b86e6fc6f3611d
get x86/fastmul/bignum_kmul_32_64.S 2fa9179f8445f4d2f540e21c3dbd6f9a852f0be57763aae713ab4a077d76df6e
get x86/fastmul/bignum_ksqr_32_64.S 16f7cf7fe364974bc208621ab01079c53f25e2fcfbe269d786ad048e30b8c9ae
get x86/fastmul/bignum_emontredc_8n.S 395a67897f51b0f6c708ac788fd871b8b1350f51afb2b3eba855f5d9cb359bb1
echo "s2n-bignum @ $C: OK"
