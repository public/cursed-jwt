#!/bin/sh
# fetch.sh: the third-party inputs of contrib/envoy, at pinned versions, SHA-256 checked, into
# contrib/envoy/third_party/ (git-ignored).  Nothing here is vendored.
#
#   envoy/       Envoy v1.40.2's dynamic-modules C ABI header (needed to build the filter) and its in-tree JWT
#                library (source/common/jwt, ex google/jwt_verify_lib: what jwt_authn runs; only for the
#                differential test and the benchmark).  Single files, raw.
#   abseil/ protobuf/ boringssl/   the versions Envoy v1.40.2 pins in MODULE.bazel (abseil-cpp 20260817.0,
#                protobuf 35.1, boringssl 0.20260929.0), as release tarballs; only for the differential test and the
#                benchmark.
#
# Usage: ./fetch.sh [envoy|deps]...   (no argument = both)
set -e
cd "$(dirname "$0")"
T=third_party
mkdir -p $T
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
dl() { # url dest sha256
  if [ -f "$2" ] && [ "$(sha "$2")" = "$3" ]; then return; fi
  echo "fetching $1"
  mkdir -p "$(dirname "$2")"
  curl -fsSL "$1" -o "$2.tmp"
  got=$(sha "$2.tmp")
  [ "$got" = "$3" ] || {
    echo "$2: SHA-256 mismatch (got $got, want $3)" >&2
    rm -f "$2.tmp"
    exit 1
  }
  mv "$2.tmp" "$2"
}

ENVOY_COMMIT=b2d89e0ae53916f28770771fbdd49c5c99c5c5a2 # tag v1.40.2
envoy() {
  e() { dl "https://raw.githubusercontent.com/envoyproxy/envoy/$ENVOY_COMMIT/$1" "$T/envoy/$1" "$2"; }
  e LICENSE cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30
  e source/common/jwt/check_audience.cc 3ebdc90962146a7706e43af5307ea661d27bedcc9bcddd956c3767eb29445944
  e source/common/jwt/check_audience.h bcb9b863f28eb707412e3cd7b120321146ca4b3814c05fe760db108323f950a9
  e source/common/jwt/jwks.cc 614269a8c30cac1a02f77ba81e27c3b5b3dfd163a610fdfbeeb4950fcbd9a94c
  e source/common/jwt/jwks.h 486a976cea6bd625026590333b20179b4ff07cd037db8618f0d20ae92d2c6189
  e source/common/jwt/jwt.cc 8d8367406269687d06982dccda4dc660385841e9c2a548f8e4347190f880449c
  e source/common/jwt/jwt.h 7c776ef0c6668e7cfea0a4e040e47aa6225dbe15026535c04b9a325828a31131
  e source/common/jwt/status.cc f7149eafea86b072741e66d02ab1298ca9f05b5c1dce3e59fef5968a4d8a17f5
  e source/common/jwt/status.h 2c1975ed523e3aa2ff7306d25bfb493e5d91aabd708db67aac746fd218b3e31c
  e source/common/jwt/struct_utils.cc 4095c36376f9f9b270ef4418cfb370d66fafb5481117d193285fc85d275b3660
  e source/common/jwt/struct_utils.h 35bd56b10a6f06a8edf7158928601848caf983aaccae9d04175fbcc66954ae5c
  e source/common/jwt/verify.cc de8c4e8dcbf92aa3854d9f540d4b07707550dd0832514be3be501ca3b765e37a
  e source/common/jwt/verify.h f5a2baf2a7b42a13cc2a0f6fba9664ae85fb03f89415a191eb82fa5e340fb145
  e source/extensions/dynamic_modules/abi/abi.h 5c004204a634b5a07c3f2af63d3b4117a5bb8ce5a53bca4a98fb41cf86a1f0a7
}

deps() {
  dl https://github.com/abseil/abseil-cpp/archive/refs/tags/20260817.0.tar.gz $T/tar/abseil.tar.gz \
    f7e05179df39c45434cad433f5783840bb3788ef322976f9138bc6b72b3a107d
  # the release tarball Envoy's registry entry (protobuf 35.1.bcr.envoy) uses; its patches only touch Bazel files
  # and warnings, not the JSON parser
  dl https://github.com/protocolbuffers/protobuf/releases/download/v35.1/protobuf-35.1.tar.gz $T/tar/protobuf.tar.gz \
    f0b6838e7522a8da96126d487068c959bc624926368f3024ac8fd03abd0a1ac4
  dl https://github.com/google/boringssl/archive/refs/tags/0.20260929.0.tar.gz $T/tar/boringssl.tar.gz \
    04da9ba0664e0a7f028e961c38d604f2cc6dac852a84ca0e51dc1fa051d4c8fe
  for d in abseil protobuf boringssl; do
    [ -d $T/$d ] || { mkdir -p $T/$d && tar -xzf $T/tar/$d.tar.gz -C $T/$d --strip-components 1; }
  done
}

[ $# -gt 0 ] || set -- envoy deps
for a in "$@"; do $a; done
