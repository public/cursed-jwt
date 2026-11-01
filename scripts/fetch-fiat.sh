#!/bin/sh
# fetch-fiat.sh: fiat-crypto's generated P-256 and curve25519 field and scalar arithmetic (formally verified, MIT / Apache-2.0 /
# BSD-1-Clause, used under MIT) into third_party/fiat (git-ignored), each file checked against a pinned SHA-256.
# Needed only for the -DJWT_PK prototype (RS256 / ES256, src/jwt_pk.inc).   github.com/mit-plv/fiat-crypto @ 1e721c6
set -e
cd "$(dirname "$0")/.."
D=third_party/fiat
mkdir -p $D
C=1e721c6f18c43b90922e7bc57fd64848e5cff2be
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
get() { # path-in-repo sha256
  f=$(basename "$1")
  if [ -f "$D/$f" ] && [ "$(sha "$D/$f")" = "$2" ]; then
    echo "$f: have it"
    return
  fi
  echo "$f: fetching fiat-crypto $C/$1"
  curl -fsSL "https://raw.githubusercontent.com/mit-plv/fiat-crypto/$C/$1" -o "$D/$f.tmp"
  got=$(sha "$D/$f.tmp")
  [ "$got" = "$2" ] || {
    echo "$f: SHA-256 mismatch (got $got, want $2)" >&2
    rm -f "$D/$f.tmp"
    exit 1
  }
  mv "$D/$f.tmp" "$D/$f"
}
get fiat-c/src/p256_64.c 68cc5c4fa08de660a869a412618a30848f11d18051245013fe53fa4e313ec701
get fiat-c/src/p256_scalar_64.c eed8ad2adb15aa8e120ff8f7ded6c6297284724a612f6b284c5afba9bebfae83
get fiat-c/src/curve25519_64.c 645233c37707ba0580338aa84d8380357078a2c9bb2db80f0c5ff4e979650e3e
get fiat-c/src/curve25519_scalar_64.c 6ce7b54074efe552d455c087b982bba0f93d41d3d5d9f90fb2d9afaf8a36626a
get LICENSE-MIT 0034712d5e97a4f5b900a160a5c19d582b740d8e0638b4e44fd07e7b492dcd13
