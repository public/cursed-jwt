#!/bin/sh
# fetch-ossl-rsaz.sh: OpenSSL's AVX-512 IFMA almost-Montgomery multiplication for 2048-bit moduli
# (ossl_rsaz_amm52x40_x1_ifma256, crypto/bn/asm/rsaz-4k-avx512.pl; Intel's contribution, Apache-2.0) into
# third_party/openssl-rsaz (git-ignored), each file checked against a pinned SHA-256, then translated by OpenSSL's own
# perlasm translator into build/rsaz-4k-avx512.S.  Only the -DJWT_RSAZ build uses it (src/jwt_pk.inc, PK.md).
#   github.com/openssl/openssl @ openssl-4.1.0 (2f4e3a5)
# Needs perl and an assembler that knows AVX-512 IFMA (binutils >= 2.26 or clang >= 7). x86-64 only.
set -e
cd "$(dirname "$0")/.."
D=third_party/openssl-rsaz
C=2f4e3a5fec05394068cfa7379890ab552483a8a6
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
get() { # path-in-repo sha256  (stored under $D by file name)
  f="${D:?}/$(basename "${1:?}")"
  mkdir -p "$D"
  if [ -f "$f" ] && [ "$(sha "$f")" = "$2" ]; then return; fi
  echo "$1: fetching openssl $C"
  curl -fsSL "https://raw.githubusercontent.com/openssl/openssl/$C/$1" -o "$f.tmp"
  got=$(sha "$f.tmp")
  [ "$got" = "$2" ] || {
    echo "$1: SHA-256 mismatch (got $got, want $2)" >&2
    rm -f "${f:?}.tmp"
    exit 1
  }
  mv "$f.tmp" "$f"
}
get LICENSE.txt 7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a
get crypto/bn/asm/rsaz-4k-avx512.pl 8e3ab163f5ccb57ef71e08103e7bc1888ee4ec448fe5d32c658b03b8180e6cce
get crypto/perlasm/x86_64-xlate.pl 77c24c8986367cac72253eaec5af35e2387bb72ad43f092dd5e934776a14f69a
mkdir -p build
# the generator probes $CC's assembler for IFMA support and emits an empty file without it: refuse that
CC="${CC:-cc}" perl "$D/rsaz-4k-avx512.pl" elf build/rsaz-4k-avx512.S.tmp
grep -q 'ossl_rsaz_amm52x40_x1_ifma256:' build/rsaz-4k-avx512.S.tmp || {
  echo "fetch-ossl-rsaz: the assembler ($CC) lacks AVX-512 IFMA; -DJWT_RSAZ needs binutils >= 2.26 or clang >= 7" >&2
  rm -f build/rsaz-4k-avx512.S.tmp
  exit 1
}
printf '.section .note.GNU-stack,"",@progbits\n' >>build/rsaz-4k-avx512.S.tmp # no executable stack (OpenSSL passes --noexecstack instead)
mv build/rsaz-4k-avx512.S.tmp build/rsaz-4k-avx512.S
echo "openssl rsaz @ $C: OK"
