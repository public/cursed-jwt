#!/usr/bin/env bash
# build.sh [cursed|stock]: HAProxy 3.4.7 with jwt_verify, jwt_header_query and jwt_payload_query going through
# cursed-jwt (cursed, the default), or unpatched (stock, for comparisons), into contrib/haproxy/build/<variant>/.
# Downloads the HAProxy release tarball once (sha256-pinned); nothing of HAProxy is committed here.
# Needs make, gcc or clang, and OpenSSL 3 headers (libssl-dev).
#   S2N=0    leave out s2n-bignum (fetched pinned by scripts/fetch-s2n-bignum.sh; x86-64 and arm64): P-256 and
#            RSA-2048 then use the portable arithmetic (fiat-crypto, libcrypto BN for RSA)
#   UNIT=1   build with -DDEBUG_UNIT and the unit tests (haproxy -U jwt-diff / jwt-bench); test.sh sets it
#   JOBS     make -j (default: the CPU count); CC and extra arguments are passed to HAProxy's make
# No -march: the library picks its engines at run time (CPUID), so the binary runs on any CPU of its architecture.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
J="$(cd "$HERE/../.." && pwd)"
V="${1:-cursed}"
[ $# -gt 0 ] && shift
case $V in cursed | stock) ;; *) echo "usage: $0 [cursed|stock] [make args]" >&2 && exit 2 ;; esac
CC="${CC:-cc}"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)}"
O="$HERE/build"
mkdir -p "$O"

HAPROXY_VER=3.4.7
HAPROXY_SHA256=ccfd342f3724c2cd659574044d788f44e20b212467c6bd5edbbfc517a2775dca
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
t="$O/haproxy-$HAPROXY_VER.tar.gz"
if [ ! -f "$t" ]; then
  curl -fsSL -o "$t.tmp" "https://www.haproxy.org/download/${HAPROXY_VER%.*}/src/haproxy-$HAPROXY_VER.tar.gz"
  mv "$t.tmp" "$t"
fi
[ "$(sha256 "$t")" = "$HAPROXY_SHA256" ] || { echo "haproxy-$HAPROXY_VER.tar.gz: sha256 mismatch" >&2 && exit 1; }

# a fresh tree per variant, so the patch is always applied to the pristine release
S="$O/$V"
rm -rf "$S" "$O/haproxy-$HAPROXY_VER"
tar -xzf "$t" -C "$O"
mv "$O/haproxy-$HAPROXY_VER" "$S"

LIBS="-lcrypto"
OBJS=""
DEFS=""
if [ "${UNIT:-0}" = 1 ]; then DEFS="-DDEBUG_UNIT"; fi
if [ "$V" = cursed ]; then
  (cd "$S" && patch -s -p1 <"$HERE/haproxy-$HAPROXY_VER.patch")
  [ "${UNIT:-0}" = 1 ] && OBJS="src/jwt_cursed_test.o"
  # cursed-jwt, and the glue in an archive of its own. The glue is compiled apart from HAProxy: cursed-jwt's jwt.h and
  # HAProxy's haproxy/jwt.h share the jwt_ prefix, so no file includes both.
  L="$O/lib"
  rm -rf "$L"
  mkdir -p "$L"
  # the library comes from the root Makefile (libcursedjwt_all.a: the JWT layer, cursed-crypto and, with S2N=1,
  # s2n-bignum's kernels), built -fPIC with this build's flags; no source list lives here
  JDEFS="-DJWT_OPENSSL"
  SHA="SHAFLAG= SHAOBJ="
  if [ "$(uname -m)-$(uname -s)" = x86_64-Linux ]; then
    JDEFS="$JDEFS -DJWT_OSSL_SHA256"
    SHA="SHAFLAG=-DJWT_OSSL_SHA256 SHAOBJ=$L/root/sha256_x86_64_ossl.o"
  fi
  [ "${S2N:-1}" = 1 ] && JDEFS="$JDEFS -DJWT_S2N"
  # shellcheck disable=SC2086 # word splitting intended
  make -s -C "$J" B="$L/root" CC="$CC" CFLAGS="-O3 -fPIC" $SHA LIBFLAGS="$JDEFS" "$L/root/libcursedjwt_all.a"
  # shellcheck disable=SC2086
  "$CC" -O2 -fPIC -Wall $JDEFS -I"$J/include" -c "$HERE/jwt_cursed.c" -o "$L/jwt_cursed.o"
  ar rcs "$L/libcursedjwt-haproxy.a" "$L/jwt_cursed.o"
  LIBS="$L/libcursedjwt-haproxy.a $L/root/libcursedjwt_all.a $LIBS"
fi

case $(uname -s) in Linux) TARGET=linux-glibc ;; Darwin) TARGET=osx ;; *) TARGET=generic ;; esac
make -s -C "$S" -j"$JOBS" TARGET="$TARGET" USE_OPENSSL=1 USE_PCRE2= USE_PCRE2_JIT= DEBUG="$DEFS" \
  EXTRA_OBJS="$OBJS" ADDLIB="$LIBS" CC="$CC" "$@"
"$S/haproxy" -v | head -1
echo "built $S/haproxy"
