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
  # cursed-jwt plus the glue, in one archive. The glue is compiled apart from HAProxy: cursed-jwt's jwt.h and
  # HAProxy's haproxy/jwt.h share the jwt_ prefix, so no file includes both.
  L="$O/lib"
  rm -rf "$L"
  mkdir -p "$L"
  JDEFS="-DJWT_OPENSSL"
  LOBJS="$L/jwt.o $L/jwt_cursed.o"
  if [ "$(uname -m)-$(uname -s)" = x86_64-Linux ]; then
    JDEFS="$JDEFS -DJWT_OSSL_SHA256"
    "$CC" -c "$J/crypto/src/sha256_x86_64_ossl.S" -o "$L/sha256_x86_64_ossl.o"
    LOBJS="$LOBJS $L/sha256_x86_64_ossl.o"
  fi
  if [ "${S2N:-1}" = 1 ]; then
    [ -d "$J/third_party/s2n-bignum/include" ] || (cd "$J" && ./scripts/fetch-s2n-bignum.sh >/dev/null)
    JDEFS="$JDEFS -DJWT_S2N"
    a=$([ "$(uname -m)" = x86_64 ] && echo x86 || echo arm)
    fs="p256/bignum_montmul_p256 p256/bignum_montsqr_p256 p256/bignum_add_p256 p256/bignum_sub_p256"
    fs="$fs fastmul/bignum_kmul_32_64 fastmul/bignum_ksqr_32_64 fastmul/bignum_emontredc_8n"
    # x86-64: the ADX-free P-256 multiply / square, for CPUs (and VMs) that hide BMI2 / ADX, and the Ed25519 comb
    # addition (both variants)
    [ "$a" = x86 ] && fs="$fs p256/bignum_montmul_p256_alt p256/bignum_montsqr_p256_alt"
    [ "$a" = x86 ] && fs="$fs curve25519/edwards25519_pepadd curve25519/edwards25519_pepadd_alt"
    for f in $fs; do
      "$CC" -c -DS2N_BN_HIDE_SYMBOLS=1 -I"$J/third_party/s2n-bignum/include" "$J/third_party/s2n-bignum/$a/$f.S" \
        -o "$L/${f#*/}.o"
      LOBJS="$LOBJS $L/${f#*/}.o"
    done
  fi
  # shellcheck disable=SC2086 # word splitting intended
  "$CC" -O3 -fPIC -Wall -Wno-deprecated-declarations -Wno-unused-function $JDEFS -I"$J/include" -I"$J/src" \
    -c "$J/src/jwt.c" -o "$L/jwt.o"
  # shellcheck disable=SC2086
  "$CC" -O2 -fPIC -Wall $JDEFS -I"$J/include" -c "$HERE/jwt_cursed.c" -o "$L/jwt_cursed.o"
  # shellcheck disable=SC2086
  ar rcs "$L/libcursedjwt-haproxy.a" $LOBJS
  LIBS="$L/libcursedjwt-haproxy.a $LIBS"
fi

case $(uname -s) in Linux) TARGET=linux-glibc ;; Darwin) TARGET=osx ;; *) TARGET=generic ;; esac
make -s -C "$S" -j"$JOBS" TARGET="$TARGET" USE_OPENSSL=1 USE_PCRE2= USE_PCRE2_JIT= DEBUG="$DEFS" \
  EXTRA_OBJS="$OBJS" ADDLIB="$LIBS" CC="$CC" "$@"
"$S/haproxy" -v | head -1
echo "built $S/haproxy"
