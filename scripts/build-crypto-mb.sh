#!/bin/sh
# build-crypto-mb.sh: fetch Intel's crypto_mb (intel/cryptography-primitives v2.3.0, Apache-2.0) at a pinned commit,
# check the tarball's SHA-256, and build its static library into third_party/crypto-mb/ (git-ignored), for the
# -DJWT_CRYPTO_MB build: 8-way AVX-512 IFMA ES256 verification and RSA public-key operations (src/jwt_pk.inc).
#
# Linux x86-64 only.  Needs CMake >= 3.18, NASM, Python 3, a C compiler (gcc >= 8.5 or clang >= 16) and OpenSSL
# >= 3.5.5 *headers* (crypto_mb's CMake insists on them even though cursed-jwt uses only its non-OpenSSL API); point
# OPENSSL_ROOT_DIR at such an install if the system's is older (Ubuntu 24.04 ships 3.0).  The library runs anywhere,
# but its kernels only on CPUs with AVX-512 IFMA (Ice Lake and later); cursed-jwt checks CPUID before calling it.
set -e
cd "$(dirname "$0")/.."
D=third_party/crypto-mb
C=b5746138d6c509082f6550192443dd9d5f28ba9e
SUM=d1a26d6dc358bfbdb4fe779fe7ec1848dad1835fdaece325742ed1c7adc9809e
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
if [ -f "$D/lib/libcrypto_mb.a" ] && [ "$(cat "$D/.commit" 2>/dev/null)" = "$C" ]; then echo "crypto_mb: have $C"; exit 0; fi
mkdir -p "$D"
T="${D:?}/src.tar.gz"
if [ ! -f "$T" ] || [ "$(sha "$T")" != "$SUM" ]; then
  echo "crypto_mb: fetching intel/cryptography-primitives @ $C"
  curl -fsSL "https://codeload.github.com/intel/cryptography-primitives/tar.gz/$C" -o "$T.tmp"
  got=$(sha "$T.tmp"); [ "$got" = "$SUM" ] || { echo "SHA-256 mismatch (got $got, want $SUM)" >&2; rm -f "${T:?}.tmp"; exit 1; }
  mv "$T.tmp" "$T"
fi
rm -rf "${D:?}/src" && mkdir -p "$D/src" && tar -xzf "$T" -C "$D/src" --strip-components=1
cmake -S "$D/src/sources/ippcp/crypto_mb" -B "$D/build" -DCMAKE_BUILD_TYPE=Release \
  ${OPENSSL_ROOT_DIR:+-DOPENSSL_ROOT_DIR="$OPENSSL_ROOT_DIR"} ${CC:+-DCMAKE_C_COMPILER="$CC"}
cmake --build "$D/build" --target crypto_mb_s -j "${JOBS:-4}"
mkdir -p "$D/lib" "$D/include"
cp "$(find "$D/build" -name 'libcrypto_mb*.a' | head -1)" "$D/lib/libcrypto_mb.a"
cp -R "$D/src/sources/ippcp/crypto_mb/include/crypto_mb" "$D/include/"
cp "$D/src/LICENSE" "$D/LICENSE"
echo "$C" > "$D/.commit"
echo "crypto_mb: built $D/lib/libcrypto_mb.a"
