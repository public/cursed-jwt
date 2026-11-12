#!/bin/sh
# fetch-compare.sh: the JWT libraries the comparison benchmark runs against, at pinned commits, into third_party/
# (git-ignored; each keeps its own licence):
#   jwt-cpp     Thalhammer/jwt-cpp @ 1e9b135   MIT (bundles picojson, BSD-2)   C++, OpenSSL + picojson
#   golang-jwt  golang-jwt/jwt v5 @ 9a618ef    MIT                             Go
#   libsodium   1.0.20 release tarball         ISC                             C (Ed25519 signing only)
set -e
cd "$(dirname "$0")/.."
mkdir -p third_party
fetch() { # name owner/repo commit
  [ -f "third_party/$1/.commit" ] && [ "$(cat "third_party/$1/.commit")" = "$3" ] && {
    echo "$1: have $3"
    return
  }
  echo "$1: fetching $2 @ $3"
  rm -rf "third_party/$1" "third_party/$1.tmp"
  mkdir -p "third_party/$1.tmp"
  curl -fsSL "https://codeload.github.com/$2/tar.gz/$3" | tar -xzf - -C "third_party/$1.tmp" --strip-components=1
  mv "third_party/$1.tmp" "third_party/$1"
  echo "$3" >"third_party/$1/.commit"
}
fetch jwt-cpp Thalhammer/jwt-cpp 1e9b1354e1b70fce293277d01abdd02b0082b1de
fetch golang-jwt golang-jwt/jwt 9a618efd06fc5036c19970cdbb1af8d0f802cc49
# libsodium 1.0.20 (ISC), the release tarball checked against its SHA-256, for the Ed25519 signing comparison
if [ ! -f third_party/libsodium/.version ] || [ "$(cat third_party/libsodium/.version)" != 1.0.20 ]; then
  echo "libsodium: fetching 1.0.20"
  rm -rf third_party/libsodium third_party/libsodium.tgz
  curl -fsSL https://download.libsodium.org/libsodium/releases/libsodium-1.0.20.tar.gz -o third_party/libsodium.tgz
  got=$(if command -v sha256sum >/dev/null; then sha256sum third_party/libsodium.tgz; else shasum -a 256 third_party/libsodium.tgz; fi | cut -d' ' -f1)
  [ "$got" = ebb65ef6ca439333c2bb41a0c1990587288da07f6c7fd07cb3a18cc18d30ce19 ] || {
    echo "libsodium: SHA-256 mismatch ($got)" >&2
    rm -f third_party/libsodium.tgz
    exit 1
  }
  mkdir -p third_party/libsodium && tar -xzf third_party/libsodium.tgz -C third_party/libsodium --strip-components=1
  rm -f third_party/libsodium.tgz && echo 1.0.20 >third_party/libsodium/.version
else
  echo "libsodium: have 1.0.20"
fi
