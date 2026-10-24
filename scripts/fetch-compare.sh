#!/bin/sh
# fetch-compare.sh: the JWT libraries the comparison benchmark runs against, at pinned commits, into third_party/
# (git-ignored; each keeps its own licence):
#   jwt-cpp     Thalhammer/jwt-cpp @ 1e9b135   MIT (bundles picojson, BSD-2)   C++, OpenSSL + picojson
#   golang-jwt  golang-jwt/jwt v5 @ 9a618ef    MIT                             Go
set -e
cd "$(dirname "$0")/.."
mkdir -p third_party
fetch() {   # name owner/repo commit
  [ -f "third_party/$1/.commit" ] && [ "$(cat "third_party/$1/.commit")" = "$3" ] && { echo "$1: have $3"; return; }
  echo "$1: fetching $2 @ $3"
  rm -rf "third_party/$1" "third_party/$1.tmp"; mkdir -p "third_party/$1.tmp"
  curl -fsSL "https://codeload.github.com/$2/tar.gz/$3" | tar -xzf - -C "third_party/$1.tmp" --strip-components=1
  mv "third_party/$1.tmp" "third_party/$1"; echo "$3" > "third_party/$1/.commit"
}
fetch jwt-cpp Thalhammer/jwt-cpp 1e9b1354e1b70fce293277d01abdd02b0082b1de
fetch golang-jwt golang-jwt/jwt 9a618efd06fc5036c19970cdbb1af8d0f802cc49
