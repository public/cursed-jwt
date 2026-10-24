#!/bin/sh
# fetch-vectors.sh: download the external HMAC-SHA256 / JWS test vectors into third_party/vectors (git-ignored),
# each checked against a pinned SHA-256. Sources:
#   RFC 4231   HMAC-SHA-256 test cases 1-7                         https://www.rfc-editor.org/rfc/rfc4231.txt
#   RFC 7515   Appendix A.1, the HS256 JWS example                 https://www.rfc-editor.org/rfc/rfc7515.txt
#   NIST CAVP  HMAC.rsp, [L=32] (HMAC-SHA-256, keys 40-70 bytes)  csrc.nist.gov hmactestvectors.zip
#   Wycheproof hmac_sha256_test.json (valid + invalid tags)        github.com/C2SP/wycheproof @ d17cc89
set -e
cd "$(dirname "$0")/.."
V=third_party/vectors; mkdir -p $V
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
get() {   # file url sha256
  if [ -f "$V/$1" ] && [ "$(sha "$V/$1")" = "$3" ]; then echo "$1: have it"; return; fi
  echo "$1: fetching $2"; curl -fsSL "$2" -o "$V/$1.tmp"
  got=$(sha "$V/$1.tmp"); [ "$got" = "$3" ] || { echo "$1: SHA-256 mismatch (got $got, want $3)" >&2; rm -f "$V/$1.tmp"; exit 1; }
  mv "$V/$1.tmp" "$V/$1"
}
get rfc4231.txt https://www.rfc-editor.org/rfc/rfc4231.txt 72178527ce93500e730bc8eb182b857e583096d652b64ece0879c52ba1df973b
get rfc7515.txt https://www.rfc-editor.org/rfc/rfc7515.txt ecbf84674118e62526511c1237e1deaa86aada86d25b247623a2a7e04ae62e40
get hmactestvectors.zip https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/hmactestvectors.zip 418c3837d38f249d6668146bd0090db24dd3c02d2e6797e3de33860a387ae4bd
get hmac_sha256_test.json https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/hmac_sha256_test.json 2d201cfa61d1bf95e6f5d07d96634b4a348b31e8eaa277ad7c8d09677b7a743f
