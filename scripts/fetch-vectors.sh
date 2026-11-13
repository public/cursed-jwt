#!/bin/sh
# fetch-vectors.sh: download the external HMAC-SHA256 / JWS test vectors into third_party/vectors (git-ignored),
# each checked against a pinned SHA-256. Sources:
#   RFC 4231   HMAC-SHA-256 test cases 1-7                         https://www.rfc-editor.org/rfc/rfc4231.txt
#   RFC 7515   Appendix A.1, the HS256 JWS example                 https://www.rfc-editor.org/rfc/rfc7515.txt
#   NIST CAVP  HMAC.rsp, [L=32] (HMAC-SHA-256, keys 40-70 bytes)  csrc.nist.gov hmactestvectors.zip
#   Wycheproof hmac_sha256_test.json (valid + invalid tags)        github.com/C2SP/wycheproof @ d17cc89
# and, for RS256 / ES256 / EdDSA (make pk-test):
#   Wycheproof ecdsa_secp256r1_sha256_p1363, rsa_signature_{2048,3072,4096}_sha256   (same commit)
# and, for contrib/python (DER signatures, as pyca/cryptography takes them):
#   Wycheproof ecdsa_secp256r1_sha256_test.json                                       (same commit)
#   NIST CAVP  186-4ecdsatestvectors.zip SigVer.rsp [P-256,SHA-256]; 186-3rsatestvectors.zip SigVer15_186-3.rsp
#   Wycheproof ed25519_test.json; RFC 8032 section 7.1 (Ed25519 test vectors); RFC 8037 A.4 (the EdDSA JWS)
# and, for signing (make sign-test): RFC 6979 A.2.5 (deterministic ECDSA P-256)
set -e
cd "$(dirname "$0")/.."
V=third_party/vectors
mkdir -p $V
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
get() { # file url sha256
  if [ -f "$V/$1" ] && [ "$(sha "$V/$1")" = "$3" ]; then
    echo "$1: have it"
    return
  fi
  echo "$1: fetching $2"
  curl -fsSL "$2" -o "$V/$1.tmp"
  got=$(sha "$V/$1.tmp")
  [ "$got" = "$3" ] || {
    echo "$1: SHA-256 mismatch (got $got, want $3)" >&2
    rm -f "$V/$1.tmp"
    exit 1
  }
  mv "$V/$1.tmp" "$V/$1"
}
get rfc4231.txt https://www.rfc-editor.org/rfc/rfc4231.txt 72178527ce93500e730bc8eb182b857e583096d652b64ece0879c52ba1df973b
get rfc7515.txt https://www.rfc-editor.org/rfc/rfc7515.txt ecbf84674118e62526511c1237e1deaa86aada86d25b247623a2a7e04ae62e40
get hmactestvectors.zip https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/hmactestvectors.zip 418c3837d38f249d6668146bd0090db24dd3c02d2e6797e3de33860a387ae4bd
get hmac_sha256_test.json https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/hmac_sha256_test.json 2d201cfa61d1bf95e6f5d07d96634b4a348b31e8eaa277ad7c8d09677b7a743f
get ecdsa_secp256r1_sha256_p1363_test.json https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/ecdsa_secp256r1_sha256_p1363_test.json c60de693930e386c3a5472d08081623ef8504decc54b38ac01ec6b2a2575c986
get ecdsa_secp256r1_sha256_test.json https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/ecdsa_secp256r1_sha256_test.json 182db4f3e230f6f9fa9f800d2a614dede30284b8e8438bbfe1171905402e9332
get rsa_signature_2048_sha256_test.json https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/rsa_signature_2048_sha256_test.json 94a917b01ff50fb874cfc05bf29b4af44868d944a6558201cf18380da93fb393
get rsa_signature_3072_sha256_test.json https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/rsa_signature_3072_sha256_test.json 0f5f18cabfaad3e2792e82f7e9882f8999049b456714de924b8a5e202f61ca43
get rsa_signature_4096_sha256_test.json https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/rsa_signature_4096_sha256_test.json 957aca128e30bd02c8982f8ca482d6521d16683f4bbc3f193cdfd4c8f04bc667
get 186-4ecdsatestvectors.zip https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-4ecdsatestvectors.zip fe47cc92b4cee418236125c9ffbcd9bb01c8c34e74a4ba195d954bcb72824752
get 186-3rsatestvectors.zip https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-3rsatestvectors.zip 8405aeb3572a4f98ed4b1a3ccb3f2f49e725462dd28ec4759d6a15d88855d19c
get ed25519_test.json https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/ed25519_test.json ea80ffebac085e21cb9d3e903e7fa2b448d96702da5b31f061d0b83b430b74b3
get rfc8032.txt https://www.rfc-editor.org/rfc/rfc8032.txt ed63657ff389301282b169b0abde9b5dd2c7e4d524fdfa5da6ff3094fc93c4c3
get rfc8037.txt https://www.rfc-editor.org/rfc/rfc8037.txt f14347f9d8eead78ef6e7a1ea3d795d35d664033095a76a80fcd567904aaedaa
get rfc6979.txt https://www.rfc-editor.org/rfc/rfc6979.txt 456e8f17558fdbd206f968b96fc6f1b4a71ea331ab30ad17f711ab3adaa7d701
