# Third-party credits

cursed-jwt contains no vendored third-party code. It credits these projects for techniques and data:

- **simdjson** (https://github.com/simdjson/simdjson, dual-licensed Apache-2.0 / MIT, Copyright 2018-2025 The
  simdjson authors). The opt-in `-DJWT_FAST_JSON` payload path in `src/jwt.c` follows simdjson's stage-1 design:
  the 16-entry operator/whitespace shuffle tables, the prefix-XOR quote mask (carry-less multiply on x86) and the
  bitmask "flatten" loop. Used under the MIT option:

  > Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
  > documentation files (the "Software"), to deal in the Software without restriction, including without
  > limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
  > Software, and to permit persons to whom the Software is furnished to do so, subject to the following
  > conditions: The above copyright notice and this permission notice shall be included in all copies or
  > substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

- **cpuminer-opt** (https://github.com/JayDDee/cpuminer-opt): the idea of reusing the previous round's
  `a ^ b` in SHA-256's Maj, saving two vector ops per round. No code is copied.
- **Intel isa-l_crypto** and **OpenSSL's sha256-mb**: the multi-buffer SHA-256 lane layout is the classic
  design these established; the `vpternlogd` immediates (0x96, 0xCA, 0xE8) are the standard truth tables. No
  code is copied.

- **fiat-crypto** (https://github.com/mit-plv/fiat-crypto, MIT / Apache-2.0 / BSD-1-Clause, used under MIT,
  Copyright the fiat-crypto authors): the RS256/ES256 prototype (`-DJWT_PK`, `src/jwt_pk.inc`) `#include`s its
  generated, formally verified `p256_64.c` and `p256_scalar_64.c`. They are fetched by `scripts/fetch-fiat.sh` at a
  pinned commit and never committed. The P-256-specific `fe_mul` follows the reduction structure of OpenSSL's
  `ecp_nistz256` (Gueron and Krasnov); no code is copied.
- **RSA batch screening** (`-DJWT_RSA_SCREEN`) is Bellare, Garay and Rabin's "screening", from *Fast Batch
  Verification for Modular Exponentiation and Digital Signatures* (EUROCRYPT 1998).

Test and benchmark dependencies (not distributed): **OpenSSL** libcrypto (Apache-2.0) is the reference HMAC in
`tests/` and the baseline in `bench/`; the library itself does not use it.

## Fetched on demand (never committed) into `third_party/`

| script | what | licence | used for |
|---|---|---|---|
| `scripts/fetch-vectors.sh` | RFC 4231, RFC 7515 (IETF Trust; code components under the Revised BSD licence) | IETF | test vectors |
| `scripts/fetch-vectors.sh` | NIST CAVP `hmactestvectors.zip` | US government work, public domain | test vectors |
| `scripts/fetch-vectors.sh` | Wycheproof `hmac_sha256_test.json` (https://github.com/C2SP/wycheproof @ `d17cc89`) | Apache-2.0 | test vectors |
| `scripts/fetch-vectors.sh` | Wycheproof `ecdsa_secp256r1_sha256_p1363_test.json`, `rsa_signature_{2048,3072,4096}_sha256_test.json` (same commit) | Apache-2.0 | RS256/ES256 test vectors |
| `scripts/fetch-vectors.sh` | NIST CAVP `186-4ecdsatestvectors.zip` (SigVer), `186-3rsatestvectors.zip` (SigVer15) | US government work, public domain | RS256/ES256 test vectors |
| `scripts/fetch-fiat.sh` | fiat-crypto `p256_64.c`, `p256_scalar_64.c` (https://github.com/mit-plv/fiat-crypto @ `1e721c6`) | MIT (also Apache-2.0, BSD-1-Clause) | the `-DJWT_PK` build |
| `scripts/fetch-compare.sh` | jwt-cpp (https://github.com/Thalhammer/jwt-cpp @ `1e9b135`), bundles picojson | MIT, picojson BSD-2 | comparison benchmark |
| `scripts/fetch-compare.sh` | golang-jwt v5 (https://github.com/golang-jwt/jwt @ `9a618ef`) | MIT | comparison benchmark |

`tests/make_vectors.py` also uses **pyca/cryptography** (Apache-2.0 / BSD) as an independent HMAC reference. It
is installed from PyPI into `build/venv` when python3 doesn't already have it.
