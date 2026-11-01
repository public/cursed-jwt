# Third-party credits

## Vendored code

- **OpenSSL `sha256_block_data_order` for x86-64**: `src/sha256_x86_64_ossl.S`.
  - Copyright 2005-2025 The OpenSSL Project Authors; written by Andy Polyakov. Apache License 2.0, full text in
    [licenses/OpenSSL-LICENSE.txt](licenses/OpenSSL-LICENSE.txt).
  - Generated from OpenSSL 3.6.0 (commit `7b371d8`) `crypto/sha/asm/sha512-x86_64.pl` by
    `scripts/extract-openssl-sha256.sh`, which fetches the perlasm sources pinned and SHA-256-checked.
  - **Modifications:**
    - symbols renamed: `sha256_block_data_order*` → `jwt_ossl_sha256_block*` (hidden), `OPENSSL_ia32cap_P` →
      `jwt_ossl_ia32cap_P`, the latter filled by `src/jwt.c` from CPUID;
    - a `.note.GNU-stack` section added;
    - nothing else.
  - Used on x86-64 Linux for HS256 batch 1 and the lanes left over by vector groups (`-DJWT_OSSL_SHA256`, set by the
    Makefile there).

## Credits

cursed-jwt credits these projects for techniques and data:

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
  Copyright the fiat-crypto authors): RS256/ES256/EdDSA (`src/jwt_pk.inc`, `src/jwt_ed25519.inc`) `#include` its
  generated, formally verified `p256_64.c`, `p256_scalar_64.c`, and for Ed25519 `curve25519_64.c` and
  `curve25519_scalar_64.c`. They are vendored in `src/fiat/` with fiat-crypto's `LICENSE-MIT`; `scripts/fetch-fiat.sh` re-fetches and checks them at a
  pinned commit and never committed. The P-256-specific `fe_mul` follows the reduction structure of OpenSSL's
  `ecp_nistz256` (Gueron and Krasnov); no code is copied.
- **s2n-bignum** (https://github.com/awslabs/s2n-bignum, Apache-2.0 OR ISC OR MIT-0, used under MIT-0, Copyright
  Amazon.com, Inc. or its affiliates): with `-DJWT_S2N`, the RS256/ES256 code links its formally verified assembly. That
  covers the P-256 field (`bignum_montmul_p256`, `bignum_montsqr_p256`, `bignum_add_p256`, `bignum_sub_p256`) and
  RSA-2048 (`bignum_kmul_32_64`, `bignum_ksqr_32_64`, `bignum_emontredc_8n`). It is fetched by
  `scripts/fetch-s2n-bignum.sh` at a pinned commit and never committed.
- **OpenSSL libcrypto** (Apache-2.0): with `-DJWT_OPENSSL`, the RS256/ES256 code calls `BN_mod_exp_mont` /
  `BN_mod_mul_montgomery` for RSA. That makes libcrypto a link dependency of that build, not just of the tests.
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
| `scripts/fetch-s2n-bignum.sh` | s2n-bignum P-256 and RSA-2048 kernels, arm and x86 (https://github.com/awslabs/s2n-bignum @ `3306729`) | MIT-0 (also Apache-2.0, ISC) | the `-DJWT_S2N` build |
| `scripts/fetch-fiat.sh` | fiat-crypto `p256_64.c`, `p256_scalar_64.c` (https://github.com/mit-plv/fiat-crypto @ `1e721c6`) | MIT (also Apache-2.0, BSD-1-Clause) | the `-DJWT_PK` build |
| `scripts/fetch-compare.sh` | jwt-cpp (https://github.com/Thalhammer/jwt-cpp @ `1e9b135`), bundles picojson | MIT, picojson BSD-2 | comparison benchmark |
| `scripts/fetch-compare.sh` | golang-jwt v5 (https://github.com/golang-jwt/jwt @ `9a618ef`) | MIT | comparison benchmark |

`tests/make_vectors.py` also uses **pyca/cryptography** (Apache-2.0 / BSD) as an independent HMAC reference. It
is installed from PyPI into `build/venv` when python3 doesn't already have it.
