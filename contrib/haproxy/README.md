# HAProxy: jwt_verify through cursed-jwt

A patch for HAProxy 3.4.7. It runs the JWT converters on cursed-jwt: `jwt_verify`, `jwt_header_query` and
`jwt_payload_query`. They return the same result for every input, and HAProxy needs about **36–61% less CPU per
request** on a config that checks a bearer token on each request.

| file | |
|---|---|
| `haproxy-3.4.7.patch` | changes to `src/jwt.c`, `src/sample.c` and `include/haproxy/jwt-t.h`. New files: `include/haproxy/jwt_cursed.h`, and `src/jwt_cursed_test.c` (unit tests, built with `-DDEBUG_UNIT` only) |
| `jwt_cursed.c` | glue between HAProxy and cursed-jwt, compiled with the library. cursed-jwt's `jwt.h` and HAProxy's `haproxy/jwt.h` share the `jwt_` prefix, so no file includes both |
| `build.sh` | downloads the HAProxy 3.4.7 tarball (sha256-pinned), then builds `build/cursed/haproxy`, or `build/stock/haproxy` unpatched for comparisons |
| `test.sh` | stock vs cursed differential test, plus HAProxy's own `reg-tests/jwt` under VTest2 (pinned) |
| `gen_tokens.py` | keys and tokens for the tests, signed with pyca/cryptography |

## What changes

HAProxy's documented bearer-token setup chains several converters. Each one tokenizes the token again and
base64url-decodes the part it needs (here the payload is decoded three times):

```
http-request set-var(txn.bearer) http_auth_bearer
http-request set-var(txn.jwt_alg) var(txn.bearer),jwt_header_query('$.alg')
http-request deny unless { var(txn.jwt_alg) -m str "RS256" }
http-request deny unless { var(txn.bearer),jwt_payload_query('$.iss') -m str "https://login.example.test/realms/prod" }
http-request deny unless { var(txn.bearer),jwt_verify(txn.jwt_alg,"/etc/haproxy/pubkey.pem") -m int 1 }
http-request set-var(txn.jwt_exp) var(txn.bearer),jwt_payload_query('$.exp','int')
http-request deny if { var(txn.jwt_exp),sub(txn.now) -m int lt 0 }
```

The patch speeds up each step and leaves the configuration alone:

- **HS256:** the stock path calls OpenSSL 3's one-shot `HMAC()`. That fetches the digest, builds a MAC context and
  rehashes the key on every call. The patch instead uses cursed-jwt's HMAC with the key's ipad/opad midstates cached
  per thread. The cache is keyed on the secret's bytes, because `jwt_verify` receives the secret as a string on every
  call. One token is hashed by OpenSSL's own extracted SHA-256 block function (x86-64 Linux; scalar elsewhere).
- **RS256 / ES256:** when HAProxy loads the PEM key, the patch builds a cursed-jwt key next to the `EVP_PKEY`. It does
  this for RSA keys of 2048–4096 bits with odd e < 2^64, and for P-256 keys.
  - Verifying is then `jwt_pk_verify_raw`. There is no `EVP_MD_CTX` / `EVP_DigestVerifyInit` per call, and ES256 needs
    no R‖S-to-DER conversion.
  - ES256 uses per-key comb tables.
  - RSA-2048 uses s2n-bignum's verified Montgomery assembly; other RSA sizes use libcrypto's BN.
- **base64url:** cursed-jwt's SIMD decoder sits in front of `base64urldec()`. That covers the signature in
  `jwt_verify` and the header and payload in the two query converters.
- **jwt_tokenize:** the same scan, done with `memchr`.
- `jwt.cursed off` in the `global` section switches all of this off.

Nothing else moves. Tokenizing, alg parsing, key lookup, every status code and every error path stay in HAProxy's
`src/jwt.c`. Anything the fast paths don't take returns to the unchanged OpenSSL code, so the result is the same for
every input:
- an algorithm other than HS256, RS256 or ES256;
- an X.509 certificate as the key (`jwt_verify` with a cert);
- a key outside the sizes above, or an alg that doesn't match the key;
- a non-canonical signature length;
- a token over 8 KB;
- base64url input the fast decoder doesn't accept.

## Results

Intel Xeon Platinum 8260 (Cascade Lake), 1 vCPU, Ubuntu 24.04, kernel 6.8, gcc 13.3, OpenSSL 3.0.13. cursed-jwt
selects AVX-512VL. Both builds use the same compiler and flags. Measured with cursed-jwt `63bc323` (before PK became
part of the default build); `test.sh` checks this tree.

**Under load:** the config above with `nbthread 1`, and 50 keep-alive connections from a closed-loop load generator
on the same box. *CPU/req* is HAProxy's own utime+stime divided by the responses served; this is the number to trust.
req/s and p99 are measured too, but on one vCPU they include the load generator's share of the CPU. Two interleaved
rounds of 4 s each, after 1 s of warm-up; the rounds differed by under 2%. "Realistic" means OIDC-like claims of about
850 bytes (`iss`, `aud`, `sub`, `scope`, `email` and so on), and the iss and aud[0] checks are added.

| token | CPU/req stock → cursed | | req/s stock → cursed | p99 stock → cursed |
|---|---|---|---|---|
| HS256, small claims | 20.8 → 16.8 µs | **−19%** | 33.7k → 40.1k | 3.5 → 2.9 ms |
| HS256, realistic | 34.8 → 20.5 µs | **−41%** | 21.8k → 34.1k | 5.2 → 3.4 ms |
| RS256-2048, realistic | 61.5 → 39.2 µs | **−36%** | 13.4k → 20.0k | 8.4 → 5.5 ms |
| ES256, realistic | 123.2 → 48.6 µs | **−61%** | 7.2k → 16.6k | 14.8 → 6.8 ms |

**Per call:** `haproxy -U jwt-bench`, ns per call, best of 5.

| token | `jwt_verify` stock → cursed | crypto alone stock → cursed | stock base64url: signature / payload | cursed `jwt_payload_query('$.exp')` |
|---|---|---|---|---|
| HS256, small | 3149 → 847 | 2768 → 660 | 114 / 114 | 253 |
| HS256, realistic | 5395 → 2618 | 4526 → 2440 | 114 / 1860 | 663 |
| RS256-2048, realistic | 29527 → 18177 | 27925 → 17924 | 857 / 1855 | 648 |
| ES256, realistic | 85433 → 21316 | 83966 → 20873 | 228 / 1855 | 655 |
| RS256-4096, small | 78304 → 71414 | 75354 → 70744 | 1692 / 113 | 254 |

The stock `base64urldec()` decodes one byte at a time: it alone takes 1.86 µs for a realistic payload. A cursed
`jwt_payload_query` takes 0.65 µs in total, JSON lookup included. In the cursed build `jwt_tokenize` takes 17–29 ns.
RSA-4096 gains little, because libcrypto's BN does its arithmetic in both builds.

## Correctness

- **`haproxy -U jwt-diff`** runs both paths in the same binary; the stock side is the same call with
  `jwt_cursed_enabled = 0`. It compares `jwt_verify`'s status on every token from `gen_tokens.py` and on 300 random
  mutants of each, and decodes 100k random strings with both base64url decoders. **0 mismatches**: 22k token checks
  (200 mutants each) and 100k decodes on the Xeon, and 222k token checks and 1M decodes on x86-64 Docker. The tokens include adversarial cases:
  - forged signatures, and ES256 high-S, zero-padded and 66-byte signatures;
  - RS256 with a wrong or missing DigestInfo, and with e = 3;
  - RSA-1024 and P-384 keys;
  - a PEM path used as the HS256 secret, alg/key mismatches, and every signature length off by one.
- **HAProxy's regtests:** `reg-tests/jwt` passes with the patched binary (`test.sh`). A full run of HAProxy's regtests
  (x86-64 Docker) matches stock: everything that fails in parallel runs passes when run alone, in both builds, except `checks/extcheck.vtc`,
  which times out on stock too.

## Behaviour differences

None in results. There are a few in how results are reached:

- **base64url:** HAProxy's `base64urldec()` accepts `=` in the middle of a string (decoded as the value 64) and
  non-canonical trailing bits. The fast decoder rejects both, and those inputs go to `base64urldec()`, so the result
  doesn't change.
- **ES256 signature lengths:** OpenSSL accepts signatures longer than 64 bytes whose halves are zero-padded, through
  `BN_bin2bn`. Those go to OpenSSL as before; the fast path only takes 64-byte signatures.
- **HMAC secrets are cached per thread** (the last secret of up to 256 bytes) and aren't zeroized on reload. HAProxy
  keeps the same secret in its config strings anyway.
- **One token per call.** cursed-jwt's multi-buffer HMAC and its RSA batch screening need batches. A converter runs
  once per request, so they don't apply here.

## Build and test

Linux, or the repository's Docker image:

```bash
contrib/haproxy/build.sh
```

```bash
contrib/haproxy/test.sh
```

`build.sh stock` builds the unpatched release next to it. With `S2N=0`, the s2n-bignum assembly is left out. A
`-DDEBUG_UNIT` build (`UNIT=1`) also has `haproxy -U jwt-bench <tokens.txt>`.

To use the patch in your own HAProxy build:
1. Apply `haproxy-3.4.7.patch` with `patch -p1`.
2. Build `libcursedjwt-haproxy.a` the way `build.sh` does: cursed-jwt's `jwt.c` and `jwt_cursed.c`, plus s2n-bignum's
   objects if wanted.
3. Pass it in `ADDLIB` together with `-lcrypto`, and keep `USE_OPENSSL=1`.

## Licence

`haproxy-3.4.7.patch` modifies HAProxy, so it is under HAProxy's licence: GPL-2.0-or-later, and LGPL-2.1 for files
under `include/`. Everything else in this directory is under cursed-jwt's MIT licence. Linking cursed-jwt (MIT) and
s2n-bignum (Apache-2.0 / ISC / MIT-0) into HAProxy is compatible with HAProxy's GPL.
