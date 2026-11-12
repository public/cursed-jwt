# cursed-jwt

[![CodSpeed](https://img.shields.io/endpoint?url=https://codspeed.io/badge.json)](https://app.codspeed.io/public/cursed-jwt?utm_source=badge)

Batch JWT verification in C, and the crypto library underneath it, **cursed-crypto**, which works on its own. Most
JWT libraries verify one token per call. cursed-jwt verifies many per call, so the CPU's SIMD units and independent
instruction streams can work on several tokens at once:
- **HS256:** one multi-buffer HMAC-SHA256 pass, a token per vector lane or SHA-NI stream:
  - 4 interleaved SHA-NI streams on AMD Zen;
  - 16 lanes of zmm for larger batches on Zen 5, and on Intel AVX-512 CPUs without SHA-NI;
  - 8 lanes of AVX-512VL or AVX2 on other x86-64, and 4 interleaved SHA2 streams on ARMv8.
  A lone token runs OpenSSL's own single-stream SHA-256 code (x86-64 Linux) or one SHA2 stream (ARM).
- **RS256, ES256 and EdDSA (Ed25519):**
  - per-key precomputed tables;
  - verified or borrowed assembly kernels (s2n-bignum, OpenSSL's);
  - on AVX-512 IFMA CPUs, optionally, 8 tokens per call in 52-bit vector lanes.

  Design and numbers: [PK.md](PK.md).
- **The front end:** SIMD base64url (AVX2, AVX-512 VBMI, NEON) and a strict RFC 8259 JSON parser with a shape-matched
  fast path.
- **Signing** (HS256 and EdDSA): batched like verification, constant time in the private key (see
  [Signing](#signing)).

Every signature is recomputed on every call; only key material is kept (HMAC midstates, public-key tables). One binary
picks the best engine for the CPU it runs on.

**Why it exists.** HMAC-SHA256 is most of an HS256 verify, and one SHA-256 has no parallelism to spare. Independent
messages do. A server that already reads requests in batches (an io_uring or epoll loop handling many connections per
wakeup) can verify all their tokens together. On a Cascade Lake VM, one HMAC of a 570-byte signing input takes 1,684 ns
alone. At 16 per call it takes 247 ns per token.

**Status.** HS256, RS256, ES256 and EdDSA are complete and tested on x86-64 and AArch64, against independent
implementations and published vectors (see [Testing](#testing)).
- Keys are passed as their numbers; there's no JWKS parsing yet.
- There are no tagged releases yet; `main` is the current version.
- It has not had an external security review (see [Security](#security)).

## How fast

**Setup.** Single thread on Vultr VMs: AMD EPYC Turin (Zen 5), AMD EPYC Genoa (Zen 4) and Intel Xeon Cascade Lake.
gcc 13.3 `-O3`, no `-march`, OpenSSL 3.0.13, Ubuntu 24.04. Medians of 7 interleaved rounds, measured in November
2026. Every implementation had to accept all the tokens and reject a forged one before it was timed. The ratios are
the other implementation's time divided by ours, so above 1 means cursed-jwt is faster.

**Against JWT libraries:** whole-token verify (split, base64url, signature, JSON, claims) of 1,024 realistic
OIDC-style tokens. HS256 is also shown with compact ones. The ratio is to the fastest other library on that CPU and
algorithm, at our batch 1 / batch 16. The other libraries verify one token per call, so their time is the same at every
batch size.

| | Turin | Genoa | Cascade Lake | fastest other library |
|---|---|---|---|---|
| HS256, compact | 2.4× / 3.6× | 2.5× / 3.7× | 1.7× / 4.5× | zerojwt (Go) |
| HS256, realistic | 1.9× / 2.6× | 1.9× / 2.5× | 1.4× / 3.1× | zerojwt |
| RS256-2048 | 1.6× / 1.7× | 1.2× / 1.2× | 1.2× / 1.2× | jwt-simple (Rust, BoringSSL) |
| ES256 | 2.7× / 4.1× | 2.7× / 3.6× | 2.8× / 4.2× | jsonwebtoken (Rust, aws-lc-rs) |
| EdDSA | 3.1× / 4.3× | 4.0× / 5.5× | 3.4× / 4.1× | jsonwebtoken |

- **The other libraries:** jsonwebtoken 11.1.0 (aws-lc-rs), jwt-simple 0.15.0, golang-jwt v5.3.1, zerojwt v2.3.3,
  jwt-cpp, libjwt v3, cjose 0.8.1 and l8w8jwt 2.5.0.
- **cursed-jwt's build:** `-DJWT_S2N -DJWT_OPENSSL`, with the IFMA options off.
- **How the ratios were measured.** The other libraries were timed against an earlier cursed-jwt (`800fa54`) on one
  set of VMs. That commit was then timed against `main` on a second set, and the two same-VM ratios are multiplied.
- **cursed-jwt alone,** ns per token at batch 1 / 16:

| | Turin | Genoa | Cascade Lake |
|---|---|---|---|
| HS256, realistic | 680 / 511 | 691 / 493 | 2,516 / 1,131 (2,403 / 967 with `make JCC=1`) |
| RS256-2048 | 11,495 / 11,256 | 21,908 / 21,362 | 28,680 / 26,635 |
| ES256 | 17,415 / 11,457 | 20,960 / 15,532 | 26,207 / 17,952 |
| EdDSA | 10,025 / 7,283 | 10,728 / 8,057 | 16,529 / 13,194 |

- **The IFMA builds** add, in µs per token at batch 1 / 16:
  - `-DJWT_RSAZ` runs RS256 one or two tokens at a time on IFMA, on Zen 4 / Zen 5 and Intel Ice Lake or later;
  - `-DJWT_RSAZ8 -DJWT_ES8` run RS256 and ES256 8 tokens at a time, on Zen 4 / Zen 5 only.

  | | Turin | Genoa |
  |---|---|---|
  | RS256 | 6.6 / 2.9 | 6.3 / 4.5 |
  | ES256 at batch 16 | 4.3 | 5.0 |

**Against crypto libraries:** one operation at a time, on the same 570-byte signing inputs. The ratio is to the
fastest other library on that CPU, which is named.

| | Turin | Genoa | Cascade Lake |
|---|---|---|---|
| HMAC-SHA256 | 1.03× (AWS-LC) | 1.00× (AWS-LC) | 1.10× (OpenSSL) |
| RSA-2048 verify | 2.20× (AWS-LC) | 3.39× (AWS-LC) | 1.03× (AWS-LC) |
| ECDSA P-256 verify | 2.47× (AWS-LC) | 2.51× (AWS-LC) | 2.64× (AWS-LC) |
| Ed25519 verify | 2.95× (AWS-LC) | 2.89× (ed25519-dalek) | 2.83× (ed25519-dalek) |

- **The other libraries:** OpenSSL 3.0.13, AWS-LC 5.13.0, libsodium 1.0.22, Go 1.27's standard library, ring 0.17.14
  and ed25519-dalek 3.0.0, each through its fastest documented path (keys parsed once).
- **cursed-crypto's build:** `-DJWT_S2N -DJWT_OPENSSL -DJWT_RSAZ -DJWT_RSAZ8`.

**Against Intel ipsec-mb's multi-buffer HMAC-SHA256** (3.0.0, its 16-lane AVX-512 manager on all three CPUs).
ipsec-mb gets exactly N messages and a flush, the same job as our call with N. Ratios for N = 1 to 32:

| | Turin | Genoa | Cascade Lake |
|---|---|---|---|
| our default engine, N = 1–32 | 1.08–5.2× | 1.24–7.8× | 1.36–2.1× at N = 1–8 |
| … from N = 9 on Cascade Lake: the 16-lane x16 kernel | — | — | 1.20–1.27× at N = 11, 12, 16, 32 |
| ipsec-mb with all 1,024 messages queued (its best case) vs our batch 16 | 1.15× | 1.24× | 1.15× |

On Cascade Lake, 9 or more tokens run on the x16 kernel, at the cost of the zmm frequency licence (see
[Building](#building)). The x16 kernel wasn't measured at N = 9, 10 or 24.

**Is it the fastest?** Of everything we measured, on those three CPUs, yes, with four caveats:
- **One HMAC at a time ties AWS-LC.** The batch-1 path is OpenSSL's own SHA-256 code, and so is AWS-LC's; batching is
  where the gain comes from.
- **ES256 and EdDSA's lead depends partly on per-key tables:** about 530–570 KB and a few milliseconds of key setup per
  key. That's the right trade for a server that sees many tokens per key, and the wrong one for verifying under a
  fresh key each time.
- **Not everything was measured:** BoringSSL directly (jwt-simple builds on it), wolfSSL, Intel IPP, Apple's
  CommonCrypto, or GPU/FPGA offload. These are VMs, not bare metal, and the ARM numbers are older (see
  [Benchmarks](#benchmarks)).
- **The licence isn't only MIT.** cursed-jwt's own code is MIT, and every fast path is permissively licensed, but some
  of the fastest kernels are other projects' code under Apache-2.0 or BSD-3-Clause (see [Licence](#licence)).

## Proven, tested, or neither

- **Nothing in cursed-jwt's own code is formally verified.** It is tested: every engine against OpenSSL and against
  published vectors (RFC 4231, NIST CAVP, Wycheproof, RFC 7515/8032/8037), plus independently generated ones
  (pyca/cryptography, Python's `hmac`), an independent Python model of the claim rules (Hypothesis) and libFuzzer.
  The vectors are fetched at pinned versions and cross-checked against pyca/cryptography before use. Planted bugs
  are used to check that the tests can fail. Details: [Testing](#testing).
- **Formally verified code it can use:** the RS256/ES256/EdDSA code takes its P-256 and curve25519 field
  and scalar arithmetic from [fiat-crypto](https://github.com/mit-plv/fiat-crypto), whose generated C is proven
  correct in Coq upstream, and can use [s2n-bignum](https://github.com/awslabs/s2n-bignum)'s assembly, which is
  proven correct in HOL Light upstream. Those proofs are about the arithmetic, not about how cursed-jwt uses it, and
  neither is used by HS256.

## Quick start

```bash
git clone https://github.com/public/cursed-jwt.git && cd cursed-jwt
make                   # build/libcursedjwt.a, build/libcursedcrypto.a, build/verify; needs only a C compiler
make test              # every engine on this CPU vs OpenSSL and the claim rules (needs libcrypto and python3)
make example-check     # the example program accepts a generated token and rejects a tampered one
```

The tests need OpenSSL's libcrypto as the reference: on macOS `brew install openssl@3`, on Debian/Ubuntu
`apt install libssl-dev`. `make test-vectors` adds the external vectors (it downloads them).

## Contents

- [How fast](#how-fast)
- [Using it](#using-it)
- [Claim semantics](#claim-semantics)
- [Signing](#signing)
- [The crypto on its own](#the-crypto-on-its-own)
- [How it works](#how-it-works)
- [Building](#building)
- [Testing](#testing)
- [Benchmarks](#benchmarks)
- [Limits](#limits)
- [Security](#security)
- [Licence](#licence)

## Using it

```c
#include "jwt.h"            // link build/libcursedjwt.a (see Building to compile the sources yourself)

jwt_key_t key;
jwt_key_init(&key, secret, secret_len);          // once: HMAC ipad/opad midstates (any key length)

const char *tok[n]; int len[n];                  // the bytes after "Bearer ", not NUL-terminated
jwt_result_t out[n];
jwt_verify_batch(&key, n, tok, len, time(NULL), out);   // live iff nbf <= now < exp

// out[i].status: JWT_OK          -> out[i].uid (the integer in "sub"), out[i].username / .username_len
//                JWT_INVALID     -> malformed, wrong alg, bad signature, expired or not yet valid
//                JWT_BAD_PAYLOAD -> valid signature and time, but sub / username unusable
// out[i].username_escape == 0: the username bytes can go verbatim between JSON quotes
```

- **Lifetime of `username`.** `out[i].username` points into `out[i].ubuf`, so don't copy the struct and keep the
  pointer.
- **Stack and threads.** `jwt_verify_batch` uses about 17 KB of stack. It is thread-safe: no global state, and the
  key is read-only after init.
- **Lower-level entry points**, for your own claims or for benchmarks:
  - `jwt_hmac_*`: raw HMAC-SHA256 of n messages per engine;
  - `jwt_b64url_decode`: base64url decode;
  - `jwt_verify_batch_<engine>`: the full verify on a chosen engine.
- **A complete program:** `examples/verify.c`, built as `build/verify SECRET TOKEN...`.

**RS256 / ES256 / EdDSA** (built by default; `-DJWT_NO_PK` leaves them out; see [PK.md](PK.md)):

```c
jwt_pkey_t *pk = jwt_pkey_es256(x, y);      // or jwt_pkey_rs256(n, n_len, e, e_len), jwt_pkey_ed25519(pub32); NULL if invalid
jwt_verify_batch_pk(pk, n, tok, len, time(NULL), out);   // same results and claim rules
jwt_pkey_free(pk);
```

The key fixes the algorithm: a token's `alg` must equal it.

## Claim semantics

Checks run in this order: structure → header → signature (always) → payload JSON → time claims → `sub`/`username`.

| input | result |
|---|---|
| not exactly 3 segments, empty header/payload, signature ≠ 43 chars, non-base64url char, `=` padding, non-canonical trailing bits | INVALID |
| header not a JSON object, or `alg` missing, duplicated or not exactly `"HS256"` (escapes decoded first) | INVALID |
| bad MAC (compared in constant time over all 32 bytes) | INVALID |
| payload not strict RFC 8259 JSON (no trailing commas or raw control chars, valid UTF-8, nesting ≤ 32), or not an object | INVALID |
| `exp` missing, not a number, or `exp <= now` (floats OK) | INVALID |
| `nbf` present and (not a number, or `nbf > now`) | INVALID |
| a duplicate `sub`/`username`/`exp`/`nbf` key | INVALID |
| `sub` not a string of ASCII digits with value 1..2^63−1 (leading zeros allowed) | BAD_PAYLOAD |
| `username` missing, not a string, or longer than `JWT_USERNAME_MAX` (255) bytes decoded | BAD_PAYLOAD |
| `iat` and unknown claims | ignored (must still be valid JSON) |
| token longer than `JWT_TOKEN_MAX` (8192) | INVALID |

Other details:
- keys are compared after unescaping;
- a lone surrogate escape in `username` decodes to U+FFFD;
- `now` is whole seconds.

The claim profile (`sub` as a numeric user id, `username` as a string) is built in. For other claims, use `jwt_hmac_*`
and the JSON parser in `src/jwt.c` as building blocks.

For RS256/ES256/EdDSA the signature length is 342 (RSA-2048) or 86 (ES256, EdDSA) characters instead of 43. `alg` must name the
key's algorithm; the rest is identical.

## Signing

HS256 and EdDSA (Ed25519) tokens are issued in batches too, under one key per call. The caller owns the output
buffers.

```c
jwt_key_t key;
jwt_key_init(&key, secret, secret_len);                   // the same key type as verification

const char *claims[n]; int claims_len[n];                 // the payloads, as JSON bytes
char *out[n]; int out_len[n];                             // out[i]: room for jwt_sign_size(claims_len[i]) bytes
int issued = jwt_sign_batch(&key, n, claims, claims_len, out, out_len);
// out[i] = {"alg":"HS256","typ":"JWT"}.<claims>.<MAC>, NUL-terminated; out_len[i] = its length, or -1 if refused

jwt_skey_t *sk = jwt_skey_ed25519(seed32);                // the 32-byte private key (an OKP JWK's "d")
uint8_t pub[32];
jwt_skey_public(sk, pub);                                 // for jwt_pkey_ed25519 / the JWK's "x"
jwt_sign_batch_pk(sk, n, claims, claims_len, out, out_len);   // {"alg":"EdDSA","typ":"JWT"}, room: jwt_sign_size_pk
jwt_skey_free(sk);                                        // wipes the key
```

- **The header** is the canonical `{"alg":"HS256","typ":"JWT"}` or `{"alg":"EdDSA","typ":"JWT"}`, the one the
  verifier recognises without decoding it.
- **The claims are the caller's bytes, used exactly as given**: nothing is added, removed or reordered. They are
  checked first, so that the library never issues a token its own verifier would reject for its form:
  - one strict RFC 8259 JSON object (valid UTF-8, nesting ≤ 32, nothing after it but whitespace);
  - `exp` present; `exp` and `nbf` JSON numbers when present;
  - no repeated `sub`, `username`, `exp` or `nbf` (keys compared after unescaping);
  - the whole token at most `JWT_TOKEN_MAX` (8192) bytes.

  A refused payload gets `out_len[i] = -1`, and nothing is written to its `out[i]` (which may be NULL); the rest of
  the batch is unaffected.
- **Not checked:** the `sub` / `username` profile (a token without them is issued, and the verifier returns
  `JWT_BAD_PAYLOAD` for it), and the clock (an `exp` in the past is issued, and rejected by the verifier).
- **Ed25519 is deterministic** (RFC 8032): no random numbers, and the same key and claims give the same token. The
  public key is derived from the private key, never taken from the caller.
- **Timing contract: signing is constant time in the private key.** No branch or memory address depends on the HMAC
  key, the Ed25519 private key, its expanded scalar and nonce prefix, or the per-signature nonce (checked by valgrind
  and trace equivalence), and by design only integer additions, multiplications, shifts and logic touch them: no
  division and no table indexed by a secret. Variable-latency instructions are not checked mechanically; dudect on
  three x86 CPUs found no timing difference. HS256 runs on the same constant-time HMAC engines as verification. Ed25519 signing is a path of
  its own that shares no code with the (variable-time) verifier beyond fiat-crypto's field and scalar arithmetic and
  SHA-512: a fixed-base multiplication that reads its table only through constant-time selects, complete addition
  formulas, a fixed inversion chain, and scalar reduction in fiat's Montgomery arithmetic. The MAC and signature go
  through a branch-free, table-free base64url encoder. What checks it is under [Constant time](#constant-time).
- **Batching.** HS256 signing goes through the multi-buffer HMAC, so a batch gets verification's speed-up. An Ed25519
  batch shares one field inversion (Montgomery's trick).
- **Cost of an Ed25519 key:** about 30 KB (a table of multiples of the base point) and 82–115 µs to set up.

**Measured** (`make bench-sign`, `make compare-sign`; Vultr VMs, Ubuntu 24.04, gcc 13.3, OpenSSL 3.0.13; the claims
set `{"sub":"123456","username":"alice","iat":1700000000,"exp":4102444800}`; ns per token, batch 1, batch 16 in
brackets):

| | AMD EPYC Turin (Zen 5) | AMD EPYC Genoa (Zen 4) | Intel Xeon Cascade Lake |
|---|---:|---:|---:|
| **HS256** cursed-jwt `jwt_sign_batch`, whole token | **238** (153) | **247** (169) | **835** (275) |
| OpenSSL `EVP_MAC`, key set once: the MAC alone | 255 | 252 | 862 |
| jsonwebtoken 9.3 (Rust) `encode` | 551 | 559 | 1,550 |
| jwt-cpp `create().sign()` | 2,666 | 2,946 | 5,224 |
| golang-jwt v5 `SignedString` | 2,816 | 3,402 | 5,877 |
| PyJWT 2.9 `jwt.encode` | 7,069 | 7,796 | 12,700 |
| **EdDSA** cursed-jwt `jwt_sign_batch_pk`, whole token | **13,874** (11,200) | **16,227** (13,571) | **20,684** (17,187) |
| Go `crypto/ed25519` `Sign`: the signature alone | 17,088 | 20,873 | 26,998 |
| golang-jwt v5 `SignedString` | 19,841 | 23,404 | 32,273 |
| pyca/cryptography `sign`: the signature alone | 22,378 | 30,138 | 37,301 |
| ring 0.17 `sign`: the signature alone | 22,886 | 33,104 | 45,546 |
| OpenSSL `EVP_DigestSign`: the signature alone | 27,048 | 36,196 | 47,108 |
| PyJWT 2.9 `jwt.encode` | 28,496 | 37,716 | 49,375 |
| jwt-cpp `create().sign()` | 29,478 | 39,276 | 51,302 |
| jsonwebtoken 9.3 (Rust) `encode` | 46,050 | 67,096 | 90,798 |

The other libraries serialise the claims themselves; cursed-jwt takes the JSON bytes and checks them. A batch of 16 HS256
tokens costs 33–68% of 16 single calls per token: that is the multi-buffer HMAC. An Ed25519 batch shares one
inversion per 16 signatures, worth 16–19%.

## The crypto on its own

The SHA-256 / HMAC engines, the CPU dispatch and RS256 / ES256 / Ed25519 verification are a library of their own,
cursed-crypto, in `crypto/`, with its own header (`crypto/include/cursed_crypto.h`, prefix `cc_`) and
`build/libcursedcrypto.a`. The JWT layer (base64url, JSON, claims, the token front ends) only calls it.

```c
#include "cursed_crypto.h"     // link build/libcursedcrypto.a

cc_hmac_key_t k;
cc_hmac_key_init(&k, secret, secret_len);           // constant time in the key
uint8_t mac[16][32], ok[16];
cc_hmac_sha256_bytes(&k, n, msgs, lens, mac);        // n messages, one batched pass on the best engine
int good = cc_hmac_sha256_verify(&k, n, msgs, lens, (const uint8_t (*)[32])tags, ok); // constant-time compare

cc_pkey_t *pk = cc_pkey_es256(x, y);                  // or cc_pkey_rs256 / cc_pkey_ed25519; per-key tables
cc_verify_batch(pk, n, msgs, lens, sigs, sig_lens, ok); // raw signatures, hashed inside, batched
cc_pkey_free(pk);

cc_skey_t *sk = cc_skey_ed25519(seed32);              // signing: constant time in the private key
cc_sign_batch(sk, n, msgs, lens, sigs);               // sigs[i]: 64 bytes, R || S
cc_skey_free(sk);
cc_sha512(data, len, digest64);                       // and cc_sha512_init / _update / _final
```

- **Timing contract.** Everything that touches an HMAC key (key setup, every engine, `cc_tag_eq32`,
  `cc_hmac_sha256_verify`) is constant time, and so are signing (`cc_skey_ed25519`, `cc_sign_batch`, `cc_skey_free`)
  and SHA-512, all checked by `make test-ct`, `test-ct-sde` and `test-ct-qemu`. Signature verification is variable
  time: all of its inputs are public, as in every other library's verify.
- **No speed lost by the split.** Calls cross the boundary once per batch, not per block or field operation, and the
  HS256 front end calls the dispatched engine through the same pointer either way. `src/jwt.c` still `#include`s
  `crypto/src/cursed_crypto.c`, so building `src/jwt.c` alone gives one translation unit, exactly as before;
  `-DJWT_EXTERNAL_CRYPTO` builds the JWT layer alone, as `build/libcursedjwt.a` does.
- **cursed-jwt's names stay.** `jwt_key_t`, `jwt_key_init`, `jwt_hmac_*`, `jwt_sha256_*`, `JWT_CPU_*`,
  `jwt_cpu_features` and `jwt_engine` are the cursed-crypto ones under their old names. They belong to the JWT layer
  (`jwt.h`): aliases in the one-unit build on ELF, one-line wrappers in `libcursedjwt.a` and elsewhere.
  `libcursedcrypto.a` exports only `cc_*` names (`make check-symbols`). `CC_CPU_MASK` / `CC_CPU_FORCE_ZMM` and the
  `JWT_` spellings both work, and so do both spellings of the build flags (`-DCC_S2N` or `-DJWT_S2N`, and so on).

## How it works

- **Multi-buffer HMAC.**
  - One SHA-256 "template" (`crypto/src/cc_mb.inc`) is instantiated per ISA. One vector register holds the same state
    word of 8 (x86) or 4 (NEON) messages, so 8 tokens hash in roughly the time of 1.
  - HMAC plans give each message `ceil((L+9)/64)` blocks after the ipad midstate. Only the 1–2 tail blocks are
    copied; full blocks are read in place.
  - Plans are sorted by block count, so vectors are almost never ragged. When they are, a finished lane keeps its
    state through a mask select.
  - The outer hash never leaves registers: the inner digest becomes W0..7 directly.
- **AVX-512: ymm or zmm, depending on the CPU.**
  - `vprord` does the rotates; `vpternlogd` does the three-input functions (0x96 xor3, 0xCA Ch and the lane select,
    0xE8 Maj).
  - On Intel, a zmm burst lowers the core's frequency licence: the scalar code after it runs 16–19% slower for 0.5–1
    ms (`make licence`). ymm costs nothing. So Intel uses 8 lanes of ymm for small batches. It switches to the 16-lane
    zmm kernel (`x16`) from 9 tokens on CPUs without SHA-NI, where only zmm reaches ipsec-mb's speed. Masking
    `JWT_CPU_ZMM_HMAC` keeps it on ymm.
  - AMD Zen 4 / Zen 5 have no licence drop, so zmm is used freely there:
    - on both, as the 16-lane engine when SHA-NI is masked;
    - on Zen 5 server and desktop parts, for groups of 11 or more beside the SHA-NI streams.

    See [Building](#building).
- **ARM uses the SHA2 instructions, interleaved.** NEON multi-buffer is 2.9× slower than one stream of `sha256h`.
  Interleaving 4 independent streams hides the instruction latency (−15%).
- **The engine is picked at run time.** Each SIMD engine is compiled in its own target region, and the CPU's
  features (CPUID / HWCAP) choose among them, so one binary runs anywhere and uses what the machine has.
  - The AVX-512 region also tells the compiler to prefer 256-bit vectors. Otherwise it auto-vectorises copies with
    zmm, and the frequency-licence drop makes everything 29% slower.
- **One token at a time uses the best single-stream code there is.**
  - A lone token, and any lanes left over when a group is too small for a vector, can't use 8-way parallelism.
  - On x86-64 Linux they run OpenSSL's `sha256_block_data_order`, extracted and vendored as
    `crypto/src/sha256_x86_64_ossl.S`. It picks SHA-NI, AVX2+BMI2, AVX, SSSE3 or plain x86-64 code at run time.
  - On the Xeon it is 25% faster than the compiled template (752 vs 1,007 ns per HMAC).
- **Front end:**
  - base64url uses `vld4q` + `vqtbl4q` on NEON, and range compares + `maddubs`/`pshufb` packing on AVX2;
  - a shape matcher recognises the common compact payload `{"sub":"…","username":"…","iat":N,"exp":N}` in 37 ns,
    and falls back to the strict parser (131 ns) for anything else;
  - SWAR integer parsing;
  - `exp`/`nbf` are compared with `now` by digit count, then bytewise, with no number conversion.
- **Identical results either way.** The shape matcher defers to the strict parser on anything unusual. The tests
  fuzz it against the strict parser.
- **RS256 / ES256 / EdDSA:**
  - **ES256 and EdDSA** precompute comb tables for the public key at key setup, so a verify is two fixed-base
    multiplications. With `-DJWT_S2N` the field arithmetic is s2n-bignum's formally verified assembly, including its
    ADX-free versions for CPUs (and VMs) that hide ADX. Without it, it's fiat-crypto's verified C.
  - **RS256** uses s2n-bignum where it can run (RSA-2048 with BMI2 + ADX). Otherwise it uses OpenSSL's `bn_mul_mont`
    (x86-64 Linux), extracted and called directly, or portable C. RS256 can also check a whole batch with one exponentiation ("screening"), opt-in
    because of a caveat.
  - **On AVX-512 IFMA CPUs (opt-in builds):** RS256 runs one or two tokens at a time in OpenSSL's 52-bit IFMA multiply
    (`-DJWT_RSAZ`). On Zen 4 / Zen 5, 8 tokens at a time go through Intel crypto_mb's 8-lane exponentiation
    (`-DJWT_RSAZ8`) and its 8-lane P-256 field under our comb tables (`-DJWT_ES8`). EdDSA's comb additions run on
    Firedancer's 4-way IFMA field there (with `-DJWT_S2N`).
  - [PK.md](PK.md) has the design, the survey of other implementations and the per-build numbers.

## Building

The library needs only a C compiler, and no `-march`. `make` builds `build/libcursedjwt.a`, `build/libcursedcrypto.a`
and `build/verify`. `libcursedjwt.a` carries the cursed-crypto objects too, so linking it alone still works; to compile
the sources into your own build, compile `src/jwt.c` (one unit) or `crypto/src/cursed_crypto.c` (the crypto alone).

**One binary runs on any CPU of its architecture.**
- **What's in it.** It is compiled for the baseline ISA (x86-64, ARMv8-A) and carries every engine that
  architecture can have, each compiled in its own target region.
- **How it chooses.** At start-up it reads CPUID and XGETBV (x86) or HWCAP / sysctl (ARM), then uses the best engine
  the machine has. Each feature that's missing degrades it one step:

| CPU | HS256 engine | RS256 / ES256 kernels (`-DJWT_PK`) |
|---|---|---|
| AMD Zen 5 server / desktop (Turin, Granite Ridge) | 16 lanes of zmm (asm) for groups of 11+ tokens, 4 SHA-NI streams for the rest | as the rows below |
| AMD with SHA-NI (every Zen) | 4 interleaved SHA-NI streams (hand-scheduled asm on x86-64 Linux) | as the rows below |
| AMD Zen 4 / Zen 5 (family ≥ 0x19) with AVX-512, SHA-NI masked | zmm, 16 lanes (no frequency-licence drop on AMD) | + IFMA if built with it: RS256 1, 2 or 8 tokens per call, ES256 8, EdDSA's 4-way field |
| Intel with AVX-512 F/VL/BW/DQ/CD and no SHA-NI (Skylake-SP, Cascade Lake, Cooper Lake) | groups of 9+ on zmm (x16), the rest AVX-512VL on ymm, 8 lanes | s2n-bignum (ADX-free versions where ADX is hidden) or OpenSSL's `bn_mul_mont` |
| x86-64 with AVX2 + BMI2 | AVX2, 8 lanes | s2n-bignum asm (`-DJWT_S2N`; RSA-2048 needs BMI2 + ADX), else OpenSSL's `bn_mul_mont` on Linux |
| other x86-64 | scalar | portable C |
| AArch64 with SHA2 instructions | 4 interleaved SHA2 streams | s2n-bignum / libcrypto |
| other AArch64 | NEON, 4 lanes | portable C |
| anything else | scalar | portable C |

- **Single tokens.** On AMD they run one SHA-NI stream of the same engine. On other x86-64 Linux they run OpenSSL's
  extracted SHA-256 code, which dispatches itself (SHA-NI, AVX2+BMI2, AVX, SSSE3, plain x86-64). The Makefile
  assembles `crypto/src/sha256_x86_64_ossl.S` and defines `JWT_OSSL_SHA256`. If you compile `src/jwt.c` into your own
  program, do the same, or leave both out to get the compiled scalar code; `make OSSL_SHA=` builds without it.
- **Intel Skylake through Cascade Lake / Cooper Lake: `make JCC=1`.** Intel's microcode fix for the JCC erratum
  stalls any branch that crosses or ends on a 32-byte boundary. `JCC=1` has the assembler keep every branch off one
  (`-Wa,-mbranches-within-32B-boundaries` with gcc, `-mbranches-within-32B-boundaries` with clang), in the C and the
  assembly alike. Measured on main 63e076d, as a ratio to the default build (below 1 is faster; 15 interleaved rounds,
  and a 48-byte placement shift of the default build as the noise control):

  | | HS256 realistic b16 | HS256 realistic b1 | HS256 compact b16 | RS256 / ES256 / EdDSA | raw HMAC, b1–32 | placement control |
  |---|---|---|---|---|---|---|
  | Cascade Lake | **0.83** | **0.96** | **0.95** | 0.98–1.01 | 0.99–1.01 | 0.99–1.01 |
  | AMD Genoa (Zen 4) | 1.07 | 1.04 | 1.00 | 1.00–1.01 | 0.99–1.01 | 0.96–1.01 |
  | AMD Turin (Zen 5) | 1.03 | 1.02 | 1.02 | 1.00–1.01 | 1.00 | 0.98–1.00 |

  The gain and the loss are both in the token front end's JSON code; the crypto doesn't move. A build that has to
  run anywhere keeps the default. Use `JCC=1` when the binary is for those Intel generations only. Ice Lake and later,
  and AMD, don't have the erratum.
- **Inspecting and masking the choice.** `jwt_engine()` names the HS256 engine in use, and `jwt_cpu_features()`
  returns the detected `JWT_CPU_*` bits. The environment variable `JWT_CPU_MASK` masks features for tests and
  benchmarks: `JWT_CPU_MASK=0` runs everything on the fallbacks.
- **AMD.** `JWT_CPU_FAST_SHANI` is set for AMD CPUs with SHA-NI (every Zen) and selects the 4-stream SHA-NI
  engine. On Zen 3 (EPYC Milan) it beats every vector engine at every batch size. Intel CPUs with SHA-NI (Ice Lake
  and later) haven't been timed, so they keep the vector engines; `jwt_hmac_shani_4r` (or `jwt_hmac_shani_4`) can be
  called directly there.
  - On x86-64 Linux the 4 streams run `crypto/src/sha256_shani_mb.S`, generated by `scripts/gen-shani-mb.py`
    (`-DJWT_SHANI_MB`, set by the Makefile with `JWT_OSSL_SHA256`; link the `.S` too). It keeps every stream's state
    in registers, which the compiled engine (`jwt_hmac_shani_4`, used elsewhere) can't: 16 xmm registers are too few
    for 4 states and 4 message schedules, and the compiler spills the state. Raw HMAC of 570-byte messages at batch
    16: 180 vs 195 ns on Genoa, 196 vs 216 ns on Turin.
- **Zen 4/5.** `JWT_CPU_FAST_ZMM` is set for AMD family ≥ 0x19 with AVX-512, and selects the 16-lane zmm engine
  when SHA-NI is masked off.
- **The zmm engine in assembly.** On x86-64 Linux (`-DJWT_SHANI_MB`) the 16-lane engine is `jwt_hmac_x16`,
  `crypto/src/sha256_x16_avx512.S`: a GAS port, generated by `scripts/gen-sha256-x16.py`, of Intel ipsec-mb's
  `sha256_x16_avx512` (BSD-3-Clause, see THIRD_PARTY.md). It keeps the message schedule in zmm16–31, loads the next
  block during the last 16 rounds, and transposes with 32 `vshufps` + 16 `vpermi2q`. Raw HMAC of 570-byte messages at
  batch 16: Turin 128 ns (the compiled zmm engine 160, ipsec-mb's multi-buffer manager 147), Cascade Lake 252 (284,
  293), Genoa 198 (224, 238; SHA-NI is faster there).
- **Zen 5.** `JWT_CPU_FULL_ZMM` is set for family 1Ah models 00h–1Fh and 40h–4Fh, which execute 512-bit ops at full
  width; SHA-NI there keeps only 2 `sha256rnds2` in flight. `jwt_hmac_shani_x16` sends each group of 11 to 16 tokens to
  `jwt_hmac_x16` and the rest to the 4 SHA-NI streams.
- **Intel AVX-512 without SHA-NI** (`JWT_CPU_ZMM_HMAC`): groups of 9 or more tokens run on `jwt_hmac_x16`, as Intel
  ipsec-mb runs its own 16-lane kernel on these CPUs; the 8-lane ymm engine there loses to ipsec-mb at 10–16 tokens.
  Raw HMAC of 570-byte messages on Cascade Lake, ns per message, against ipsec-mb given exactly N jobs: 345 vs 415 at
  11, 322 vs 390 at 12, 247 vs 315 at 16 (ymm: 500, 463, 351). The cost is zmm's frequency licence: scalar code right
  after it runs 16% slower for 0.5–1 ms (`make licence`), and a full `jwt_verify_batch` at batch 16 measured 1,088 ns
  against 1,067 on ymm. Masking `JWT_CPU_ZMM_HMAC` (bit 2048) in `JWT_CPU_MASK` keeps HS256 on ymm. Intel's SHA-NI
  parts (Ice Lake and later) haven't been measured and keep AVX-512VL on ymm.
- **Speed of the dispatching build.** On the Xeon its HMAC matches a `-march=cascadelake` build. Full verify is
  within 2% with clang and 7% with gcc, because the front end is compiled for baseline x86-64.
  `ARCHFLAGS=-march=native` still works, and dispatch still checks the CPU.
- **Engine-specific functions** are exported for tests and benchmarks; call one only if `jwt_cpu_features()` has
  its bit.

**Options:**

| flag | effect |
|---|---|
| `-DJWT_INPUT_PADDED` | every token has ≥ 64 readable bytes after it, which allows fixed-size tail loads |
| `-DJWT_NO_SHAPE_JSON` | strict parser only |
| `JWT_USERNAME_MAX`, `JWT_TOKEN_MAX` | size limits |
| `-DJWT_NO_PK` | leave out RS256 / ES256 / EdDSA (they're built by default, from fiat-crypto's arithmetic vendored in `crypto/src/fiat/`) |
| `-DJWT_S2N` | s2n-bignum's formally verified asm kernels for P-256, Ed25519 and RSA-2048 (`scripts/fetch-s2n-bignum.sh`). On x86, its ADX-free P-256 / Ed25519 versions run where BMI2 + ADX are missing; RSA-2048 then uses `bn_mul_mont` |
| `-DJWT_OPENSSL` | libcrypto's bignum asm for RSA (links `-lcrypto`) |
| `-DJWT_RSA_SCREEN` | RSA batch screening (read the caveat in [PK.md](PK.md) first) |
| `-DJWT_RSAZ` | RS256-2048 on AVX-512 IFMA (Zen 4 / Zen 5, Intel Ice Lake and later): OpenSSL's 52-bit multiply, one or two tokens per call (`scripts/fetch-ossl-rsaz.sh`, x86-64 Linux) |
| `-DJWT_RSAZ8` | with `-DJWT_RSAZ`: 8 RS256 tokens per call through crypto_mb's 8-lane exponentiation, on Zen 4 / Zen 5 (`scripts/fetch-crypto-mb-rsa.sh`) |
| `-DJWT_ES8` | 8 ES256 tokens per call on crypto_mb's 8-lane P-256 field under our comb tables, on Zen 4 / Zen 5 |
| `-DJWT_CRYPTO_MB` | Intel crypto_mb's own 8-way ES256 / RSA API (`scripts/build-crypto-mb.sh`, which needs OpenSSL ≥ 3.5.5 headers). Kept for comparison: `-DJWT_RSAZ8` / `-DJWT_ES8` are the measured paths |
| `make OSSL_SHA=` | build without the x86-64 Linux assembly (OpenSSL's SHA-256 and `bn_mul_mont` extracts, the generated 4-stream SHA-NI and 16-lane zmm kernels); the compiled engines stay |
| `make JCC=1` | keep branches off 32-byte boundaries (Intel's JCC erratum): for builds that run only on Intel Skylake through Cascade Lake / Cooper Lake |

**Targets:**

```bash
make              # build/libcursedjwt.a, build/libcursedcrypto.a, build/verify (JCC=1: Intel Skylake..Cascade Lake builds)
make test         # every engine vs OpenSSL + the claim rules (~6 s)
make test-quick   # fewer random iterations (CI)
make test-vectors # + RFC 4231, NIST CAVP, Wycheproof, RFC 7515, pyca/cryptography vectors (network)
make test-hypothesis # property-based tests vs an independent Python model (Hypothesis; network for the venv)
make fuzz-smoke   # fuzz harnesses replaying their corpora under ASan + UBSan (seconds); `make fuzz` = libFuzzer
make asan         # ASan + UBSan
make bench        # ns/token per engine and batch size, vs OpenSSL
make compare      # full verify vs jwt-cpp and golang-jwt, fetched at pinned commits (network; go optional)
make avx512       # AVX-512VL test + bench binaries (run them on AVX-512 hardware)
make licence      # AVX-512 frequency-licence probe (AVX-512 hardware)
make pk-test      # RS256 / ES256 / EdDSA: portable C builds vs Wycheproof, NIST CAVP, RFC 7515/8032/8037, pyca (network)
make pk-test-fast # RS256 / ES256 with the s2n-bignum + libcrypto kernels
make pk-bench pk-bench-fast   # RS256 / ES256 / EdDSA ns/token vs OpenSSL, with and without batch screening
make pk-test-ifma pk-bench-ifma   # + crypto_mb (needs scripts/build-crypto-mb.sh; an IFMA CPU to exercise it)
```

- **Test dependencies.** The tests need OpenSSL's libcrypto (the reference) and python3: on macOS, Homebrew's
  `openssl@3`; on Linux, `libssl-dev`.
- **Linux in Docker.** `./scripts/docker-test.sh amd64` (or `arm64`) runs the tests on Ubuntu 24.04 with gcc and
  clang. `DOCKER_CPUS=8-13` pins the container to those CPUs.

## Testing

Every engine is tested against independent implementations and published vectors, never only against itself.
`make test` / `test-quick` use only local generators. `make test-vectors` and `make pk-test` add the external
vectors, which `scripts/fetch-vectors.sh` downloads and checks against pinned SHA-256s (they are never committed).
- **Each vector is cross-checked against pyca/cryptography before use**, by `tests/make_vectors.py` and
  `tests/make_pk_vectors.py`. A misparsed vector therefore fails the build, rather than testing nothing.
- **A planted error has to make a run fail.** Flipping one expected result fails it, and so does an always-accept
  planted in one lane.

### HS256

| source | what | cases | origin, licence |
|---|---|---|---|
| RFC 4231 | HMAC-SHA-256 test cases 1–7, incl. a truncated tag and keys longer than a block | 7 | [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc4231), IETF Trust |
| NIST CAVP `HMAC.rsp`, `[L=32]` | keys of 40–70 bytes, tags of 16–32 bytes | 225 | [CAVP `hmactestvectors.zip`](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program), US government work |
| Wycheproof `hmac_sha256_test.json` | valid tags and invalid ones that must be rejected | 174 | [C2SP/wycheproof](https://github.com/C2SP/wycheproof) @ `d17cc89`, Apache-2.0 |
| RFC 7515 A.1 | the HS256 JWS: BAD_PAYLOAD while live (no `sub`/`username`), INVALID once expired, INVALID with a signature character changed | 3 | [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc7515), IETF Trust |
| pyca/cryptography, random | keys of 0–200 bytes, messages of 0–1,100 bytes, 10% corrupted tags | 5,000 | generated by `tests/make_vectors.py` |
| Python `hmac`, tokens | full JWTs minted by `tests/gen_tokens.py` with an independent HS256 implementation, verified at batch sizes 1–100 | 20,000 | generated |
| OpenSSL `HMAC()`, differential | random batches of 1–70 messages of 0–699 bytes (ragged lanes, 1-vs-2 tail blocks) | 3,000 batches | `tests/test_jwt.c` |
| crafted tokens | exact expected status, uid, username and escape flag, at every batch size 1–123 (list below) | 123 | `tests/test_jwt.c` |
| strict parser, differential | fuzzed payloads: the JSON fast paths must agree with the strict parser | 300,000 | `tests/test_jwt.c` |
| scalar references | SIMD vs scalar base64url (20k strings) and SWAR integer parsing (200k values) | 220,000 | `tests/test_jwt.c` |

- **Engines covered.** Every vector runs on every engine the machine has:
  - scalar, NEON and SHA2 ×1/×2/×4 on ARM;
  - SHA-NI ×1/×2/×4 (compiled, and the hand-scheduled 3/4-stream assembly), AVX2, AVX-512VL, zmm (compiled, and
    the `x16` assembly) and the SHA-NI + `x16` split on x86;
  - each dispatch path of the extracted OpenSSL code (SHA-NI, AVX2, AVX, SSSE3, x86-64);
  - a C emulation of `vpternlogd` with the same immediates, so the AVX-512 logic is exercised on any machine.
- **How the external vectors run.** Each one sits in a batch of 1–24 messages, at a random lane. The other lanes are
  random messages checked against OpenSSL.
- **The crafted tokens cover:**
  - garbage, bad signature, `alg=none` (with and without a copied signature), HS512, expired;
  - `sub` ∈ {0, 1, true, "0", "-1", "1.5", "abc", null, …};
  - non-string usernames, float and huge `exp`, `nbf` in the future or malformed;
  - duplicate claims, escaped keys and usernames, invalid UTF-8, nesting too deep;
  - a wrong secret, a non-canonical last signature character, padding, extra segments;
  - a 3 KB payload.

### RS256 / ES256 / EdDSA (`make pk-test`)

| source | what | cases | origin, licence |
|---|---|---|---|
| Wycheproof `ecdsa_secp256r1_sha256_p1363_test.json` | ES256 in JOSE's r‖s format: malleability, out-of-range r/s, edge-case points | 262 | C2SP/wycheproof @ `d17cc89`, Apache-2.0 |
| Wycheproof `rsa_signature_{2048,3072,4096}_sha256_test.json` | RSASSA-PKCS1-v1_5, mostly invalid encodings that must be rejected | 773 | same |
| Wycheproof `ed25519_test.json` | Ed25519: S ≥ L, non-canonical and off-curve encodings, truncation | 181 | same |
| NIST CAVP `SigVer.rsp` [P-256, SHA-256] | ECDSA signature verification | 15 | CAVP `186-4ecdsatestvectors.zip`, US government work |
| NIST CAVP `SigVer15_186-3.rsp`, SHA-256, mod 2048/3072 | RSA verification, with assorted public exponents | 36 | CAVP `186-3rsatestvectors.zip`, US government work |
| RFC 7515 A.2, A.3 | the RS256 and ES256 JWS examples: live, expired, tampered | 6 | IETF Trust |
| RFC 8032 §7.1, RFC 8037 A.4 | the Ed25519 test vectors and the EdDSA JWS example (plus a tampered copy) | 8 | IETF Trust |
| pyca/cryptography, random | 8 P-256 keys, 6 RSA keys (2048/3072/4096, e = 3 and 65537) and 6 Ed25519 keys; messages of 0–1,100 bytes; 15% corrupted, 15% high-s, 10% EdDSA S + L | 5,000 | generated by `tests/make_pk_vectors.py` |
| pyca/cryptography, tokens | full JWTs: valid, expired, bad signature, wrong `alg`, padding, missing username, header variants | 360 | generated |
| screening counterexamples | genuine signatures turned into s₁·x, s₂/x: rejected one at a time, and accepted only by the opt-in screening | 4 pairs | generated |
| fiat-crypto (formally verified) | the P-256 and curve25519 field and scalar arithmetic come from it; the P-256 code (C and s2n-bignum versions) is cross-checked against it on random and edge inputs | 200,000 | [mit-plv/fiat-crypto](https://github.com/mit-plv/fiat-crypto), MIT |

- **How each vector runs:** alone, then inside random sub-batches, then in its whole key group shuffled into one
  batch. That way invalid signatures sit next to valid ones.
- **Builds covered:** every backend (portable C, s2n-bignum, libcrypto) and comb window (W = 5, 7, 8), with and
  without screening.

### Generated tests: property-based and fuzzing

Two generators look for cases nobody wrote down.

**Hypothesis** (`make test-hypothesis`, `tests/test_hypothesis.py`):
- **What it generates:** whole JWTs —
  - claims of every JSON type near the boundaries: `exp`/`nbf` around now in every number spelling, `sub` around 1
    and 2^63−1 with leading zeros and escapes, usernames straddling 255 bytes with multibyte characters and lone
    surrogates;
  - nesting around the 32-level limit, duplicate and escaped keys, random whitespace;
  - header variants, wrong secrets;
  - corruption of the JSON, the base64url and the signature.
- **What it checks against:** an independent Python model written from the claim table above. Python's `json`
  (with NaN, duplicates and depth checked by hand) decides JSON validity, `hmac` computes HS256, and
  pyca/cryptography signs and verifies RS256/ES256/EdDSA (including near-valid ES256 edge signatures).
- **Engines and batches:** every token runs on every engine in a random batch, through a ctypes shim
  (`tests/pyshim.c`).
- **Cost:** 200 examples per property by default, about 10 s. `HYP_N=20000` gives a long run.
- **It catches planted bugs:** off-by-one mutants of the `exp` boundary and the username limit both failed it.

**libFuzzer** (`fuzz/`), coverage-guided under ASan + UBSan:

| harness | oracle |
|---|---|
| `fuzz_verify` | every engine, on the whole batch and on each token alone, gives identical results; the shape matcher agrees with the strict parser; JWT_OK results are well-formed. A config bit re-signs tokens with OpenSSL, so inputs reach the JSON and claims code |
| `fuzz_b64` | SIMD and scalar base64url decoders agree with an RFC 4648 reference written in the harness |
| `fuzz_pk` | mutated real ES256/RS256/EdDSA signatures (byte flips; the other valid s and r or s at 0/1/n−1/n/n+1 for ES256; S + L and R's sign bit for EdDSA) get OpenSSL's verdict, alone and among valid fillers in a batch; built as portable C, with screening and with libcrypto BN |

```bash
make fuzz-smoke   # replay the seeds and any saved corpus under ASan + UBSan, locally (~2 s): for every change
make fuzz         # libFuzzer in Docker, 10 s per harness, one worker: a quick check
JOBS=6 ./scripts/fuzz.sh arm64 600   # a real campaign; corpora accumulate in build/fuzz-<arch>/
```

- **Limit of the fuzzing:** in a 3-minute, 6-worker trial it did not find a planted off-by-one in the shape
  matcher's username limit. That path only fires on one exact payload layout, so the property tests and the crafted
  cases are what cover it.

### Constant time

Everything that touches an HMAC key must take the same branches and touch the same addresses whatever the key:
key setup, every engine, `cc_tag_eq32`, `cc_hmac_sha256_verify`. Three deterministic checks prove it, each with a
planted early-exit compare as a positive control that must fail:
- **`make test-ct`.** valgrind memcheck with the key marked undefined, in the style of TIMECOP: any key-dependent
  branch or address fails it. It covers the engines valgrind runs (scalar, OpenSSL's SHA-256 code, AVX2, and on arm64
  the NEON and SHA2 engines).
- **`make test-ct-sde SDE=…/sde64`.** Intel SDE traces key setup plus each SHA-NI and AVX-512 engine under two keys, at
  batches 1, 3 and 16. The instruction and memory-address traces must be identical.
- **`make test-ct-qemu QEMU=… EXECLOG=…`.** The same for the AArch64 engines, from an x86-64 machine, through
  qemu-aarch64's execlog plugin. It needs a qemu built with `--enable-plugins`.

**Signing** is checked the same three ways (`test_ct sign`, and the `sign_hs` / `sign_ed` traces): the HS256 key, the
Ed25519 private key, its scalar `a` and prefix, and the nonce `r` are marked secret (valgrind) or varied in every
byte (SDE, qemu), through key setup and batches of 1 to 17 signatures, and the fixed-base multiplication, reduction
mod L, inversion and SHA-512 on their own. valgrind runs it on gcc and clang builds at -O1 to -O3. Its positive
control runs the verifier's variable-time scalar code on a secret and must be flagged. **`make dudect-sign`** adds
fixed-against-random-key timing tests of both, with A/A controls, an early-exit control and a variable-time comb
control that must both say LEAK. On Turin, Genoa and Cascade Lake every signing line is ok (max |t| 2.99, 10⁶ samples
for HS256 at batch 1 and 16, 3·10⁵ for Ed25519 at batch 1 and 8, 10⁵ for Ed25519 key setup), repeated runs agree,
and both controls say LEAK (|t| 244 to 5,859).

**`make dudect`** adds a statistical timing test on real hardware: Welch's t, fixed against random keys, with A/A
negative controls and the leaky positive control. On Turin, Genoa and Cascade Lake it's clean, with one exception:
the AVX-512 engine on Genoa sat at the threshold, and its SDE traces are identical. RS256 / ES256 / EdDSA verification
is variable time by design, since every input it handles is public.

**Platforms run:**

| platform | compilers | what ran |
|---|---|---|
| macOS arm64 (Apple M5 Pro) | Apple clang 21 | test, test-vectors, example, compare; pk-test, every backend |
| Linux arm64 (Ubuntu 24.04, Docker) | gcc 13.3, clang 18.1 | test, ASan/UBSan; pk-test, every backend |
| Linux amd64 (Ubuntu 24.04, Docker on Rosetta) | gcc 13.3, clang 18.1 | test, test-vectors (AVX2 engines, every OpenSSL SHA-256 path but SHA-NI), ASan/UBSan, AVX-512 build; pk-test, portable C |
| Intel Xeon Platinum 8260 (Ubuntu 24.04, kernel 6.8) | gcc 13.3, clang 18.1 | test, test-vectors on real AVX-512 (every engine); pk-test, every backend |
| AMD EPYC Turin (Zen 5), AMD EPYC Genoa (Zen 4), Intel Xeon Cascade Lake (Vultr VMs, Ubuntu 24.04) | gcc 13.3 | test, pk-test, the AVX-512 / IFMA / SHA-NI / VBMI suites natively, dudect, dudect-sign, the benchmarks in [How fast](#how-fast) and [Signing](#signing) |
| Intel SDE 10.13 (Ice Lake and Cascade Lake emulation) | gcc 13.3 | test_jwt on every AVX-512 and SHA-NI engine, the IFMA PK suites (`scripts/ifma-sde-test.sh`), test-ct-sde |
| qemu 8.2 aarch64-linux-user, with plugins | gcc 13.3 (cross) | test-ct-qemu, the AArch64 engines against scalar |
| GitHub Actions | gcc, clang | test-quick, test-vectors, ASan, AVX-512 build, fuzz-smoke, lint on Ubuntu x86/ARM and macOS; the Rust port's tests |

## Benchmarks

The comparisons with other libraries are in [How fast](#how-fast). This section has the per-engine detail, measured
earlier: on a bare-metal Xeon Platinum 8260 (Cascade Lake) and an Apple M5 Pro, before the November 2026 SHA-NI, zmm
and IFMA work. The engines picked by default have changed since (see [Building](#building)), but what each engine
costs on those machines hasn't.

**Method.**
- `bench/bench_jwt.c`, ns per token, best of several runs, hot cache.
- Tokens are ~140-byte signing inputs: 3 inner SHA-256 blocks + 1 outer.
- "Full verify" includes split, header, signature decode, HMAC, payload base64url, JSON and claims.
- OpenSSL baselines: `HMAC()` as most code calls it, re-keying per call; and precomputed ipad/opad `SHA256_CTX`
  midstates, OpenSSL's best case.

**Xeon Platinum 8260** (Cascade Lake, 2.4 GHz, no SHA-NI), 1 vCPU VM, Ubuntu 24.04, kernel 6.8, gcc 13.3,
`-O3 -march=cascadelake` (the default build, with no `-march` and run-time dispatch, has the same HMAC
speed and full verify within 2–7%).

HMAC only, ns/token:

| engine \ batch | 1 | 4 | 8 | 16 | 32 |
|---|---|---|---|---|---|
| OpenSSL `HMAC()` | 2,901 | 2,904 | 2,909 | 2,902 | 2,902 |
| OpenSSL, precomputed midstates | 772 | 766 | 763 | 766 | 762 |
| compiled scalar template | 1,007 | 1,009 | 1,022 | 1,006 | 1,008 |
| extracted OpenSSL SHA-256, one stream at a time | 754 | 754 | 752 | 749 | 752 |
| AVX2 ×8 | 766 | 423 | 222 | 222 | 222 |
| **AVX-512VL ymm ×8** (this CPU class's engine below 9 tokens) | **762** | **286** | **154** | 154 | 154 |
| zmm ×16, compiled (the `x16` assembly kernel now runs 9+ tokens here) | 767 | 287 | 154 | 125 | 125 |

At batch 1 every vector engine runs the extracted single-stream code. Two interleaved 8-lane ymm groups (16 lanes;
AVX2 ×2 and AVX-512VL 2×ymm) were slower than one group at every batch size (AVX-512VL: 176 vs 154 ns at 16 and 32;
2.80 vs 2.43 and 1.66 vs 1.34 cycles/byte measured) and were removed.

Full verify, ns/token, on the ymm engine (the default then):

| batch | 1 | 2 | 3 | 4 | 8 | 16 | 32 |
|---|---|---|---|---|---|---|---|
| shape-matched JSON (default) | **935** | 695 | 509 | 417 | **278** | 272 | 268 |
| strict JSON only (`-DJWT_NO_SHAPE_JSON`) | 1,046 | 803 | 616 | 519 | 375 | 366 | 362 |

**Against established libraries.** `make compare` runs the same 20,000 tokens and the same job through each one:
HS256 only, `exp` required, `sub` and `username` read (`bench/compare/e2e.c`, which measures within ~1.5% of
`bench_jwt`). Full verify, ns per token, on the Xeon Platinum 8260 (the wider November 2026 comparison is in
[How fast](#how-fast)):

| implementation | batch 1 | batch 3 | batch 8 |
|---|---|---|---|
| **cursed-jwt** | **922** | **507** | **277** |
| cursed-jwt, strict JSON only | 1,038 | 615 | 375 |
| [jwt-cpp](https://github.com/Thalhammer/jwt-cpp) (C++, OpenSSL + picojson) | 6,236 | 6,236 | 6,236 |
| [golang-jwt v5](https://github.com/golang-jwt/jwt) (Go, `MapClaims`) | 8,673 | 8,673 | 8,673 |

On the Apple M5 Pro, cursed-jwt took 116 ns at batch 8 against jwt-cpp's 2,521.

| library | build |
|---|---|
| cursed-jwt | `-O3` and the target's `-march` (`-march=cascadelake` on the Xeon) |
| jwt-cpp | header-only C++17, `-O3`, same `-march`, default picojson traits. Its HMAC is the same system OpenSSL libcrypto, with OpenSSL's runtime-dispatched SHA-256 asm |
| golang-jwt v5 | `go build`; Go has no optimisation flags, and no PGO is applied |

- **Correctness gate.** Each implementation must accept all 20,000 tokens and reject a forged one before it's timed.
- **Setup is done once.** jwt-cpp's verifier and golang-jwt's parser and key are built before the loop, as in a
  server.
- **Batch sizes.** The libraries verify one token per call, so their number is the same at every batch size.
  Compare them with our batch-1 column for a like-for-like single call.
- **What favours us.** The default build's shape-matched JSON path fits these compact payloads. The strict-JSON row
  shows the result without it.
- **Pinned versions.** The libraries are fetched at pinned commits into `third_party/`. golang-jwt needs a Go
  toolchain.

**AVX-512 frequency licence** (`make licence`). A fixed scalar workload is timed right after a 2 ms burst of each
engine; each figure is the median of 300 trials.

| after a burst of… | slowdown of the following scalar code |
|---|---|
| AVX2 ymm | +0.1% |
| **AVX-512VL ymm** | **0.0%** |
| zmm | **+19.4%**, lasting 0.5–1 ms |

**Apple M5 Pro** (macOS, Apple clang 21), ns/token:

| engine | HMAC, batch 4 | full verify, batch 4 |
|---|---|---|
| OpenSSL `HMAC()` | 736 | 794 |
| OpenSSL midstates | 95 | 185 |
| NEON 4-lane multi-buffer | 246 | 348 |
| **SHA2 instructions, 4 streams (default)** | **72** | **~142** |

**RS256 / ES256 / EdDSA:** [PK.md](PK.md) has every build at every batch size, on both machines.

### Continuous benchmarking (CodSpeed)

`bench/codspeed/bench_codspeed.cpp` benchmarks the public API with Google Benchmark (CodSpeed's fork), and
`.github/workflows/codspeed.yml` runs it on every push to `main` and every pull request under
[CodSpeed](https://app.codspeed.io/public/cursed-jwt)'s CPU simulation, which counts instructions and cache misses
instead of timing, so results are stable enough to flag regressions per PR. It covers HS256 full verify (batch 1, 3, 8,
64; shape-matched and strict JSON; forged tokens; the scalar engine), key setup, raw HMAC, batch SHA-256, base64url,
and RS256-2048 / ES256 / EdDSA verify and key setup. The engine is picked at run time as usual (under simulation:
AVX2 on x86-64). HS256 tokens are minted at start-up with the library's scalar HMAC; the public-key fixtures are in
`bench/codspeed/pk_fixtures.h` (regenerate with `bench/codspeed/gen_fixtures.py`, which needs pyca/cryptography).
No OpenSSL or Python is needed to build or run it:

```sh
cmake -S bench/codspeed -B build/codspeed -DCMAKE_BUILD_TYPE=Release -DCODSPEED_MODE=simulation
cmake --build build/codspeed -j
codspeed run -m simulation -- ./build/codspeed/bench_codspeed   # or run the binary directly for plain timings
```

### Estimating other CPUs (`make mca`)

`scripts/mca/mca.sh` runs each SHA-256 engine's block function (`scripts/mca/kernels.c`) through static pipeline
models, for CPUs we can't run on. The output is cycles per byte per message, for one 64-byte block per lane.
- **llvm-mca** (LLVM, Apache-2.0): every x86 and Arm model LLVM has. The script says which models repeat
  (LLVM 23 has none for Granite Rapids, Zen 5 or Sierra Forest).
- **uiCA** ([uops.info](https://uops.info), AGPL-3.0, fetched by `scripts/mca/fetch-uica.sh`, never vendored):
  Intel only, up to Ice Lake / Tiger Lake. `UICA=path` reuses an existing checkout.
- **`make mca-validate`** measures the same functions with `perf stat` on the machine it runs on
  (`scripts/mca/validate.sh`, x86-64 Linux) and adds them as columns.

Calibration on the Xeon Platinum 8260 (`make mca-validate`, clang 18), cycles per byte per message:

| engine | measured, one message's blocks | measured, independent | uiCA | llvm-mca |
|---|---|---|---|---|
| scalar | 15.4 | 15.6 | 16.1 | 8.9 |
| AVX2, 8 lanes | 2.43 | 2.35 | 2.23 | 1.31 |
| AVX-512VL, 8 lanes | 1.34 | 1.45 | 1.44 | 0.70 |
| zmm, 16 lanes | 0.86 | 0.84 | 0.83 | 0.66 |

- **uiCA** is within about 5% of the measurement on every engine.
- **llvm-mca** gets the order right but is 1.3–2.1× optimistic, so read its other CPUs as relative numbers.
- **Chained vs independent calls** cost about the same, because one compress is already one long dependency chain.
- **zmm is the cheapest compress per byte.** On Intel the frequency-licence drop measured by `make licence` (which
  cycle counts can't show) is why it runs only batches of 9 or more, and only on CPUs without SHA-NI.

What the models add (llvm-mca, cycles per byte per message, relative):
- **Zen 4 / Zen 5:**
  - AVX-512VL 8 lanes: 1.21;
  - zmm: 0.61, about 2× cheaper, on CPUs without Cascade Lake's licence drop;
  - AVX2: 1.28.
- **Arm, SHA2 instructions:** 2.1 on Neoverse N1 (Ampere Altra), 0.69–0.97 on N2 / V1 / V2 / V3.
- **Arm, NEON 4-lane multi-buffer:** 2.4–5.4 on the same models, so the SHA2-instruction engine should stay the
  default on every one of them.
- `apple-m4`'s scalar figure (26) is out of line with every other model; don't use it.

## Limits

- **Algorithms.** HS256 by default. RS256, ES256 and EdDSA (Ed25519 only) are built in, without JWKS parsing; there's no Ed448, no JWE and no
  `kid` lookup.
- **The claim profile is fixed** (see above). There's no `aud`/`iss` checking.
- **A lone token ties OpenSSL, it doesn't beat it,** except on AMD. On other x86-64 Linux it *is* OpenSSL's code.
  On AMD the SHA-NI engine's single stream is used instead (132 vs 160 ns per HMAC on EPYC Milan).
- **x86-64 macOS and Windows** use the compiled scalar template for single tokens: the extracted file is ELF-only.
- **Big-endian targets are untested.**
- `jwt_result_t` embeds a 256-byte username buffer per token.
- **Public keys are heavy:** an ES256 or EdDSA key holds about 530–570 KB of precomputed tables and takes a few
  milliseconds to set up. That's cheap per token for long-lived keys, and expensive for a key used once.
- **The IFMA paths are opt-in build flags** (`-DJWT_RSAZ`, `-DJWT_RSAZ8`, `-DJWT_ES8`), x86-64 Linux only.

## Security

- **What's checked:** every signature is recomputed; the MAC is compared in constant time over all 32 bytes; `alg`
  must equal the key's algorithm (so `alg=none` and algorithm confusion are rejected); `exp` is required. The exact
  rules are under [Claim semantics](#claim-semantics).
- **What isn't:** `aud`, `iss` and `kid`. If you need them, check them yourself on the decoded payload.
- **The RS256/ES256/EdDSA code is not constant-time**, by design: it only handles public data (keys, signatures,
  messages). RSA batch screening (`-DJWT_RSA_SCREEN`) accepts some mangled signature pairs that one-at-a-time
  verification rejects; read [PK.md](PK.md#screening-what-it-does-and-doesnt-prove) before turning it on.
- **The HMAC key path is constant time:** every engine, key setup and the tag compare, proven by trace
  equivalence (see [Constant time](#constant-time)).
- **Signing is constant time in the private key** (HS256 and Ed25519; see [Signing](#signing) and
  [Constant time](#constant-time)). Ed25519 private keys are wiped by `jwt_skey_free` / `cc_skey_free`, and the
  signer wipes its stack copies of secrets; neither can reach copies the compiler made in registers or spills.
- **An internal review, not an external one.** It reproduced the bug classes known from other JWT and crypto
  libraries: `alg=none` and algorithm confusion, ECDSA r = s = 0 and out-of-range scalars, invalid-curve points,
  Ed25519 S ≥ L and non-canonical encodings, Bleichenbacher's e = 3 forgery, duplicate claims and parser
  differentials against PyJWT and python-jose. It also ran long fuzzing campaigns on AVX-512 / IFMA hardware. None
  found a vulnerability; the tests it added are in the suite. Report vulnerabilities privately, as described in
  [SECURITY.md](SECURITY.md).

## Licence

cursed-jwt's own code is MIT, see [LICENSE](LICENSE). Some of the fastest code paths are other projects' code, all
under permissive licences that allow commercial use; [THIRD_PARTY.md](THIRD_PARTY.md) has every entry, its exact
origin and its pinned commit.
- **Vendored in the repository:**
  - OpenSSL's x86-64 SHA-256 and `bn_mul_mont` extracts (`crypto/src/sha256_x86_64_ossl.S`,
    `crypto/src/bn_mont*_x86_64_ossl.S`), Apache-2.0;
  - a port of Intel ipsec-mb's `sha256_x16_avx512` (`crypto/src/sha256_x16_avx512.S`), BSD-3-Clause;
  - Firedancer's AVX-512 IFMA curve25519 field (in `crypto/src/cc_ed25519_r43x6.inc`), Apache-2.0;
  - fiat-crypto's generated field arithmetic (`crypto/src/fiat/`), used under MIT.
- **Fetched at build time, never committed, and only for the builds that use them:**
  - s2n-bignum (`-DJWT_S2N`), used under MIT-0;
  - OpenSSL's IFMA RSA multiply (`-DJWT_RSAZ`), Apache-2.0;
  - parts of Intel crypto_mb (`-DJWT_RSAZ8`, `-DJWT_ES8`), Apache-2.0.

  The vendored projects' licence texts are in [licenses/](licenses/), and fiat-crypto's is in `crypto/src/fiat/`. The
  fetched projects' come with them.
- **Optional libraries linked:** OpenSSL's libcrypto with `-DJWT_OPENSSL`.
- **Credits for ideas:** cpuminer-opt and others, in [THIRD_PARTY.md](THIRD_PARTY.md).
