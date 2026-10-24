# cursed-jwt

Batch HS256 JWT verification in C. It checks many tokens with **one multi-buffer SIMD HMAC-SHA256 pass**:
- AVX-512VL or AVX2 hash 8 tokens per vector on x86;
- interleaved ARMv8 SHA2 instructions hash 4 streams on ARM;
- a portable scalar engine covers everything else.

The front end is SIMD too: base64url with NEON or AVX2, and a strict RFC 8259 JSON parser with a shape-matched
fast path. Every signature is recomputed on every call; nothing is cached except the key's HMAC ipad/opad
midstates.

On a Xeon Platinum 8260 (no SHA-NI), a full verify costs **277 ns per token at batch 8** and 1,178 ns for a lone
token. On the same box, jwt-cpp takes 6,201 ns and golang-jwt v5 8,739 ns per token: **5–24× faster**.

### Benchmark comparison at a glance

Full verify (signature + base64url + JSON + claims), ns per token, Intel Xeon Platinum 8260 (Cascade Lake, no
SHA-NI), Ubuntu 24.04, kernel 6.8, gcc 13.3. Every implementation accepted the same tokens and rejected a forged
one. Method and full tables are under [Benchmarks](#benchmarks).

| implementation | batch 1 | batch 3 | batch 8 |
|---|---|---|---|
| **cursed-jwt** (AVX-512VL ymm, shape-matched JSON) | **1,178** | **508** | **277** |
| cursed-jwt, strict JSON only | 1,276 | 617 | 376 |
| [jwt-cpp](https://github.com/Thalhammer/jwt-cpp) (C++, OpenSSL + picojson) | 6,201 | 6,201 | 6,201 |
| [golang-jwt v5](https://github.com/golang-jwt/jwt) (Go, `MapClaims`) | 8,739 | 8,739 | 8,739 |

| HMAC-SHA256 only, ns/token | batch 1 | batch 8 |
|---|---|---|
| **cursed-jwt AVX-512VL ymm ×8** | 1,014 | **155** |
| cursed-jwt AVX2 ×8 | 1,015 | 222 |
| OpenSSL, precomputed ipad/opad midstates | 764 | 763 |
| OpenSSL `HMAC()` | 2,878 | 2,870 |

On an Apple M5 Pro (`make compare`): cursed-jwt 116 ns/token at batch 8, jwt-cpp 2,521.

## Contents

- [API](#api)
- [Claim semantics](#claim-semantics)
- [Why it's fast](#why-its-fast)
- [Build matrix](#build-matrix)
- [Build and test](#build-and-test)
- [Benchmarks](#benchmarks)
- [Limits](#limits)
- [Licence](#licence)

## API

```c
#include "jwt.h"            // link build/libcursedjwt.a (or compile src/jwt.c into your program)

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

`out[i].username` points into `out[i].ubuf`, so don't copy the struct and keep the pointer. `jwt_verify_batch` uses
about 17 KB of stack. It is thread-safe: no global state, and the key is read-only after init.

Lower-level entry points, for your own claims or for benchmarks:
- `jwt_hmac_*`: raw multi-buffer HMAC-SHA256 of n messages per engine;
- `jwt_b64url_decode`: base64url decode;
- `jwt_verify_batch_<engine>`: the full verify on a chosen engine.

`examples/verify.c` is a complete program: `build/verify SECRET TOKEN...`.

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

The claim profile (`sub` as a numeric user id, `username` as a string) is built in. For other claims, use
`jwt_hmac_*` and the JSON parser in `src/jwt.c` as building blocks.

## Why it's fast

- **Multi-buffer HMAC.**
  - One SHA-256 "template" (`src/jwt_mb.inc`) is instantiated per ISA. One vector register holds the same state
    word of 8 (x86) or 4 (NEON) different messages, so 8 tokens hash in roughly the time of 1.
  - HMAC plans give each message `ceil((L+9)/64)` blocks after the ipad midstate. Only the 1–2 tail blocks are
    copied; full blocks are read in place.
  - Plans are sorted by block count, so vectors are almost never ragged. When they are, a finished lane keeps
    its state through a mask select.
  - The outer hash never leaves registers: the inner digest becomes W0..7 directly.
- **AVX-512VL on ymm**, not zmm:
  - `vprord` for rotates, and `vpternlogd` for the three-input functions (0x96 xor3, 0xCA Ch and the lane select,
    0xE8 Maj).
  - A zmm burst slows *all following code* by 19.4% for 0.5–1 ms on Cascade Lake (measured, below). ymm costs 0%.
- **ARM uses SHA2 instructions, interleaved.** NEON multi-buffer is 2.9× slower than one stream of `sha256h`.
  Interleaving 4 independent streams hides the instruction latency instead (−15%).
- **Front end:**
  - base64url uses `vld4q` + `vqtbl4q` on NEON, and range compares + `maddubs`/`pshufb` packing on AVX2;
  - a shape matcher recognises the common compact payload `{"sub":"…","username":"…","iat":N,"exp":N}` in
    37 ns, and falls back to the strict parser (131 ns) for anything else;
  - SWAR integer parsing;
  - `exp`/`nbf` are compared with `now` by digit count, then bytewise, with no number conversion.
- **Identical results either way.** The shape matcher and the opt-in simdjson-style path both defer to the strict
  parser on anything unusual. The tests fuzz each against it.

## Build matrix

The engine is chosen at compile time. Every engine the target can run is also exported for tests.

| target | flags | default engine |
|---|---|---|
| x86-64, AVX-512VL (Skylake-SP, Cascade Lake, Ice Lake …) | `-march=cascadelake -DJWT_AVX512` (gcc recommended) | AVX-512VL ymm, 8 lanes |
| x86-64, AVX2 | `-march=haswell` / `-march=native` | AVX2, 8 lanes |
| AArch64 with SHA2 (`__ARM_FEATURE_SHA2`) | `-march=armv8.2-a+crypto+sha3`, `-mcpu=native` on Apple | SHA2 instructions, 4 streams |
| AArch64 without SHA2 | `-march=armv8-a` | NEON, 4 lanes |
| anything else | — | scalar |

A batch of 1 runs the scalar engine, because one token through an 8-lane block costs the same.

Options:
- `-DJWT_INPUT_PADDED`: every token has ≥ 64 readable bytes after it, which allows fixed-size tail loads.
- `-DJWT_NO_SHAPE_JSON`: strict parser only.
- `-DJWT_FAST_JSON`: the simdjson-style path, 3–4% slower on a Xeon.
- `-DJWT_LANE_JSON`: lane-parallel JSON, which only pays at batch ≥ 32.
- `JWT_USERNAME_MAX`, `JWT_TOKEN_MAX`: size limits.

The 16-lane `jwt_hmac_zmm` and `jwt_hmac_avx512x2` exist for benchmarks; neither is the default.

## Build and test

The library needs only a C compiler. The tests need OpenSSL's libcrypto (the reference HMAC) and python3 (token
generation).

```bash
make              # build/libcursedjwt.a, build/verify
make test         # every engine vs OpenSSL + the claim rules (~6 s)
make test-quick   # fewer random iterations (CI)
make test-vectors # + external vectors: RFC 4231, NIST CAVP, Wycheproof, RFC 7515, pyca/cryptography (network)
make compare      # full verify vs jwt-cpp and golang-jwt, fetched at pinned commits (network; go optional)
make asan         # ASan + UBSan
make bench        # ns/token per engine and batch size, vs OpenSSL
make avx512       # real AVX-512VL test + bench binaries (run them on AVX-512 hardware)
make licence      # AVX-512 frequency-licence probe (AVX-512 hardware)
```

```bash
./scripts/docker-test.sh amd64
```

```bash
./scripts/docker-test.sh arm64
```

The Docker runs use Ubuntu 24.04 with gcc and clang. `DOCKER_CPUS=8-13` pins the container to those CPUs.

On macOS, the Makefile finds Homebrew's `openssl@3`. On Linux, install `libssl-dev`.

**External vectors** (`make test-vectors`). These are independent of OpenSSL's HMAC and of this repository's
generators:
- **Sources.** `scripts/fetch-vectors.sh` downloads them and checks each file against a pinned SHA-256:
  - RFC 4231 test cases 1–7 (one with a truncated tag, and keys longer than the block size);
  - NIST CAVP `HMAC.rsp` `[L=32]`: 225 vectors, keys of 40–70 bytes, tags of 16–32 bytes;
  - Wycheproof `hmac_sha256_test.json`: 174 cases, including invalid tags that must be rejected;
  - the RFC 7515 Appendix A.1 HS256 JWS.
- **Generator.** `tests/make_vectors.py` checks every parsed vector against **pyca/cryptography** first, so a
  parsing mistake cannot pass silently. It then adds 5,000 random cases from cryptography: keys of 0–200 bytes,
  messages of 0–1,100 bytes, and 10% corrupted tags.
- **Every engine** (scalar, NEON, SHA2 ×1/×2/×4, AVX2, AVX2 ×2, AVX-512VL, 2×ymm, zmm, emulated ternlog) runs
  every vector in a batch of 1–24 messages under the vector's key, at a random lane. The other lanes are random
  messages checked against OpenSSL.
- **The RFC 7515 token** must give BAD_PAYLOAD while live: the signature and time are valid, but it has no
  `sub`/`username`. It must give INVALID once expired, and INVALID with one signature character changed.
- A corrupted vector file makes the test fail. This was checked by flipping one expected result.

**What the tests check** (`tests/test_jwt.c`, about 1.2M checks per run):
- **Every engine's raw HMAC against OpenSSL `HMAC()`.** This covers 20,000 generated tokens, and 3,000 random
  batches of 1–70 messages with lengths 0–699, which exercise ragged lanes and the 1-vs-2 tail-block cases.
- **Full verify of every token** at batch sizes 1/3/4/8/16/32/64/100.
  - The tokens are minted by `tests/gen_tokens.py` with Python's `hmac` module, an independent implementation.
- **123 crafted tokens** with exact expected status, uid, username and escape flag, at every batch size 1–123:
  - garbage, bad signature, `alg=none` (with and without a copied signature), HS512, expired;
  - `sub` ∈ {0, 1, true, "0", "-1", "1.5", "abc", null, …};
  - non-string usernames, float and huge `exp`, `nbf` in the future or malformed;
  - duplicate claims, escaped keys and usernames, invalid UTF-8, nesting too deep;
  - a wrong secret, a non-canonical last signature character, padding, extra segments;
  - a 3 KB payload.
- **Differential fuzz** of the JSON fast paths against the strict parser: 300k payloads.
- **SIMD vs scalar** for base64url (20k strings) and the SWAR integer parser (200k values).
- **AVX-512 by construction on any machine.** The template runs with a C emulation of `vpternlogd` using the same
  immediates.

**Platforms run:**

| platform | compilers | result |
|---|---|---|
| macOS arm64 (Apple M5 Pro) | Apple clang 21 | test, test-vectors, example, compare (jwt-cpp) |
| Linux arm64 (Ubuntu 24.04, Docker) | gcc 13.3, clang 18.1 | test, ASan/UBSan |
| Linux amd64 (Ubuntu 24.04, Docker) | gcc 13.3, clang 18.1 | test (AVX2 engines), ASan/UBSan, AVX-512 build compiles |
| Intel Xeon Platinum 8260 (Ubuntu 24.04, kernel 6.8) | gcc 13.3, clang 18.1 | test on real AVX-512 (AVX-512VL, 2×ymm, zmm engines) |

## Benchmarks

**Method.**
- `bench/bench_jwt.c`, ns per token, best of several 1-second runs, hot cache.
- Tokens are ~140-byte signing inputs: 3 inner SHA-256 blocks + 1 outer.
- "Full verify" includes split, header, signature decode, HMAC, payload base64url, JSON and claims.
- **OpenSSL baselines:**
  - `HMAC()` as most code calls it, re-keying per call;
  - precomputed ipad/opad `SHA256_CTX` midstates, OpenSSL's best case.

**Xeon Platinum 8260** (Cascade Lake, 2.4 GHz, no SHA-NI), 1 vCPU VM, Ubuntu 24.04, kernel 6.8, gcc 13.3
`-O3 -march=cascadelake -DJWT_AVX512`.

HMAC only, ns/token:

| engine \ batch | 1 | 4 | 8 | 16 | 32 |
|---|---|---|---|---|---|
| OpenSSL `HMAC()` | 2878 | 2888 | 2870 | 2867 | 2881 |
| OpenSSL, precomputed midstates | 764 | 763 | 763 | 761 | 763 |
| scalar | 1015 | 1007 | 1008 | 1004 | 1005 |
| AVX2 ×8 (`-march=cascadelake` build) | 1015* | 422 | 222 | 221 | 221 |
| **AVX-512VL ymm ×8 (default)** | 1014* | **286** | **155** | 154 | 153 |
| AVX-512VL 2×ymm ×16 | 1017* | 287 | 155 | 177 | 176 |
| zmm ×16 (not recommended) | 1017* | 287 | 155 | 126 | 126 |

\* A batch of 1 runs the scalar engine.

Full verify, ns/token, default build (AVX-512VL + shape-matched JSON):

| batch | 1 | 2 | 3 | 4 | 8 | 16 | 32 |
|---|---|---|---|---|---|---|---|
| shape-matched JSON (default) | **1,178** | 691 | 508 | 417 | **277** | 272 | 268 |
| strict JSON only (`-DJWT_NO_SHAPE_JSON`) | 1,276 | 801 | 617 | 522 | 376 | 369 | 363 |

**Against established libraries** on the same box, the same tokens and the same job (HS256, `exp` required, `sub`
and `username` read). Every implementation accepted the same tokens and rejected a forged one.

| full verify, ns/token | batch 1 | batch 3 | batch 8 |
|---|---|---|---|
| **cursed-jwt** (strict-JSON build at the time) | **1,271** | **608** | **371** |
| [jwt-cpp](https://github.com/Thalhammer/jwt-cpp) (C++, OpenSSL + picojson) | 6,201 | 6,201 | 6,201 |
| [golang-jwt v5](https://github.com/golang-jwt/jwt), `MapClaims` | 8,739 | 8,739 | 8,739 |

The libraries verify one token at a time. `make compare` reruns this:
- it fetches jwt-cpp and golang-jwt at pinned commits into `third_party/`;
- each harness in `bench/compare/` first checks that every test token is accepted and a forged one rejected, then
  times it;
- golang-jwt needs a Go toolchain.

On the Apple M5 Pro (`make compare`), full verify was 116 ns/token at batch 8 for cursed-jwt, against 2,521 for
jwt-cpp.

**How the comparison is kept fair** (`bench/compare/`):

| library | build |
|---|---|
| cursed-jwt | `-O3` and the target's `-march` (`-march=cascadelake -DJWT_AVX512` on the Xeon) |
| jwt-cpp | header-only C++17, `-O3` and the same `-march`. It links the same system OpenSSL libcrypto, whose own runtime-dispatched SHA-256 asm (AVX2, SHA-NI where present) does its HMAC. It uses its default picojson traits |
| golang-jwt v5 | `go build`; Go has no optimisation flags, and no PGO is applied |

- **Same tokens and job for all three.** They run the same 20,000 tokens and do the same job: HS256 only, `exp`
  required, `sub` and `username` read.
- **Correctness gate.** Each implementation must accept all 20,000 tokens and reject a forged one before it's
  timed.
- **Verifier setup is done once.** jwt-cpp's verifier and golang-jwt's parser and key are built before the loop,
  as in a server.
- **Batch sizes.** The libraries can only verify one token per call, so their number is the same at every batch
  size. Compare them with our batch-1 column for a like-for-like single call.
- **What favours us.** Our default build also has the shape-matched JSON fast path, which these compact
  `{"sub","username","iat","exp"}` payloads hit. The strict-JSON-only row shows the result without it.

**AVX-512 frequency licence** (`make licence`). A fixed scalar workload is timed right after a 2 ms burst of each
engine; each figure is the median of 300 trials.

| after a burst of… | slowdown of the following scalar code |
|---|---|
| AVX2 ymm | +0.1% |
| **AVX-512VL ymm (default)** | **0.0%** |
| zmm | **+19.4%**, lasting 0.5–1 ms |

**Apple M5 Pro** (macOS, Apple clang 21), ns/token:

| engine | HMAC, batch 4 | full verify, batch 4 |
|---|---|---|
| OpenSSL `HMAC()` | 736 | 794 |
| OpenSSL midstates | 95 | 185 |
| NEON 4-lane multi-buffer | 246 | 348 |
| **SHA2 instructions, 4 streams (default)** | **72** | **~142** |

## Limits

- **HS256 only.** No RS/ES/EdDSA, no JWE, no `kid` lookup; the key is one shared secret.
- **The claim profile is fixed** (see above). There's no `aud`/`iss` checking.
- **Batch 1 is the weak spot on x86 without SHA-NI.** The scalar engine (1,005 ns HMAC) is slower than OpenSSL's
  single-stream code (763 ns). From batch 2 the 8-lane engine wins.
- There's no SHA-NI engine. On x86 CPUs with SHA-NI, OpenSSL's single-stream code is likely competitive.
- **Big-endian targets are untested.**
- `jwt_result_t` embeds a 256-byte username buffer per token.

## Licence

MIT, see [LICENSE](LICENSE). Credits for techniques (simdjson, cpuminer-opt) are in [THIRD_PARTY.md](THIRD_PARTY.md).
