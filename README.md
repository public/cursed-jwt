# cursed-jwt

Batch JWT verification in C. Instead of checking HS256 tokens one at a time, cursed-jwt checks many at once with **one
multi-buffer SIMD HMAC-SHA256 pass**, one token per vector lane:
- with SHA-NI (every AMD Zen, Intel Ice Lake and later), 4 interleaved SHA-NI streams;
- without it, AVX-512VL or AVX2 hash 8 tokens per vector;
- interleaved ARMv8 SHA2 instructions hash 4 streams on ARM;
- a lone token runs OpenSSL's own single-stream SHA-256 code (x86-64 Linux) or one SHA2 stream (ARM).

The front end is SIMD too: base64url with NEON or AVX2, and a strict RFC 8259 JSON parser with a shape-matched fast
path. Every signature is recomputed on every call. Nothing is cached except the key's HMAC ipad/opad midstates. One
binary picks the best engine for the CPU it runs on.

RS256, ES256 and EdDSA (Ed25519) use the same front end ([PK.md](PK.md)).

**Why it exists.** JWT libraries verify one token per call, and HMAC-SHA256 is most of that call's cost. A server
that already reads requests in batches (an io_uring or epoll loop handling many connections per wakeup) can verify
all of their tokens at once. One SHA-256 has no parallelism to spare, but independent messages do: with one message
per vector lane, an HMAC costs 154 ns per token at batch 8 on a Cascade Lake Xeon, against 762 ns for one at a time
(see [Benchmarks](#benchmarks)). cursed-jwt is that batch verifier, with a strict JSON front end and tests against
independent implementations.

**Status.** The HS256 path is complete and tested on x86-64 and AArch64. RS256, ES256 and EdDSA are
built in and tested against the same kinds of vectors; they don't parse JWKS yet (you pass the key's numbers). There are no tagged
releases yet; `main` is the current version. It has not had an external security review (see [Security](#security)).

## At a glance

**HS256 full verify** (signature, base64url, JSON, claims), ns per token, on an Intel Xeon Platinum 8260 (Cascade
Lake, no SHA-NI). Every implementation accepted the same 20,000 tokens and rejected a forged one.

| implementation | batch 1 | batch 3 | batch 8 |
|---|---|---|---|
| **cursed-jwt** | **922** | **507** | **277** |
| cursed-jwt, strict JSON only | 1,038 | 615 | 375 |
| [jwt-cpp](https://github.com/Thalhammer/jwt-cpp) (C++, OpenSSL + picojson) | 6,236 | 6,236 | 6,236 |
| [golang-jwt v5](https://github.com/golang-jwt/jwt) (Go, `MapClaims`) | 8,673 | 8,673 | 8,673 |

That's **6.8–31× faster**. On an Apple M5 Pro, cursed-jwt takes 116 ns at batch 8 against jwt-cpp's 2,521. How these
were measured, and the caveats, are under [Benchmarks](#benchmarks).

**RS256 / ES256 / EdDSA** (fastest build: `-DJWT_S2N -DJWT_OPENSSL`), µs per token against OpenSSL `EVP_DigestVerify`:

| | Xeon, batch 1 | Xeon, batch 16 | Xeon, OpenSSL | M5, batch 16 | M5, OpenSSL |
|---|---|---|---|---|---|
| ES256 | 21.8 | **14.9** | 78.8 | **9.2** | 32.4 |
| RS256-2048 | 16.5 | 16.0 | 22.9 | 8.3 | 9.0 |
| RS256-2048, batch screening | 16.2 | **3.16** | 22.9 | **2.35** | 9.0 |
| EdDSA (Ed25519), portable C | 21.5 | **16.5** | 150.2 | **4.6** (b32) | 40.4 |

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
make                   # build/libcursedjwt.a and build/verify; needs only a C compiler
make test              # every engine on this CPU vs OpenSSL and the claim rules (needs libcrypto and python3)
make example-check     # the example program accepts a generated token and rejects a tampered one
```

The tests need OpenSSL's libcrypto as the reference: on macOS `brew install openssl@3`, on Debian/Ubuntu
`apt install libssl-dev`. `make test-vectors` adds the external vectors (it downloads them).

## Contents

- [Using it](#using-it)
- [Claim semantics](#claim-semantics)
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

## How it works

- **Multi-buffer HMAC.**
  - One SHA-256 "template" (`src/jwt_mb.inc`) is instantiated per ISA. One vector register holds the same state
    word of 8 (x86) or 4 (NEON) messages, so 8 tokens hash in roughly the time of 1.
  - HMAC plans give each message `ceil((L+9)/64)` blocks after the ipad midstate. Only the 1–2 tail blocks are
    copied; full blocks are read in place.
  - Plans are sorted by block count, so vectors are almost never ragged. When they are, a finished lane keeps its
    state through a mask select.
  - The outer hash never leaves registers: the inner digest becomes W0..7 directly.
- **AVX-512VL on ymm, not zmm.**
  - `vprord` does the rotates; `vpternlogd` does the three-input functions (0x96 xor3, 0xCA Ch and the lane select,
    0xE8 Maj).
  - A zmm burst slows *all following code* by 19.4% for 0.5–1 ms on Cascade Lake. ymm costs 0% (measured below).
- **ARM uses the SHA2 instructions, interleaved.** NEON multi-buffer is 2.9× slower than one stream of `sha256h`.
  Interleaving 4 independent streams hides the instruction latency (−15%).
- **The engine is picked at run time.** Each SIMD engine is compiled in its own target region, and the CPU's
  features (CPUID / HWCAP) choose among them, so one binary runs anywhere and uses what the machine has.
  - The AVX-512 region also tells the compiler to prefer 256-bit vectors. Otherwise it auto-vectorises copies with
    zmm, and the frequency-licence drop makes everything 29% slower.
- **One token at a time uses the best single-stream code there is.**
  - A lone token, and any lanes left over when a group is too small for a vector, can't use 8-way parallelism.
  - On x86-64 Linux they run OpenSSL's `sha256_block_data_order`, extracted and vendored as
    `src/sha256_x86_64_ossl.S`. It picks SHA-NI, AVX2+BMI2, AVX, SSSE3 or plain x86-64 code at run time.
  - On the Xeon it is 25% faster than the compiled template (752 vs 1,007 ns per HMAC).
- **Front end:**
  - base64url uses `vld4q` + `vqtbl4q` on NEON, and range compares + `maddubs`/`pshufb` packing on AVX2;
  - a shape matcher recognises the common compact payload `{"sub":"…","username":"…","iat":N,"exp":N}` in 37 ns,
    and falls back to the strict parser (131 ns) for anything else;
  - SWAR integer parsing;
  - `exp`/`nbf` are compared with `now` by digit count, then bytewise, with no number conversion.
- **Identical results either way.** The shape matcher defers to the strict parser on anything unusual. The tests
  fuzz it against the strict parser.
- **RS256 / ES256** don't batch like HMAC: SIMD across tokens would need AVX-512 IFMA. Instead:
  - ES256 precomputes comb tables for the public key at key setup, so a verify is two fixed-base multiplications.
  - RS256 can check a whole batch with one exponentiation ("screening"), which is opt-in because of a caveat.
  - Both use AWS s2n-bignum's verified asm or libcrypto's bignum asm where those beat portable C.
  - [PK.md](PK.md) has the design, the survey of other implementations, the licences and every number.

## Building

The library needs only a C compiler, and no `-march`. `make` builds `build/libcursedjwt.a` and `build/verify`.

**One binary runs on any CPU of its architecture.**
- **What's in it.** It is compiled for the baseline ISA (x86-64, ARMv8-A) and carries every engine that
  architecture can have, each compiled in its own target region.
- **How it chooses.** At start-up it reads CPUID and XGETBV (x86) or HWCAP / sysctl (ARM), then uses the best engine
  the machine has. Each feature that's missing degrades it one step:

| CPU | HS256 engine | RS256 / ES256 kernels (`-DJWT_PK`) |
|---|---|---|
| AMD Zen 5 (family 1Ah) | groups of 16 on zmm, the rest on 4 SHA-NI streams | as the rows below |
| any other x86-64 with SHA-NI (Zen 1–4, Intel Ice Lake and later, Atom cores) | 4 interleaved SHA-NI streams | as the rows below |
| AMD Zen 4 / Zen 5 (family ≥ 0x19) with AVX-512, SHA-NI masked | zmm, 16 lanes (no frequency-licence drop on AMD) | + crypto_mb 8-way IFMA if built with it |
| x86-64 with AVX-512 F/VL/BW/DQ/CD (Skylake-SP, Cascade Lake, Ice Lake …) | AVX-512VL on ymm, 8 lanes | + crypto_mb 8-way IFMA if built with it and the CPU has IFMA |
| x86-64 with AVX2 + BMI2 | AVX2, 8 lanes | s2n-bignum asm if BMI2 + ADX |
| other x86-64 | scalar | portable C |
| AArch64 with SHA2 instructions | 4 interleaved SHA2 streams | s2n-bignum / libcrypto |
| other AArch64 | NEON, 4 lanes | portable C |
| anything else | scalar | portable C |

- **Single tokens.** With SHA-NI they run one SHA-NI stream of the same engine. On other x86-64 Linux they run OpenSSL's
  extracted SHA-256 code, which dispatches itself (SHA-NI, AVX2+BMI2, AVX, SSSE3, plain x86-64). The Makefile
  assembles `src/sha256_x86_64_ossl.S` and defines `JWT_OSSL_SHA256`. If you compile `src/jwt.c` into your own
  program, do the same, or leave both out to get the compiled scalar code; `make OSSL_SHA=` builds without it.
- **Inspecting and masking the choice.** `jwt_engine()` names the HS256 engine in use, and `jwt_cpu_features()`
  returns the detected `JWT_CPU_*` bits. The environment variable `JWT_CPU_MASK` masks features for tests and
  benchmarks: `JWT_CPU_MASK=0` runs everything on the fallbacks.
- **SHA-NI.** `JWT_CPU_FAST_SHANI` is set on every CPU with SHA-NI except Zen 5, and selects the 4-stream SHA-NI
  engine. On Zen 3 and Zen 4 (EPYC Milan, Genoa) it beats every vector engine at every batch size, zmm
  included. On the other CPUs it is an expectation, not a measurement: Intel's SHA-NI parts and Zen 5 haven't
  been timed. Zen 5 runs 512-bit vectors at full width, so there `jwt_hmac_shani_zmm` sends whole groups of 16
  to the zmm engine and the rest to SHA-NI.
  Masking SHA-NI (`JWT_CPU_MASK` without bit 8) restores the vector engines.
- **Zen 4/5.** `JWT_CPU_FAST_ZMM` is set for AMD family ≥ 0x19 with AVX-512, and selects the 16-lane zmm engine
  when SHA-NI is masked off.
- **Speed of the dispatching build.** On the Xeon its HMAC matches a `-march=cascadelake` build. Full verify is
  within 2% with clang and 7% with gcc, because the front end is compiled for baseline x86-64.
  `ARCHFLAGS=-march=native` still works, and dispatch still checks the CPU.
- **Engine-specific functions** are exported for tests and benchmarks; call one only if `jwt_cpu_features()` has
  its bit. `jwt_hmac_avx512x2` exists only for benchmarks.

**Options:**

| flag | effect |
|---|---|
| `-DJWT_INPUT_PADDED` | every token has ≥ 64 readable bytes after it, which allows fixed-size tail loads |
| `-DJWT_NO_SHAPE_JSON` | strict parser only |
| `JWT_USERNAME_MAX`, `JWT_TOKEN_MAX` | size limits |
| `-DJWT_NO_PK` | leave out RS256 / ES256 / EdDSA (they're built by default, from fiat-crypto's arithmetic vendored in `src/fiat/`) |
| `-DJWT_S2N` | s2n-bignum's asm kernels (`scripts/fetch-s2n-bignum.sh`; x86 needs BMI2 + ADX) |
| `-DJWT_OPENSSL` | libcrypto's bignum asm for RSA (links `-lcrypto`) |
| `-DJWT_RSA_SCREEN` | RSA batch screening (read the caveat in [PK.md](PK.md) first) |
| `-DJWT_CRYPTO_MB` | Intel crypto_mb's 8-way AVX-512 IFMA ES256 / RSA, used only on IFMA CPUs (`scripts/build-crypto-mb.sh`; Linux x86-64; not yet run on IFMA hardware) |

**Targets:**

```bash
make              # build/libcursedjwt.a, build/verify
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
  - SHA-NI ×1/×2/×4, AVX2, AVX2 ×2, AVX-512VL, 2×ymm and zmm on x86;
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

**Platforms run:**

| platform | compilers | what ran |
|---|---|---|
| macOS arm64 (Apple M5 Pro) | Apple clang 21 | test, test-vectors, example, compare; pk-test, every backend |
| Linux arm64 (Ubuntu 24.04, Docker) | gcc 13.3, clang 18.1 | test, ASan/UBSan; pk-test, every backend |
| Linux amd64 (Ubuntu 24.04, Docker on Rosetta) | gcc 13.3, clang 18.1 | test, test-vectors (AVX2 engines, every OpenSSL SHA-256 path but SHA-NI), ASan/UBSan, AVX-512 build; pk-test, portable C |
| Intel Xeon Platinum 8260 (Ubuntu 24.04, kernel 6.8) | gcc 13.3, clang 18.1 | test, test-vectors on real AVX-512 (every engine); pk-test, every backend |
| GitHub Actions | gcc, clang | test-quick, test-vectors, ASan, AVX-512 build on Ubuntu x86/ARM and macOS |

## Benchmarks

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
| **AVX-512VL ymm ×8 (default)** | **762** | **286** | **154** | 154 | 154 |
| AVX-512VL 2×ymm ×16 | 770 | 287 | 154 | 176 | 176 |
| zmm ×16 (not recommended) | 767 | 287 | 154 | 125 | 125 |

At batch 1 every vector engine runs the extracted single-stream code.

Full verify, ns/token, default engine:

| batch | 1 | 2 | 3 | 4 | 8 | 16 | 32 |
|---|---|---|---|---|---|---|---|
| shape-matched JSON (default) | **935** | 695 | 509 | 417 | **278** | 272 | 268 |
| strict JSON only (`-DJWT_NO_SHAPE_JSON`) | 1,046 | 803 | 616 | 519 | 375 | 366 | 362 |

**Against established libraries.** `make compare` runs the same 20,000 tokens and the same job through each one:
HS256 only, `exp` required, `sub` and `username` read. Those are the numbers in [At a glance](#at-a-glance), from
`bench/compare/e2e.c`, which measures within ~1.5% of `bench_jwt`.

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
| **AVX-512VL ymm (default)** | **0.0%** |
| zmm | **+19.4%**, lasting 0.5–1 ms |

**Apple M5 Pro** (macOS, Apple clang 21), ns/token:

| engine | HMAC, batch 4 | full verify, batch 4 |
|---|---|---|
| OpenSSL `HMAC()` | 736 | 794 |
| OpenSSL midstates | 95 | 185 |
| NEON 4-lane multi-buffer | 246 | 348 |
| **SHA2 instructions, 4 streams (default)** | **72** | **~142** |

**RS256 / ES256 / EdDSA:** [PK.md](PK.md) has every build at every batch size, on both machines.

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
| AVX2, 2 × 8 lanes | 2.80 | 2.64 | 2.63 | 1.46 |
| AVX-512VL, 8 lanes (default) | 1.34 | 1.45 | 1.44 | 0.70 |
| AVX-512VL, 2 × 8 lanes | 1.66 | 1.61 | 1.68 | 0.78 |
| zmm, 16 lanes | 0.86 | 0.84 | 0.83 | 0.66 |

- **uiCA** is within about 5% of the measurement on every engine.
- **llvm-mca** gets the order right but is 1.3–2.1× optimistic, so read its other CPUs as relative numbers.
- **Chained vs independent calls** cost about the same, because one compress is already one long dependency chain.
- **zmm is the cheapest compress per byte.** It isn't the default because of the frequency-licence drop
  measured by `make licence`, which cycle counts can't show.

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
- **A lone token ties OpenSSL, it doesn't beat it,** except with SHA-NI. Elsewhere on x86-64 Linux it *is* OpenSSL's
  code. With SHA-NI the engine's single stream is used instead (132 vs 160 ns per HMAC on EPYC Milan).
- **x86-64 macOS and Windows** use the compiled scalar template for single tokens: the extracted file is ELF-only.
- **Big-endian targets are untested.**
- `jwt_result_t` embeds a 256-byte username buffer per token.

## Security

- **What's checked:** every signature is recomputed; the MAC is compared in constant time over all 32 bytes; `alg`
  must equal the key's algorithm (so `alg=none` and algorithm confusion are rejected); `exp` is required. The exact
  rules are under [Claim semantics](#claim-semantics).
- **What isn't:** `aud`, `iss` and `kid`. If you need them, check them yourself on the decoded payload.
- **The RS256/ES256/EdDSA code is not constant-time**, by design: it only handles public data (keys, signatures,
  messages). RSA batch screening (`-DJWT_RSA_SCREEN`) accepts some mangled signature pairs that one-at-a-time
  verification rejects; read [PK.md](PK.md#screening-what-it-does-and-doesnt-prove) before turning it on.
- **No external review yet.** Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## Licence

MIT, see [LICENSE](LICENSE).
- The one vendored file, `src/sha256_x86_64_ossl.S`, is OpenSSL's, under Apache-2.0
  ([licenses/OpenSSL-LICENSE.txt](licenses/OpenSSL-LICENSE.txt)).
- The optional builds' fetched dependencies (fiat-crypto, s2n-bignum), and credits for techniques
  (cpuminer-opt), are in [THIRD_PARTY.md](THIRD_PARTY.md).
