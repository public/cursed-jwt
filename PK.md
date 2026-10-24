# RS256, ES256 and EdDSA in cursed-jwt: survey, prototype, numbers

This covers asymmetric JWT algorithms. HS384/HS512 get a short note at the end.

- **Targets:**
  - Apple M5 Pro: ARMv8 SHA2/SHA512 and NEON, no AVX-512 IFMA equivalent.
  - Xeon Platinum 8260 (Cascade Lake): AVX-512F/BW/VL/DQ, **no IFMA**, no SHA-NI, 1 vCPU KVM, OpenSSL 3.0.13.
- **Prototype:** `src/jwt_pk.inc`, built with `-DJWT_PK`, behind `jwt_verify_batch_pk` (same front end and claim
  rules as `jwt_verify_batch`).
- **Three arithmetic backends**, chosen at compile time:
  - portable C (the default; no dependencies beyond fiat-crypto's generated C);
  - `-DJWT_S2N`: AWS s2n-bignum's formally verified assembly for the P-256 field and RSA-2048;
  - `-DJWT_OPENSSL`: libcrypto's BN Montgomery assembly for RSA.

  The **fast build** is `-DJWT_S2N -DJWT_OPENSSL`. It picks the kernel that measured fastest per platform and key
  size (see [Backends](#backends)).
- **Tests:** `make pk-test` / `pk-test-s2n` / `pk-test-fast` check every build against Wycheproof, NIST CAVP,
  RFC 7515 A.2/A.3 and pyca/cryptography.

## Summary

- **Batching works very differently here from HS256.**
  - For HMAC, one SIMD register holds 8 tokens' state.
  - For RSA and ECC, the work is 64×64-bit multiply chains. SIMD across tokens needs 52-bit vector multipliers
    (AVX-512 IFMA), which Cascade Lake doesn't have. With ymm `vpmuludq` (32×32→64) it would at best match scalar
    `mulx`.
  - Intel's multi-buffer RSA/ECDSA/Ed25519 (`crypto_mb` in ipp-crypto) requires IFMA. So on both targets the
    levers are algebraic, not SIMD.
- **ES256: per-key comb tables, then two fixed-base multiplications.**
  - A JWT verifier holds a few long-lived public keys, so key setup precomputes a comb table for **Q** as well as
    for G (2.4 ms and 528 KB per key on the M5).
  - A verify is then 2 × 33 mixed additions with no doublings. Compare OpenSSL's ~256 doublings + ~90 additions.
  - The x-coordinate check is projective, so a token needs no field inversion. All the s⁻¹ of a batch share one
    inversion.
  - **Fast build, batch 16: 3.5× faster than OpenSSL on the M5, 5.1× on the Xeon.** Already 3.0× / 3.6× at batch 1.
- **RS256: one-at-a-time verification is at OpenSSL parity (it's the same 19 Montgomery operations); batch
  screening is far ahead.**
  - **Screening** (Bellare–Garay–Rabin) checks a whole batch with one exponentiation:

    (∏ sᵢ)^e ≡ ∏ EMᵢ (mod n)

    That's 2 multiplications per token + 17 per batch, instead of 19 per token.
  - Fast build, RSA-2048 at batch 16: **3.8× faster than OpenSSL on the M5, 6.1× on the Xeon.**
  - **The catch:** screening proves that every *message* was signed. It does not prove that every *signature string*
    is the canonical one: s₁·x and s₂/x pass together. So it's opt-in (`-DJWT_RSA_SCREEN`); see below.
- **EdDSA isn't prototyped yet, but it is where the biggest ratio is.** OpenSSL's Ed25519 verify is slow (38 µs on
  the M5, 141 µs on the Xeon). The ES256 fixed-key trick applies unchanged (verify = [S]B − [k]A, with A fixed per
  key), and Edwards additions are cheaper.
- **Recommendation:**
  1. Ship the fast build's backend choice as the default for `-DJWT_PK`, and keep the portable C as the fallback
     when it has no dependencies.
  2. Keep RS256 screening as an explicit batch option.
  3. Do Ed25519 next, the same way.
  4. RS256 is what most OIDC providers default to (Google, Microsoft Entra, Auth0, Okta), so it matters most in
     practice, even though it gains least without screening.

## Benchmarks: every batch size

- **Method:** `bench/bench_pk.c` (`make pk-bench`, `pk-bench-s2n`, `pk-bench-fast`). Times are µs per token,
  `jwt_pk_verify_raw`, best of 3.
  - Tokens are 64 per key, with 136-byte signing inputs.
  - Full verify through `jwt_verify_batch_pk` (base64url, header, claims) adds 0.1–0.3 µs.
- **OpenSSL** verifies one token at a time, so its cost is the same at every batch size: `EVP_DigestVerify` with the
  `EVP_PKEY` parsed once.
- **Machines:**
  - M5: Apple clang, best of two runs under a load average of 5–10.
  - Xeon: clang 18, `-O3 -march=cascadelake`, broker experiments exp79 (C), exp107 (s2n), exp109 (OpenSSL BN) and
    exp110 (fast build).

**ES256**

| build \ batch | 1 | 2 | 4 | 8 | 16 | 32 | OpenSSL |
|---|---|---|---|---|---|---|---|
| M5, portable C | 11.0 | 9.6 | 9.4 | 9.1 | 9.0 | 9.0 | 32.4 |
| M5, fast (s2n-bignum P-256) | 10.8 | 9.6 | 9.4 | 9.3 | 9.2 | 9.2 | 32.4 |
| Xeon, portable C | 28.2 | 24.7 | 23.0 | 22.1 | 21.6 | 21.4 | 78.6 |
| **Xeon, fast (s2n-bignum P-256)** | **21.7** | 18.4 | 16.7 | 15.8 | **15.4** | 15.3 | 78.6 |

**RS256-2048, one at a time (screening off)**

| build \ batch | 1 | 2 | 4 | 8 | 16 | 32 | OpenSSL |
|---|---|---|---|---|---|---|---|
| M5, portable C | 13.5 | 13.2 | 13.2 | 13.3 | 13.3 | 13.5 | 9.0 |
| M5, s2n-bignum | 13.1 | 13.2 | 13.2 | 13.2 | 13.2 | 13.2 | 9.0 |
| **M5, fast (libcrypto BN)** | **8.5** | 8.4 | 8.3 | 8.4 | 8.3 | 8.4 | 9.0 |
| Xeon, portable C | 34.3 | 34.5 | 34.4 | 34.4 | 34.4 | 34.4 | 23.1 |
| Xeon, libcrypto BN | 20.8 | 20.6 | 21.2 | 20.2 | 20.6 | 20.0 | 23.1 |
| **Xeon, fast (s2n-bignum)** | **16.5** | 16.5 | 16.4 | 16.5 | 16.4 | 16.4 | 23.1 |

**RS256-2048, batch mode (`-DJWT_RSA_SCREEN`)**

| build \ batch | 1 | 2 | 4 | 8 | 16 | 32 | OpenSSL |
|---|---|---|---|---|---|---|---|
| M5, portable C | 13.3 | 7.6 | 4.8 | 3.4 | 2.7 | 2.8 | 9.0 |
| **M5, fast (libcrypto BN)** | 8.5 | 5.5 | 3.7 | 2.8 | **2.35** | 2.34 | 9.0 |
| Xeon, portable C | 35.0 | 20.0 | 12.4 | 8.8 | 6.9 | 6.9 | 23.1 |
| Xeon, libcrypto BN | 20.8 | 12.8 | 8.3 | 6.1 | 4.95 | 4.96 | 23.1 |
| **Xeon, fast (s2n-bignum)** | 16.4 | 9.7 | 6.3 | 4.6 | **3.8** | 3.8 | 23.1 |

**RS256-3072** (the fast build uses libcrypto BN at this size on both machines)

| build \ batch | 1 | 2 | 4 | 8 | 16 | 32 | OpenSSL |
|---|---|---|---|---|---|---|---|
| M5, portable C, one at a time | 28.3 | 28.4 | 28.0 | 28.0 | 27.9 | 28.0 | 18.7 |
| M5, fast, one at a time | 18.0 | 17.7 | 17.6 | 17.6 | 17.5 | 17.5 | 18.7 |
| M5, portable C, screened | 27.9 | 16.1 | 10.2 | 7.2 | 5.9 | 5.8 | 18.7 |
| **M5, fast, screened** | 18.0 | 11.3 | 7.4 | 5.5 | **4.6** | 4.6 | 18.7 |
| Xeon, fast, one at a time | 41.7 | 41.2 | 41.1 | 41.0 | 40.9 | 40.9 | 43.7 |
| **Xeon, fast, screened** | 41.2 | 25.3 | 16.1 | 11.5 | **9.1** | 9.1 | 43.7 |

- **ES256's batch gain is small (~1.4× from batch 1 to 16):** it comes only from sharing the s⁻¹ inversion.
- **RSA's batch gain is the screening:** c tokens cost 2c + 17 multiplications against 19c.
  - Predicted speedups at batches 2, 4, 8 and 16: 1.8×, 3.0×, 4.6× and 6.2×.
  - Measured on the Xeon fast build: 1.7×, 2.6×, 3.6× and 4.3×.
  - The gap is per-token work that doesn't batch: SHA-256, building the PKCS#1 block, the base64url decode.
- **Batch 32 equals batch 16**, because the screening chunk is 16 tokens.
- **gcc vs clang on the Xeon:**
  - with the asm backends the two are within 6%;
  - with the portable C, gcc is 1.2–1.7× slower (exp79), so prefer clang for the C build on x86.

## Backends

| kernel | M5 | Xeon | used by the fast build |
|---|---|---|---|
| P-256 field: portable C (fiat-crypto + P-256 `fe_mul`) | 9.0 µs ES256 | 21.6 µs | — |
| P-256 field: s2n-bignum `bignum_montmul_p256` etc. | 9.2 µs (no gain) | **15.4 µs** | both (M5 harmless; Xeon −29%) |
| RSA-2048: portable C (product scanning, `_addcarry_u64` on x86) | 13.3 µs | 34.4 µs | — |
| RSA-2048: s2n-bignum `bignum_kmul_32_64` / `ksqr` + `emontredc_8n` | 13.2 µs | **16.4 µs** | Xeon |
| RSA-2048: libcrypto `BN_mod_exp_mont` / `BN_mod_mul_montgomery` | **8.4 µs** | 20.4 µs | M5 |
| RSA-3072/4096: libcrypto BN | **17.6 µs** | **41 µs** | both (s2n has no fixed kernel at these sizes) |

- **Arm64:** s2n-bignum's Montgomery reduction (`bignum_emontredc_8n`) costs ~490 ns by itself. OpenSSL's whole
  2048-bit square, `armv8-mont` sqr8x through the BN API, costs 343 ns. That's why libcrypto wins on arm.
- **x86-64:** s2n-bignum's `mulx`/`adcx`/`adox` code beats OpenSSL's `x86_64-mont5`, by 20% in a full RSA-2048
  verify.
- **The selection is `rsa_use_ossl()` in `src/jwt_pk.inc`.** x86-64 with `JWT_S2N` uses s2n-bignum for 2048-bit
  moduli and libcrypto above that; everything else uses libcrypto.
- **The x86 s2n-bignum build needs BMI2 and ADX** (Broadwell or later); it refuses to compile without them.
  Rosetta doesn't implement ADX, so it can't be run under Docker on a Mac. It was tested on the real Xeon.

## Comparison: algorithm × implementation × ns/token × licence

- **"meas."** numbers were measured here, as in the tables above (batch 16 unless noted). **"est."** numbers are
  estimates, with the reasoning given.
- **IFMA-only code** can't run on either target, so it is listed for completeness.

### ES256 (ECDSA P-256, SHA-256)

| implementation | technique | M5 µs | Xeon µs | licence |
|---|---|---|---|---|
| OpenSSL 3.x `ecp_nistz256` (Gueron–Krasnov asm) | fixed-base comb for G; wNAF for Q (~256 doublings) | **32.4–33.7** meas. | **78.6** meas. | Apache-2.0 |
| BoringSSL (nistz256 asm + fiat-crypto) | same algorithm as OpenSSL | ~30 est. | ~75 est. | Apache-2.0 (older files ISC) |
| AWS-LC + s2n-bignum (`p256_montjscalarmul`) | same shape, verified field ops | ~30 est. | ~70 est. | Apache-2.0 OR ISC (s2n-bignum also MIT-0) |
| Go `crypto/internal/fips140/nistec` | nistz256 port | ~35 est. | ~85 est. | BSD-3-Clause |
| ipp-crypto `crypto_mb` `mbx_nistp256_ecdsa_verify_ssl_mb8` | 8 tokens per zmm, 52-bit limbs | n/a (no IFMA) | n/a (no IFMA) | Apache-2.0 |
| **cursed-jwt, portable C** | **fixed-key combs for G and Q (W=8)**, projective x-check, batched s⁻¹ | **11.0** b1 / **9.0** b16 meas. | **28.2** b1 / **21.6** b16 meas. | MIT (+ fiat-crypto, MIT) |
| **cursed-jwt, fast (s2n-bignum field asm)** | the same, verified asm field ops | **10.8** b1 / **9.2** b16 meas. | **21.7** b1 / **15.4** b16 meas. | + s2n-bignum (MIT-0) |
| joint comb table (one add per window for both scalars) | 52 adds instead of 66, ~1.8 MB per key | ~8 est. | n/a: exceeds the 1 MB L2 | — |

- **Batch affine addition** (one shared inversion per step across tokens) breaks even with mixed Jacobian additions
  only at batches of ~64, so it isn't worth it.

### RS256 (RSASSA-PKCS1-v1_5, SHA-256, e = 65537)

| implementation | technique | M5 µs (2048 / 3072) | Xeon µs (2048 / 3072) | licence |
|---|---|---|---|---|
| OpenSSL 3.x `bn_mul_mont` (armv8-mont / x86_64-mont5) | 16 sqr + 1 mul, asm | **9.0 / 18.7** meas. | **23.1 / 43.7** meas. | Apache-2.0 |
| AWS-LC (s2n-bignum kernels inside libcrypto) | Karatsuba + verified Montgomery reduction | ~13 / – est. (as s2n here) | ~17 / – est. (as s2n here) | Apache-2.0 OR ISC |
| OpenSSL `rsaz-avx512` / AWS-LC IFMA RSA | 52-bit IFMA | n/a | n/a (no IFMA; also used for private-key CRT, not verify) | Apache-2.0 |
| ipp-crypto `crypto_mb` RSA public mb8 | 8 moduli per zmm, IFMA | n/a | n/a | Apache-2.0 |
| **cursed-jwt fast, one at a time** | libcrypto BN (M5, 3072) / s2n-bignum (Xeon 2048) | **8.4 / 17.6** meas. | **16.4 / 41** meas. | MIT + Apache-2.0 / MIT-0 |
| **cursed-jwt fast, screened, batch 16** | BGR screening, 2 mults/token + 1 exponentiation | **2.35 / 4.6** meas. | **3.8 / 9.1** meas. | same |
| cursed-jwt portable C, screened, batch 16 | | 2.7 / 5.9 meas. | 6.9 / – meas. | MIT |

- **No single-token win is possible here.** Verification is 19 Montgomery operations, and the libraries' asm already
  does them. The 1.4× over OpenSSL on the Xeon is s2n-bignum's kernel against `x86_64-mont5`, plus skipping EVP and
  padding parsing.
- **SME2 on the M5.** It has 16×16→64-bit outer products (`FEAT_SME_I16I64`). In principle that's a 2048-bit
  schoolbook product in tiles, but nothing public does it. It's research, not a borrowable implementation.

### EdDSA (Ed25519), for comparison (not prototyped)

| implementation | technique | M5 µs | Xeon µs | licence |
|---|---|---|---|---|
| OpenSSL 3.x | ref10-style, one at a time | **38.0** meas. (`openssl speed`) | **140.6** meas. (`openssl speed`) | Apache-2.0 |
| libsodium | ref10, strict RFC 8032 checks | ~30 est. | ~60 est. | ISC |
| curve25519-dalek / ed25519-dalek (AVX2 backend; `verify_batch`) | 4-way parallel field ops inside one point op; batch = Straus/Pippenger with random 128-bit coefficients, ~2× at batch 64 | ~20 single, ~10 batch est. | ~45 single, ~22 batch est. | BSD-3-Clause |
| ed25519-donna | 64-bit / SSE2; Bos–Coster batch verify | ~25 / ~12 est. | ~55 / ~28 est. | public domain |
| Firedancer `fd_ed25519` (AVX-512 IFMA) | 8-way IFMA, batch | n/a | n/a (IFMA) | Apache-2.0 |
| **fixed-key comb for A + B (the ES256 design)** | 2 × 32 extended-coordinate mixed adds, batched inversion for the R comparison | ~4 est. | ~15 est. | — |

- **Why the fixed-key estimate is that low.** A mixed addition in extended twisted Edwards coordinates is 7M
  (P-256 Jacobian: 11). A 2²⁵⁵−19 multiply (5×51-bit limbs) is ~0.7× a P-256 Montgomery multiply in C. So the
  cost is ~0.45× ES256, plus SHA-512 of R‖A‖M.
- **The semantics risk.** Batch Ed25519 (dalek, donna) can accept different signatures from single verification
  unless both use the cofactored equation (ZIP-215). A fixed-key single verify avoids that question entirely.
- **What it needs.** SHA-512 of R‖A‖M, which ties in with the SHA-512 work below. Tests: Wycheproof `ed25519_test.json` and RFC 8037 A.4.

## The prototype

```c
jwt_pkey_t *k = jwt_pkey_es256(x, y);        // or jwt_pkey_rs256(n, nlen, e, elen); NULL if invalid
jwt_verify_batch_pk(k, n, tok, len, time(NULL), out);   // same results and claim rules as jwt_verify_batch
jwt_pkey_free(k);
```

- **The key fixes the algorithm.** The header's `alg` must equal it, so a key never verifies another algorithm's
  tokens. The canonical header `{"alg":"ES256","typ":"JWT"}` is matched as bytes; anything else goes through the
  strict header parser.
- **ES256:**
  - Key setup checks the public point (coordinates < p, on the curve).
  - It builds signed-digit comb tables of `k·2^(8j)·P`, k = 1..128, for G and Q: 33 rows each, 528 KB per key,
    2.4 ms on the M5 and ~6 ms on the Xeon.
  - Verify:
    1. reject unless r, s ∈ [1, n−1] and the signature is exactly 64 bytes;
    2. e = SHA-256 mod n;
    3. all s⁻¹ of the batch with one inversion (Montgomery's trick, then a variable-time binary GCD, since s is
       public);
    4. u₁ = e·s⁻¹ and u₂ = r·s⁻¹, recoded to signed base-256 digits;
    5. 66 mixed additions;
    6. accept iff R ≠ ∞ and X ≡ r·Z² or (r + n)·Z² (mod p), the second only when r + n < p.
  - The mixed addition handles the exceptional cases (equal points → doubling, opposite points → infinity) by
    branching. That's fine for public data, but the code is deliberately not constant-time.
- **Field arithmetic:**
  - fiat-crypto's generated `p256_64.c` / `p256_scalar_64.c` (formally verified, MIT), fetched by
    `scripts/fetch-fiat.sh` at a pinned commit, plus my `fe_mul`.
  - `fe_mul` is a Montgomery CIOS that uses p's limb structure: −p⁻¹ ≡ 1 (mod 2⁶⁴), and p₂ = 0. Each round needs
    2 multiplications instead of 4.
  - `-DJWT_S2N` swaps in s2n-bignum's `bignum_montmul_p256`, `bignum_montsqr_p256`, `bignum_add_p256` and
    `bignum_sub_p256`. These are fetched by `scripts/fetch-s2n-bignum.sh` at a pinned commit, with every file
    SHA-256-checked.
  - Cross-checked against fiat on 200,000 random and edge inputs: both versions of mul/sqr/add/sub, and the scalar
    inverse.
- **RS256:**
  - 2048–4096-bit odd n and odd e < 2⁶⁴ (so the CAVP vectors with e ≠ 65537 run too). The signature must be
    exactly k bytes and < n.
  - The key holds R² mod n, −n⁻¹ mod 2⁶⁴, and the EMSA-PKCS1-v1_5 block with a zero hash as limbs.
  - Verification computes s^e and compares it word for word with the expected block. Nothing parses the decrypted
    block, so Bleichenbacher-style parsing bugs (garbage after the hash, short padding, a missing NULL) can't exist.
  - Montgomery multiplication is product scanning with a 3-word accumulator, plus a squaring that doubles the
    cross products.
    - **On x86 the accumulator goes through `_addcarry_u64`.** gcc compiled a plain `acc += z; c2 += acc < z` into
      branches and stack spills, which ran 6.7× slower than OpenSSL on the Xeon (exp75).
    - Fixed-size copies exist for 2048/3072/4096 bits.
  - **`-DJWT_S2N` (2048-bit moduli):** s2n-bignum's Karatsuba `bignum_kmul_32_64` / `bignum_ksqr_32_64` and
    `bignum_emontredc_8n`, which is how AWS-LC uses them. Cross-checked against the C on 20,000 random operands.
  - **`-DJWT_OPENSSL`:** libcrypto's `BN_mod_exp_mont` and `BN_mod_mul_montgomery`, with a `BN_MONT_CTX` cached in
    the key. The exact block compare and the screening algebra stay ours.
- **Screening (`-DJWT_RSA_SCREEN`):**
  - A = ∏ sᵢ and B = ∏ EMᵢ, each by chained Montgomery products of the raw values, so both carry R^−(c−1).
  - Accept the whole batch iff mont(pow(A·R, e), K_c) = B, where K_c = R^((c−1)(e−1)) mod n is precomputed per
    key for c ≤ 16.
  - Otherwise fall back to per-token verification, so honest results are unchanged.
  - Cost: 2c + 17 multiplications for c tokens, against 19c one at a time.

**Tests:** `make pk-test` runs 4 builds (portable C, screening, W=5, W=7); `pk-test-s2n` and `pk-test-fast` run
the asm backends with and without screening. Each build makes about 12,100 checks. All pass on:
- macOS arm64 (Apple clang), every build;
- Linux arm64 in Docker (gcc 13.3, clang 18.1), every build, plus ASan/UBSan on the fast screening build;
- Linux amd64 in Docker, the portable C builds plus ASan/UBSan (Rosetta can't run the ADX asm);
- the real Xeon: portable C with gcc (exp75/79), and the s2n, libcrypto and fast builds with clang (exp107/109/110).

HS256 is unchanged by the shared front end (`claims_one`, `header_ok` taking the alg). On the Xeon (exp79), full
verify is 277.9 ns at batch 8 and 1,178.7 at batch 1. The README had 277 and 1,178 at the time; batch 1 has since
moved to the extracted OpenSSL SHA-256 code (938 ns). `make test-vectors` passes on the M5.

The sources, all fetched by `scripts/fetch-vectors.sh` with pinned SHA-256s:

| source | vectors |
|---|---|
| Wycheproof `ecdsa_secp256r1_sha256_p1363_test.json` (JOSE r‖s format) | 262 (173 valid, 89 invalid) |
| Wycheproof `rsa_signature_{2048,3072,4096}_sha256_test.json` | 773 (non-"acceptable"; mostly invalid encodings) |
| NIST CAVP `SigVer.rsp` [P-256,SHA-256] | 15 |
| NIST CAVP `SigVer15_186-3.rsp`, SHA256, mod 2048/3072, assorted e | 36 |
| RFC 7515 A.2 (RS256) and A.3 (ES256) | live → BAD_PAYLOAD (no sub), expired → INVALID, tampered → INVALID |
| pyca/cryptography random: 6 RSA keys (2048/3072/4096, e = 3 and 65537), 8 P-256 keys, messages 0–1100 B, 15% corrupted, 15% high-s | 600 |
| pyca/cryptography tokens: alg mismatch, expired, bad signature, padding, missing username, header variants | 360 |

- **Every vector is checked against pyca/cryptography first** (`tests/make_pk_vectors.py`), so a parsing mistake
  can't pass silently.
  - NIST's RSA file prints messages and signatures without leading zero nibbles. The cross-check is what caught
    that.
- **How each vector runs.** Alone, inside random sub-batches with repeats, and with its whole key group shuffled
  into one batch. That way invalid signatures sit beside valid ones, which exercises the shared inversion and the
  screening fallback.
- **Screening's documented weakness is a test.** 4 pairs (s₁·x, s₂/x) must be rejected one at a time and by
  default. The screening build reports that it accepts them (4/4).
- **Mutation checks.**
  - Flipping one expected result fails the run.
  - Planting an always-accept for one lane fails 64 checks.
  - A W=8 build first failed 22/64 tokens: the signed digit ±128 overflowed `int8_t`. That's why `pk-test` now runs
    other window sizes too.

## Screening: what it does and doesn't prove

- **What a pass means.** If the batch passes, (∏ sᵢ)^e ≡ ∏ EMᵢ.
- **What an attacker gains.** Suppose an attacker holds genuine signatures σᵢ on some of the messages. Then
  accepting one unsigned message m* means EM* = (∏ sᵢ / ∏ σⱼ)^e, i.e. a forgery. More generally, an accepted batch
  hands the attacker an e-th root of a product of PKCS#1 encodings. That is the multiplicative-forgery problem
  plain RSA-PKCS1-v1_5 verification already relies on. It's believed hard for full-size padding, but unlike screening
  for RSA-FDH it isn't proven.
- **What it doesn't give.** Uniqueness of the token string. Two genuine tokens whose signatures are re-randomised
  as s₁·x, s₂/x verify together; on their own both fail. The claims are still authentic. But if anything keys on the
  raw token or signature (a cache of "already verified" strings, a revocation list of token hashes), batching
  changes the answer.
- **The DoS angle.** One bad token makes the whole batch take the fallback: batch cost + per-token cost, ~1.2× the
  non-screening cost. An attacker can't make it worse than that.
- **Random small exponents (the classic "small exponent test").** They would close the malleability gap. But each
  64-bit exponent costs more multiplications than the 17 it replaces.

## HS384 / HS512

- **The method carries over directly.**
  - The multi-buffer template (`src/jwt_mb.inc`) generalises to 64-bit words, with 128-byte blocks and 80 rounds:
    - ymm AVX-512VL ×4 lanes using `vprorq`/`vpternlogq`;
    - AVX2 ×4;
    - the ARMv8.2 SHA512 instructions on the M5 (`vsha512hq_u64` etc., `__ARM_FEATURE_SHA512` is defined), with
      interleaved streams like the SHA-256 engine.
  - A ~140-byte signing input is 2 inner blocks + 1 outer: 240 rounds against SHA-256's 256, at half the lanes.
- **Expected costs:**
  - Xeon: ~280–300 ns of HMAC per token at batch 4–8 (HS256: 154).
  - M5: OpenSSL hashes SHA-512 at ~1.0 GB/s against SHA-256's 1.8 GB/s (`openssl speed`), so roughly 1.5–2× the
    HS256 cost.
- **Prior art:**
  - intel-ipsec-mb `sha512_x4_avx2` / `x8_avx512` (BSD-3-Clause);
  - isa-l_crypto `sha512_mb` (BSD-3-Clause);
  - OpenSSL `sha512-armv8` (Apache-2.0).
- **Not prototyped.** You asked for RSA/EC instead.

## Next steps

1. **Ed25519 with fixed-key combs and SHA-512.**
   - Same API.
   - s2n-bignum has verified `edwards25519` field and point code to borrow (`bignum_mul_p25519`,
     `edwards25519_scalarmuldouble`).
   - Tests: Wycheproof `ed25519_test.json` and RFC 8037.
2. **JWKS input.** `jwt_pkey_from_jwk()` for `{"kty":"RSA","n","e"}` and `{"kty":"EC","crv":"P-256","x","y"}`,
   plus `kid` selection across keys.
3. **Batch the SHA-256 of signing inputs** through the multi-buffer engine.
   - It's ~0.7 µs per token on the Xeon's scalar path: ~5% of ES256, but ~20% of screened RS256 at batch 16.
   - It's also part of why the measured screening ratios trail the predicted ones.
4. **Make the fast build the `-DJWT_PK` default.**
   - It currently needs libcrypto and the s2n-bignum fetch.
   - A build that has neither falls back to the portable C, which is still 2.8–3.6× ahead of OpenSSL on ES256.
