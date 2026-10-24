# RS256, ES256 and EdDSA in cursed-jwt: survey, prototype, numbers

This covers asymmetric JWT algorithms. HS384/HS512 get a short note at the end.

- **Targets:**
  - Apple M5 Pro: ARMv8 SHA2/SHA512 and NEON, no AVX-512 IFMA equivalent.
  - Xeon Platinum 8260 (Cascade Lake): AVX-512F/BW/VL/DQ, **no IFMA**, no SHA-NI, 1 vCPU KVM, OpenSSL 3.0.13.
- **Prototype:** `src/jwt_pk.inc`, built with `-DJWT_PK`, behind `jwt_verify_batch_pk` (same front end and claim
  rules as `jwt_verify_batch`).
- **Tests:** `make pk-test` checks it against Wycheproof, NIST CAVP, RFC 7515 A.2/A.3 and pyca/cryptography.

## Summary

- **Batching works very differently here from HS256.**
  - For HMAC, one SIMD register can hold 8 tokens' state.
  - For RSA and ECC, the work is 64×64-bit multiply chains. SIMD across tokens needs 52-bit vector multipliers
    (AVX-512 IFMA), which Cascade Lake doesn't have. With ymm `vpmuludq` (32×32→64) it would at best match scalar
    `mulx`.
  - Intel's multi-buffer RSA/ECDSA/Ed25519 (`crypto_mb` in ipp-crypto) requires IFMA. So on both targets the
    levers are algebraic, not SIMD.
- **ES256: build per-key tables, then two fixed-base multiplications.**
  - A JWT verifier holds a few long-lived public keys, so the key setup can precompute a comb table for **Q** as
    well as for G (2.4 ms and 528 KB per key on the M5).
  - A verify is then 2 × 33 mixed additions with no doublings. Compare OpenSSL's ~256 doublings + ~90 additions.
  - The x-coordinate check is projective (X = r·Z²), so a token needs no field inversion. All the s⁻¹ in a batch
    share one inversion.
  - **Measured: 2.0–3.5× faster than OpenSSL**, at batch 1 too:

    | | M5 | Xeon |
    |---|---|---|
    | cursed-jwt, batch 16 | 9.0–9.8 µs | 37.6 µs |
    | OpenSSL | 31.6–33.7 µs | 76.3 µs |

  - The field arithmetic is portable C (fiat-crypto's verified code, plus a P-256-specific Montgomery multiply).
    Swapping in assembly (OpenSSL's ecp_nistz256 or AWS's s2n-bignum) is the obvious next step.
- **RS256: single-token verification can't get past parity; batch screening can.**
  - e = 65537 means 16 squarings + 1 multiply, and OpenSSL already does exactly that with hand-written
    `bn_mul_mont`. My portable C Montgomery multiply is 1.5× slower than OpenSSL per token on the M5.
  - **Screening** (Bellare–Garay–Rabin) checks a whole batch with one exponentiation:

    (∏ sᵢ)^e ≡ ∏ EMᵢ (mod n)

    That is 2 multiplications per token + 17 per batch, instead of 19 per token. On the M5, RSA-2048 costs
    **2.7–2.8 µs per token at batch 16, against OpenSSL's 8.4–8.9 µs (3.1×)**.
  - **The catch:** screening proves that every *message* was signed. It does not prove that every *signature string*
    is the canonical one: s₁·x and s₂/x pass together. So it's opt-in (`-DJWT_RSA_SCREEN`); see below.
- **EdDSA isn't prototyped yet, but it is where the biggest ratio is.** OpenSSL's Ed25519 verify is slow (38 µs on
  the M5, 141 µs on the Xeon). The ES256 fixed-key trick applies unchanged (verify = [S]B − [k]A, A fixed per key),
  and Edwards additions are cheaper than P-256 Jacobian ones.
- **Recommendation:**
  1. Keep ES256 (fixed-key comb) as the asymmetric path.
  2. Move its field arithmetic to s2n-bignum's verified P-256 assembly (Apache-2.0 / ISC / MIT-0).
  3. Do Ed25519 the same way next.
  4. Offer RS256 with single verification by default and screening as an explicit batch option.
  5. RS256 is the algorithm most OIDC providers default to (Google, Microsoft Entra, Auth0, Okta), so it matters
     most in practice even though it gains least.

## Comparison: algorithm × implementation × ns/token × licence

- **"meas."** numbers were measured here:
  - M5: `bench/bench_pk.c`, best of 3, under a load average of ~7, with ±10% noise;
  - Xeon: broker experiments exp75/exp79.
- **"est."** numbers are estimates, and the reasoning is given.
- **OpenSSL** numbers are `EVP_DigestVerify` with the key parsed once (`openssl speed` agrees within 10%).
- **IFMA-only code** can't run on either target, so it is listed for completeness.

### ES256 (ECDSA P-256, SHA-256)

| implementation | technique | M5 µs | Xeon µs | licence |
|---|---|---|---|---|
| OpenSSL 3.x `ecp_nistz256` (Gueron–Krasnov asm) | fixed-base comb for G; wNAF for Q (~256 doublings) | **32.4** meas. | **78.7** meas. | Apache-2.0 |
| BoringSSL (nistz256 asm + fiat-crypto) | same algorithm as OpenSSL | ~30 est. | ~75 est. | Apache-2.0 (older files ISC) |
| AWS-LC + s2n-bignum (`p256_montjscalarmul`, formally verified asm) | same shape, verified field ops | ~30 est. | ~70 est. | Apache-2.0 OR ISC (s2n-bignum also MIT-0) |
| Go `crypto/internal/fips140/nistec` | nistz256 port | ~35 est. | ~85 est. | BSD-3-Clause |
| ipp-crypto `crypto_mb` `mbx_nistp256_ecdsa_verify_ssl_mb8` | 8 tokens per zmm, 52-bit limbs | n/a (no IFMA) | n/a (no IFMA) | Apache-2.0 |
| **cursed-jwt prototype** (fiat-crypto C + P-256-specific `fe_mul`) | **fixed-key combs for G and Q (W=8)**, projective x-check, batched s⁻¹ | **11.1–12.0** b1 / **9.0–9.8** b16 meas. | **45.5** b1 / **37.6** b16 meas. | MIT (fiat-crypto MIT) |
| same with s2n-bignum or nistz256 field asm | swap `fe_mul`/`fe_sqr`/add/sub | ~7 est. | ~20 est. | + Apache-2.0 / MIT-0 |
| joint comb table (one add per window for both scalars) | 52 adds instead of 66, ~1.8 MB per key | ~8 est. | n/a: exceeds the 1 MB L2 | — |

- **The "with asm" estimates.** The prototype makes ~730 field multiplications per verify:
  - The Xeon spends ~51 ns per multiplication, all-in. gcc's 128-bit C is the weak spot there. OpenSSL does
    ~3,300 field operations (~256 doublings, ~90 additions) in 78.7 µs: ~24 ns each with nistz256's `mulx`/`adx`
    asm, about 2× faster per operation.
  - On the M5 the gap is smaller (C ≈ 43 cycles of latency per multiply).
- **Batching** adds ~15% from batch 1 to batch 16, because all the s⁻¹ share one inversion.
  - True multi-token SIMD needs IFMA.
  - "Batch affine addition" (one shared inversion per step across tokens) breaks even with mixed Jacobian additions
    only at batches of ~64, so it isn't worth it.

### RS256 (RSASSA-PKCS1-v1_5, SHA-256, e = 65537)

| implementation | technique | M5 µs (2048 / 3072) | Xeon µs (2048 / 3072) | licence |
|---|---|---|---|---|
| OpenSSL 3.x `bn_mul_mont` (armv8-mont / x86_64-mont5, mulx/adx) | 16 sqr + 1 mul, asm | **9.4 / 18.7** meas. | **22.8 / 43.9** meas. | Apache-2.0 |
| AWS-LC (s2n-bignum `bignum_kmul_32_64` + `bignum_emontredc_8n`) | Karatsuba + verified Montgomery reduction | ~8 / ~17 est. | ~20 / ~40 est. | Apache-2.0 OR ISC / MIT-0 |
| OpenSSL `rsaz-avx512` / AWS-LC IFMA RSA | 52-bit IFMA | n/a | n/a (no IFMA; also used for private-key CRT, not verify) | Apache-2.0 |
| ipp-crypto `crypto_mb` RSA public mb8 | 8 moduli per zmm, IFMA | n/a | n/a | Apache-2.0 |
| **cursed-jwt prototype**, per token | product-scanning Montgomery in C, dedicated squaring | **13.3–14.6 / 28–33** meas. | XEON_RS_SINGLE meas. | MIT |
| **cursed-jwt `-DJWT_RSA_SCREEN`**, batch 16 | BGR screening, 2 mults/token + 1 exponentiation | **2.7–2.8 / 5.9–6.1** meas. | XEON_RS_SCREEN meas. | MIT |
| screening + OpenSSL-class multiply (s2n-bignum) | | ~1.8 / ~4 est. | ~5 / ~10 est. | + Apache-2.0 / MIT-0 |

- **Ceiling without screening.** Verification is 19 Montgomery operations, which OpenSSL already does in asm.
  Beating it per token needs a better multiplier, and the only candidate is IFMA.
- **SME2 on the M5.** It has 16×16→64-bit outer products (`FEAT_SME_I16I64`). In principle that's a 2048-bit
  schoolbook product in tiles, but nothing public does it. It's research, not a borrowable implementation.
- **Ratio vs batch size.** Screening c tokens costs 2c + 17 multiplications against 19c, which predicts 1.8×, 3.0×,
  4.6× and 6.2× at batches 2, 4, 8 and 16. Measured on the M5: 13.3 → 7.6 → 4.8 → 3.4 → 2.7 µs, i.e. 1.75×, 2.8×,
  3.9× and 4.9×. The gap is the per-token work that doesn't batch: SHA-256, building the PKCS#1 block, base64url.

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
  - Two things are cross-checked against fiat on 200,000 random and edge inputs: `fe_mul`/`fe_sqr`, and the
    scalar inverse.
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
- **Screening (`-DJWT_RSA_SCREEN`):**
  - A = ∏ sᵢ and B = ∏ EMᵢ, each by chained Montgomery products of the raw values, so both carry R^−(c−1).
  - Accept the whole batch iff mont(pow(A·R, e), K_c) = B, where K_c = R^((c−1)(e−1)) mod n is precomputed per
    key for c ≤ 16.
  - Otherwise fall back to per-token verification, so honest results are unchanged.
  - Cost: 2c + 17 multiplications for c tokens, against 19c one at a time.

**Tests** (`make pk-test`, about 12,150 checks per build; it runs 4 builds: default, screening, W=5, W=7). All pass
on:
- macOS arm64 (Apple clang);
- Linux arm64 and amd64 in Docker (gcc 13.3, clang 18.1, plus ASan/UBSan);
- the real Xeon (gcc 13.3).

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

1. **ES256 field arithmetic in verified asm.**
   - Fetch s2n-bignum at a pinned commit and link `bignum_montmul_p256`, `bignum_montsqr_p256` and the
     add/sub/neg routines for arm64 and x86-64.
   - Expected: Xeon ~38 → ~20 µs, M5 ~9.5 → ~7 µs.
   - s2n-bignum is Apache-2.0 OR ISC OR MIT-0; the MIT-0 option needs no notice.
   - The same library's `bignum_kmul_32_64`/`bignum_ksqr_32_64` + `bignum_emontredc_8n` would bring RS256 to
     OpenSSL parity per token, and make screening ~1.5× cheaper again.
   - This wasn't done here: the sandbox refused to assemble and run third-party asm that hadn't been reviewed.
2. **Ed25519 with fixed-key combs and SHA-512.** Same API, tested against Wycheproof `ed25519_test.json` and
   RFC 8037.
3. **JWKS input.** `jwt_pkey_from_jwk()` for `{"kty":"RSA","n","e"}` and `{"kty":"EC","crv":"P-256","x","y"}`,
   plus `kid` selection across keys.
4. **Batch the SHA-256 of signing inputs** through the multi-buffer engine. It's ~0.7 µs per token on the Xeon's
   scalar path: ~2% of ES256, but 10–25% of screened RS256.
