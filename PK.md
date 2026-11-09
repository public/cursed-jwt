# RS256, ES256 and EdDSA in cursed-jwt: survey, design, numbers

This covers asymmetric JWT algorithms. HS384/HS512 get a short note at the end.

- **Targets:**
  - Apple M5 Pro: ARMv8 SHA2/SHA512 and NEON, no AVX-512 IFMA equivalent.
  - Xeon Platinum 8260 (Cascade Lake): AVX-512F/BW/VL/DQ, **no IFMA**, no SHA-NI, 1 vCPU KVM, OpenSSL 3.0.13.
- **Code:** `crypto/src/cc_pk.c`, in the default build (`-DJWT_NO_PK` leaves it out), behind `jwt_verify_batch_pk` (same front end and claim
  rules as `jwt_verify_batch`).
- **Three arithmetic backends**, chosen at compile time:
  - portable C (the default; no dependencies beyond fiat-crypto's generated C);
  - `-DJWT_S2N`: AWS s2n-bignum's formally verified assembly for the P-256 field and RSA-2048;
  - `-DJWT_OPENSSL`: libcrypto's BN Montgomery assembly for RSA.

  The **fast build** is `-DJWT_S2N -DJWT_OPENSSL`. It picks the kernel that measured fastest per platform and key
  size (see [Backends](#backends)).
- **Tests:** `make pk-test` / `pk-test-s2n` / `pk-test-fast` check every build against Wycheproof, NIST CAVP,
  RFC 7515 A.2/A.3, RFC 8032, RFC 8037 and pyca/cryptography.

## Summary

- **Batching works very differently here from HS256.**
  - For HMAC, one SIMD register holds 8 tokens' state.
  - For RSA and ECC, the work is 64×64-bit multiply chains. SIMD across tokens needs 52-bit vector multipliers
    (AVX-512 IFMA), which Cascade Lake doesn't have. With ymm `vpmuludq` (32×32→64) it would at best match scalar
    `mulx`.
  - Intel's multi-buffer RSA/ECDSA/Ed25519 (`crypto_mb` in ipp-crypto) requires IFMA. So on both targets the
    levers are algebraic, not SIMD.
  - The library still uses crypto_mb on CPUs that do have IFMA (`-DJWT_CRYPTO_MB`, below). It's chosen at run
    time, like every other kernel here.
- **ES256: per-key comb tables, then two fixed-base multiplications.**
  - A JWT verifier holds a few long-lived public keys, so key setup precomputes a comb table for **Q** as well as
    for G (2.4 ms and 528 KB per key on the M5).
  - A verify is then 2 × 33 mixed additions with no doublings. Compare OpenSSL's ~256 doublings + ~90 additions.
  - The x-coordinate check is projective, so a token needs no field inversion. All the s⁻¹ of a batch share one
    inversion.
  - **Fast build, batch 16: 3.5× faster than OpenSSL on the M5, 5.3× on the Xeon** (14.9 vs 78.8 µs). Already
    3.0× / 3.6× at batch 1.
- **RS256: one-at-a-time verification is at OpenSSL parity (it's the same 19 Montgomery operations); batch
  screening is far ahead.**
  - **Screening** (Bellare–Garay–Rabin) checks a whole batch with one exponentiation:

    (∏ sᵢ)^e ≡ ∏ EMᵢ (mod n)

    That's 2 multiplications per token + 17 per batch, instead of 19 per token.
  - Fast build, RSA-2048 at batch 16: **3.8× faster than OpenSSL on the M5, 7.2× on the Xeon** (3.16 vs 22.9 µs).
  - **The catch:** screening proves that every *message* was signed. It does not prove that every *signature string*
    is the canonical one: s₁·x and s₂/x pass together. So it's opt-in (`-DJWT_RSA_SCREEN`); see below.
- **EdDSA (Ed25519): the biggest ratio.** OpenSSL's Ed25519 verify is slow (40 µs on the M5, 150 µs on the Xeon).
  The ES256 fixed-key trick applies unchanged: verify = `[S]B + [k](−A)`, with comb tables for B and −A built at key
  setup, and Edwards additions are cheaper than Jacobian ones.
  - **Portable C, batch 32: 8.8× faster than OpenSSL on the M5 (4.6 vs 40.4 µs), 9.2× on the Xeon (16.3 vs
    150.2 µs).** Already 6.2× / 7.0× at batch 1.
- **Recommendation:**
  1. Ship the fast build's backend choice as the default for the default build, and keep the portable C as the fallback
     when it has no dependencies.
  2. Keep RS256 screening as an explicit batch option.
  3. Ed25519 is done the same way; give it s2n-bignum's verified `p25519` field asm next (see Next steps).
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
  - Xeon: clang 18, `-O3 -march=cascadelake`, one run per build (C, s2n, OpenSSL BN, fast).

**ES256**

| build \ batch | 1 | 2 | 4 | 8 | 16 | 32 | OpenSSL |
|---|---|---|---|---|---|---|---|
| M5, portable C | 11.0 | 9.6 | 9.4 | 9.1 | 9.0 | 9.0 | 32.4 |
| M5, fast (s2n-bignum P-256) | 10.8 | 9.6 | 9.4 | 9.3 | 9.2 | 9.2 | 32.4 |
| Xeon, portable C | 28.2 | 24.7 | 23.0 | 22.1 | 21.6 | 21.4 | 78.6 |
| **Xeon, fast (s2n-bignum P-256)** | **21.8** | 18.3 | 16.3 | 15.3 | **14.9** | 14.8 | 78.8 |

**EdDSA (Ed25519)**, portable C only (fiat-crypto curve25519 field; Xeon, clang 18)

| build \ batch | 1 | 2 | 4 | 8 | 16 | 32 | OpenSSL |
|---|---|---|---|---|---|---|---|
| **M5, portable C** | **6.5** | – | – | – | – | **4.6** | 40.4 |
| **Xeon, portable C** | **21.5** | 18.9 | 17.5 | 17.0 | 16.5 | **16.3** | 150.2 |

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
| **Xeon, fast (s2n-bignum)** | 16.2 | 9.3 | 5.8 | 4.1 | **3.16** | 3.15 | 22.9 |

**RS256-3072** (the fast build uses libcrypto BN at this size on both machines)

| build \ batch | 1 | 2 | 4 | 8 | 16 | 32 | OpenSSL |
|---|---|---|---|---|---|---|---|
| M5, portable C, one at a time | 28.3 | 28.4 | 28.0 | 28.0 | 27.9 | 28.0 | 18.7 |
| M5, fast, one at a time | 18.0 | 17.7 | 17.6 | 17.6 | 17.5 | 17.5 | 18.7 |
| M5, portable C, screened | 27.9 | 16.1 | 10.2 | 7.2 | 5.9 | 5.8 | 18.7 |
| **M5, fast, screened** | 18.0 | 11.3 | 7.4 | 5.5 | **4.6** | 4.6 | 18.7 |
| Xeon, fast, one at a time | 41.7 | 41.2 | 41.1 | 41.0 | 40.9 | 40.9 | 43.7 |
| **Xeon, fast, screened** | 41.4 | 25.1 | 15.7 | 10.9 | **8.6** | 8.6 | 43.9 |

- **ES256's batch gain is small (~1.4× from batch 1 to 16):** it comes only from sharing the s⁻¹ inversion.
  EdDSA's (~1.3×) is the same thing for the Z⁻¹ that encodes R′: one inversion per chunk of 32 tokens.
- **RSA's batch gain is the screening:** c tokens cost 2c + 17 multiplications against 19c.
  - Predicted speedups at batches 2, 4, 8 and 16: 1.8×, 3.0×, 4.6× and 6.2×.
  - Measured on the Xeon fast build: 1.7×, 2.8×, 3.9× and 5.1×.
  - The gap is per-token work that doesn't batch: building the PKCS#1 block, the base64url decode, converting the
    signature.
  - **The signing-input SHA-256 is now batched.** Each chunk's inputs go through the multi-buffer engines: 8 lanes
    on AVX-512VL/AVX2, 4 SHA2 streams on ARM. On the Xeon that took screened RS256-2048 from 3.78 to 3.16 µs and
    ES256 from 15.4 to 14.9 µs. On the M5 it's within noise, because a single SHA2 stream was already
    ~0.1 µs per token.
- **Interleaving ES256 tokens** (`JWT_ES_ILV`, running the point additions of 2–4 tokens in lockstep) gained
  nothing on either machine: 8.86–8.90 vs 8.87 µs on the M5, 14.78–14.90 vs 14.80 on the Xeon. The out-of-order
  cores already overlap the chains, so the default is 1.
- **Batch 32 equals batch 16**, because the screening chunk is 16 tokens.
- **gcc vs clang on the Xeon:**
  - with the asm backends the two are within 6%;
  - with the portable C, gcc is 1.2–1.7× slower, so prefer clang for the C build on x86.

## Backends

| kernel | M5 | Xeon | used by the fast build |
|---|---|---|---|
| P-256 field: portable C (fiat-crypto + P-256 `fe_mul`) | 9.0 µs ES256 | 21.6 µs | — |
| P-256 field: s2n-bignum `bignum_montmul_p256` etc. | 9.2 µs (no gain) | **15.4 µs** | both (M5 harmless; Xeon −29%) |
| P-256 field: s2n-bignum `bignum_montmul_p256_alt` / `_montsqr_p256_alt` (no BMI2/ADX needed) | n/a | x86-64 without BMI2/ADX | both, on such CPUs and VMs: see below |
| RSA-2048: portable C (product scanning, `_addcarry_u64` on x86) | 13.3 µs | 34.4 µs | — |
| RSA-2048: s2n-bignum `bignum_kmul_32_64` / `ksqr` + `emontredc_8n` | 13.2 µs | **16.4 µs** | Xeon |
| RSA-2048: libcrypto `BN_mod_exp_mont` / `BN_mod_mul_montgomery` | **8.4 µs** | 20.4 µs | M5 |
| RSA-3072/4096: libcrypto BN | **17.6 µs** | **41 µs** | both (s2n has no fixed kernel at these sizes) |
| RSA-2048: OpenSSL's AVX-512 IFMA `ossl_rsaz_amm52x40_x1_ifma256` (`-DJWT_RSAZ`) | n/a | n/a (no IFMA) | not yet (opt-in): see below |

- **Arm64:** s2n-bignum's Montgomery reduction (`bignum_emontredc_8n`) costs ~490 ns by itself. OpenSSL's whole
  2048-bit square, `armv8-mont` sqr8x through the BN API, costs 343 ns. That's why libcrypto wins on arm.
- **x86-64:** s2n-bignum's `mulx`/`adcx`/`adox` code beats OpenSSL's `x86_64-mont5`, by 20% in a full RSA-2048
  verify.
- **The choice is made at run time** from the CPU's features, so a build containing every backend runs on any
  machine:
  - `s2n_ok()`: on x86-64, s2n-bignum's kernels run only with BMI2 + ADX. The P-256 point arithmetic is compiled
    three times (`crypto/src/cc_pk_ec.inc`: with C, with s2n-bignum's field operations, and on x86-64 with its ADX-free
    `_alt` multiply / square), and one is picked per batch.
  - Some VMs hide BMI2/ADX from the guest; Vultr's Genoa and Cascade Lake guests do. There the `_alt` kernels
    replace fiat C. ES256 full verify (1 vCPU, gcc -O3, 7 interleaved rounds):
    - Genoa: 30.2 → 21.2 µs at batch 1, 25.0 → 16.0 µs at batch 16.
    - Cascade Lake: 41.8 → 26.5 µs, 33.9 → 18.4 µs.
    - Turin, which exposes ADX: unchanged (±0.2%).
  - `rsa_use_ossl()` / `mont_for()`: RSA-2048 on x86-64 uses s2n-bignum when BMI2 + ADX are present, otherwise
    libcrypto (if built in), otherwise C. Larger moduli and ARM use libcrypto.
  - `cmb_ok()`: crypto_mb runs only with AVX-512 IFMA (below).
  - `ifma_ok()`: with `-DJWT_RSAZ`, RSA-2048 runs on OpenSSL's IFMA multiply only with AVX-512 IFMA + VL (below).
  - On the Xeon, the fast build passes every vector both with s2n-bignum and with BMI2/ADX masked off
    (`JWT_CPU_MASK=0x3`).
- **Rosetta doesn't implement ADX,** so the x86 s2n-bignum kernels can't run under Docker on a Mac. They were
  tested on the real Xeon.

### AVX-512 IFMA: Intel crypto_mb (`-DJWT_CRYPTO_MB`)

- **What it gives.** On CPUs with IFMA (Ice Lake and later Xeons; Zen 4 has IFMA too), Intel's crypto_mb verifies
  8 ES256 signatures, or runs 8 RSA-65537 public-key operations, per call, in 52-bit vector lanes. That's the SIMD
  across tokens that Cascade Lake can't do.
  - It's cryptography-primitives v2.3.0, Apache-2.0. `scripts/build-crypto-mb.sh` fetches it pinned and
    SHA-256-checked, and builds it.
- **How it's wired in:**
  - **ES256:** after the structural checks and the batched hashing, groups of 8 go to
    `mbx_nistp256_ecdsa_verify_mb8`.
  - **RS256:** with e = 65537 and a 2048/3072/4096-bit modulus, the exponentiations go to `mbx_rsa_public_mb8`,
    and the result is compared with the expected PKCS#1 block as before. Screening, when enabled, still runs
    first, because it's cheaper per token.
  - **Byte order** comes from Intel's own known-answer tests: big-endian r, s, digests and RSA strings;
    little-endian key limbs.
- **Status: compile-tested only.**
  - The integration is syntax-checked for x86-64 against crypto_mb's real headers.
  - crypto_mb's build needs CMake ≥ 3.18, NASM and OpenSSL ≥ 3.5.5 headers (Ubuntu 24.04 ships 3.0).
  - Neither test machine has IFMA. `make pk-test-ifma` runs the full vector set through it, and the test prints
    whether the IFMA path was active, so it's ready for an IFMA machine.
  - `make pk-bench-ifma` benchmarks it, then repeats the same binary with IFMA masked off for comparison.
  - It isn't yet known whether crypto_mb beats the fixed-key comb tables on ES256. Intel's code doesn't exploit
    a fixed key; ours does.

### AVX-512 IFMA: 8-lane ES256 comb on crypto_mb's field (`-DJWT_ES8`)

- **What it is.** The ES256 comb additions for 8 tokens at once, one per 64-bit zmm lane, on crypto_mb's 8-lane
  P-256 field arithmetic (`ifma_arith_p256.c` / `ifma_arith_m256.c`, cryptography-primitives @ 316ce55, Apache-2.0,
  fetched pinned by `scripts/fetch-crypto-mb-rsa.sh`). `crypto/src/cmb_ec/es8.c` #includes them unchanged and builds into
  `build/libcmbec.a`; only its `cc_es8_*` symbols stay global.
  - Not `mbx_nistp256_ecdsa_verify_mb8` itself: that has no per-key precompute and needs ~5,000 field multiplies
    per token, against our ~730.
- **How it works:**
  - The per-key comb tables are read in place, with no second copy. Each lane gathers its own entry, which is moved
    into crypto_mb's radix-2^52, R = 2^260 domain on the way in: ×16, then one Solinas fold, no multiply.
  - The addition is the scalar code's madd-2007-bl (7M + 4S), with "at infinity" kept as a lane mask.
  - The exceptional cases (acc = ±q) aren't branched on. They make H = 0, and Z stays 0 from then on. A lane that
    ends with Z = 0 or at infinity, and the rare r + n < p candidate, is redone by the scalar code, so the results
    are always the scalar code's.
  - The batched s⁻¹ inversion and the recoding are unchanged.
- **When it runs.** On IFMA CPUs where zmm costs no clock speed (FAST_ZMM: AMD Zen 4 / 5), for groups of at least
  `JWT_ES8_MIN` (3) tokens. A short last group is padded. Batch 1 never takes it.
- **Measured.** Raw verify per token on 570-byte signing inputs, gcc -O3, 1–2 vCPU Vultr VMs, median of 7 interleaved
  rounds, against the same tree without it:

  | CPU | b1 | b3 | b4 | b8 | b16 | b32 |
  |---|---:|---:|---:|---:|---:|---:|
  | Turin (Zen 5) | 14.3 → 14.3 µs | 11.3 → 8.8 | 10.7 → 6.8 | 9.76 → 3.65 | **9.42 → 3.33** (2.8×) | 9.25 → 3.17 |
  | Genoa (Zen 4) | 20.6 → 20.5 | 17.3 → 12.5 | 16.8 → 9.3 | 15.9 → 5.12 | **15.5 → 4.83** (3.2×) | 15.2 → 4.61 |

  With the 8-lane group used from 2 tokens, b2 was +3.6% on Turin and −2% on Genoa, hence the minimum of 3.
- **Tests** (`make pk-test-es8`; on Intel run them under SDE with `JWT_CPU_FORCE_ZMM=1`):
  - the 8-lane field ops against fiat-crypto on [0, 2p) with edge values;
  - the 8-lane accumulators against the scalar chain, including Q = G with d₂ = ±d₁, which forces both exceptional
    cases;
  - the verdicts against `es_points_c`;
  - batches of 8 and 16 with one bad signature in every lane position;
  - the full vector set.

### AVX-512 IFMA: OpenSSL's RSA-2048 multiply (`-DJWT_RSAZ`)

- **What it gives.** One token at a time, RSA-2048 verification in 52-bit digits on IFMA CPUs. It's the fastest
  single-token RS256 measured. Full verify (`jwt_verify_batch_pk`, batch 1, ~920-byte OIDC-style tokens, gcc -O3,
  1 vCPU, 7 interleaved rounds):

  | CPU | `-DJWT_RSAZ` | fast build without it | jwt-simple (BoringSSL) | jsonwebtoken (aws-lc-rs) |
  |---|---:|---:|---:|---:|
  | AMD EPYC Genoa (Zen 4) | **6.98 µs** | 24.8 µs | 27.9 µs | 28.6 µs |
  | AMD EPYC Turin (Zen 5) | **6.69 µs** | 11.7 µs | 18.7 µs | 19.3 µs |

  The same binary with IFMA masked off (`JWT_CPU_MASK=0xffffffef`) matches the fast build within 1.3%.
- **The kernel.** `ossl_rsaz_amm52x40_x1_ifma256`, from OpenSSL's `crypto/bn/asm/rsaz-4k-avx512.pl`, is Intel's
  almost-Montgomery multiplication of 40-digit numbers in radix 2^52, on ymm registers (so no zmm clock drop).
  OpenSSL uses it only for the private-key CRT halves of RSA-4096. `scripts/fetch-ossl-rsaz.sh` fetches it and
  OpenSSL's perlasm translator at a pinned commit, SHA-256-checked, and generates `build/rsaz-4k-avx512.S`.
- **How it's wired in.**
  - Key setup adds n and R'^2 = 2^4160 mod n in radix 2^52 (64 more modular doublings after R^2).
  - A verify is to-Montgomery, 16 squarings and 1 multiplication for e = 65537 (any odd e works), and one AMM by
    1 out of the Montgomery domain.
  - The result is checked to be normalised and below 2^2048, reduced once, and compared with the expected
    PKCS#1 block.
  - Screened batches (`-DJWT_RSA_SCREEN`, c ≥ 2) still take the screening path. Every other RS256-2048 token
    takes this path when the CPU has IFMA.
- **Tested.**
  - `make test-rsaz` (`tests/test_rsaz.c`) checks it against libcrypto's `BN_mod_exp`. That's RSA keys with
    e = 65537, 3 and a random 32-bit e, plus moduli at both ends of the 2048-bit range. s covers 0, 1, 2, n−1, n−2
    and random values. Every case must accept the exact result and reject it with any of 10 single bits flipped.
  - `make pk-test-rsaz` adds the full vector set (Wycheproof, CAVP, the generated vectors) through it.
  - Results: 29,744 / 29,744 test_rsaz cases and every PK-suite check (49,356–49,386, depending on the engines
    the CPU has) on real Genoa and Turin. Without IFMA hardware it also
    passes under Intel SDE (`sde64 -icx`).
- **Batches: two tokens per call.** A batch's tokens go through the two-way `ossl_rsaz_amm52x40_x2_ifma256` in
  pairs, the odd one through x1. Full verify at batch 2–16 is 5–10% faster than one at a time:
  - Genoa: 6.26 → 5.67 µs at batch 16;
  - Turin: 5.54 → 5.26 µs;
  - batch 1 unchanged.
  The gain is smaller than the dependency-chain argument suggested, so the per-digit chain is not the whole cost.
- **Next.** RSA-3072 and -4096 have their own kernels (`amm52x30`, `amm52x40` x2) in the same family.

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

- **Without IFMA, no single-token win is possible here.** Verification is 19 Montgomery operations, and the
  libraries' asm already does them. On IFMA CPUs, `-DJWT_RSAZ` does them in 52-bit digits, 1.7–3.5× faster (above). The 1.4× over OpenSSL on the Xeon is s2n-bignum's kernel against `x86_64-mont5`, plus skipping EVP and
  padding parsing.
- **SME2 on the M5.** It has 16×16→64-bit outer products (`FEAT_SME_I16I64`). In principle that's a 2048-bit
  schoolbook product in tiles, but nothing public does it. It's research, not a borrowable implementation.

### EdDSA (Ed25519)

| implementation | technique | M5 µs | Xeon µs | licence |
|---|---|---|---|---|
| OpenSSL 3.x | ref10-style, one at a time | **40.4** meas. | **150.2** meas. | Apache-2.0 |
| libsodium | ref10, strict RFC 8032 checks | ~30 est. | ~60 est. | ISC |
| curve25519-dalek / ed25519-dalek (AVX2 backend; `verify_batch`) | 4-way parallel field ops inside one point op; batch = Straus/Pippenger with random 128-bit coefficients, ~2× at batch 64 | ~20 single, ~10 batch est. | ~45 single, ~22 batch est. | BSD-3-Clause |
| ed25519-donna | 64-bit / SSE2; Bos–Coster batch verify | ~25 / ~12 est. | ~55 / ~28 est. | public domain |
| Firedancer `fd_ed25519` (AVX-512 IFMA) | 8-way IFMA, batch | n/a | n/a (IFMA) | Apache-2.0 |
| **cursed-jwt, portable C** | **fixed-key combs for B and −A (W=7)**, batched Z⁻¹ for the R comparison | **6.5** b1 / **4.6** b32 meas. | **21.5** b1 / **16.3** b32 meas. | MIT (+ fiat-crypto, MIT) |

- **Why it's this cheap.** A mixed addition in extended twisted Edwards coordinates is 7M (P-256 Jacobian: 11),
  and a verify is 2 × 37 of them with no doublings. The estimate before building it was ~4 µs on the M5 and ~15 on
  the Xeon.
- **The semantics.** It is a single-signature verify, not a random-linear-combination batch, so it can't accept
  anything single verification rejects. The equation is the cofactorless one, compared as bytes: accept iff
  S < L, A and R decode, and encode([S]B − [k]A) = R. That matches RFC 8032 §5.1.7 as OpenSSL, libsodium and
  Wycheproof's "valid" set read it. Non-canonical encodings of A (y ≥ p) are rejected at key setup.
- **Not constant-time,** like the ES256 code: every input is public.

## The implementation

```c
jwt_pkey_t *k = jwt_pkey_es256(x, y);        // or jwt_pkey_rs256(n, nlen, e, elen), jwt_pkey_ed25519(pub); NULL if invalid
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
    vendored in `crypto/src/fiat/` (pinned and re-checked by `scripts/fetch-fiat.sh`), plus my `fe_mul`.
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
      branches and stack spills, which ran 6.7× slower than OpenSSL on the Xeon.
    - Fixed-size copies exist for 2048/3072/4096 bits.
  - **`-DJWT_S2N` (2048-bit moduli):** s2n-bignum's Karatsuba `bignum_kmul_32_64` / `bignum_ksqr_32_64` and
    `bignum_emontredc_8n`, which is how AWS-LC uses them. Cross-checked against the C on 20,000 random operands.
  - **`-DJWT_OPENSSL`:** libcrypto's `BN_mod_exp_mont` and `BN_mod_mul_montgomery`, with a `BN_MONT_CTX` cached in
    the key. The exact block compare and the screening algebra stay ours.
- **EdDSA (Ed25519, `alg` "EdDSA", RFC 8037):**
  - Key setup decodes A (rejecting y ≥ p and points off the curve) and builds signed-digit comb tables of
    `k·2^(7j)·P`, k = 1..64, for B and −A, in Niels form (y+x, y−x, 2dxy): 37 rows each, 568 KB per key, 0.77 ms
    on the M5 and 2.9 ms on the Xeon.
  - Verify, in chunks of 32 tokens:
    1. reject unless the signature is exactly 64 bytes and S < L;
    2. k = SHA-512(R ‖ A ‖ M) mod L (a C SHA-512; the reduction goes through fiat's Montgomery scalar code);
    3. S and k recoded to signed base-128 digits; 2 × 37 complete mixed additions (no exceptional cases);
    4. all the Z of the chunk inverted together (Montgomery's trick + the ref10 addition chain);
    5. accept iff the encoding of the result equals R byte for byte.
  - Field arithmetic is fiat-crypto's `curve25519_64.c` and `curve25519_scalar_64.c` (MIT), fetched by
    vendored in `crypto/src/fiat/` like the P-256 files. `JWT_ED_W` sets the window.
- **Screening (`-DJWT_RSA_SCREEN`):**
  - A = ∏ sᵢ and B = ∏ EMᵢ, each by chained Montgomery products of the raw values, so both carry R^−(c−1).
  - Accept the whole batch iff mont(pow(A·R, e), K_c) = B, where K_c = R^((c−1)(e−1)) mod n is precomputed per
    key for c ≤ 16.
  - Otherwise fall back to per-token verification, so honest results are unchanged.
  - Cost: 2c + 17 multiplications for c tokens, against 19c one at a time.

**Tests:** `make pk-test` runs 4 builds (portable C, screening, W=5, W=7); `pk-test-s2n` and `pk-test-fast` run
the asm backends with and without screening. Each build makes about 14,500 checks. All pass on:
- macOS arm64 (Apple clang), every build;
- Linux arm64 in Docker (gcc 13.3, clang 18.1), every build, plus ASan/UBSan on the fast screening build;
- Linux amd64 in Docker, the portable C builds plus ASan/UBSan (Rosetta can't run the ADX asm);
- the Xeon: portable C with gcc, and the s2n, libcrypto and fast builds with clang; EdDSA with clang.

HS256 is unchanged by the shared front end (`claims_one`, `header_ok` taking the alg). On the Xeon, full
verify is 277.9 ns at batch 8 and 1,178.7 at batch 1. The README had 277 and 1,178 at the time; batch 1 has since
moved to the extracted OpenSSL SHA-256 code (938 ns). `make test-vectors` passes on the M5.

The sources, all fetched by `scripts/fetch-vectors.sh` with pinned SHA-256s:

| source | vectors |
|---|---|
| Wycheproof `ecdsa_secp256r1_sha256_p1363_test.json` (JOSE r‖s format) | 262 (173 valid, 89 invalid) |
| Wycheproof `rsa_signature_{2048,3072,4096}_sha256_test.json` | 773 (non-"acceptable"; mostly invalid encodings) |
| Wycheproof `ed25519_test.json` | 181 (117 valid, 64 invalid: S ≥ L, bad encodings, truncation) |
| RFC 8032 §7.1 Ed25519 tests (empty, 1-, 2-, 1023-byte and SHA(abc) messages) | 5 |
| RFC 8037 A.4 (the JWS Ed25519 example) | raw + tampered, and the token |
| NIST CAVP `SigVer.rsp` [P-256,SHA-256] | 15 |
| NIST CAVP `SigVer15_186-3.rsp`, SHA256, mod 2048/3072, assorted e | 36 |
| RFC 7515 A.2 (RS256) and A.3 (ES256) | live → BAD_PAYLOAD (no sub), expired → INVALID, tampered → INVALID |
| pyca/cryptography random: 6 RSA keys (2048/3072/4096, e = 3 and 65537), 8 P-256 keys, messages 0–1100 B, 15% corrupted, 15% high-s | 450 |
| pyca/cryptography random Ed25519: 6 keys, 10% with S + L, 15% bit-flipped | 150 |
| pyca/cryptography tokens: alg mismatch, expired, bad signature, padding, missing username, header variants | 486 (120 EdDSA) |

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
  - Removing EdDSA's S < L check fails 85 checks; ignoring the sign bit of x fails 1,262.
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
  - The multi-buffer template (`crypto/src/cc_mb.inc`) generalises to 64-bit words, with 128-byte blocks and 80 rounds:
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

1. **Ed25519 speed-ups.**
   - s2n-bignum's verified `bignum_mul_p25519` / `bignum_sqr_p25519` asm in place of fiat's C, as for P-256.
   - The SHA-512 of R ‖ A ‖ M through the ARMv8.2 SHA512 instructions and a multi-buffer x86 engine (see HS384 /
     HS512 below); it is ~0.4 µs of the 4.6 on the M5.
2. **JWKS input.** `jwt_pkey_from_jwk()` for `{"kty":"RSA","n","e"}` and `{"kty":"EC","crv":"P-256","x","y"}`,
   plus `kid` selection across keys.
3. **Run the crypto_mb path on an IFMA machine:** `make pk-test-ifma pk-bench-ifma`. Then decide, per algorithm,
   whether it or the existing path is the default on IFMA CPUs.
4. **Make the fast build the the default build default.**
   - It currently needs libcrypto and the s2n-bignum fetch.
   - A build that has neither falls back to the portable C, which is still 2.8–3.6× ahead of OpenSSL on ES256.
