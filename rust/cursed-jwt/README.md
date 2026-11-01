# cursed-jwt (Rust)

The Rust port of [cursed-jwt](../../README.md): batch JWT verification with one multi-buffer SIMD
HMAC-SHA256 pass for many HS256 tokens, one token per vector lane, and RS256 / ES256 / EdDSA on the same front end.
It accepts and rejects exactly the tokens the C library does; the tests check that differentially against the C
code.

```rust
use cursed_jwt::{Error, Hs256Key, Verdict};

let key = Hs256Key::new(b"secret");                       // once: HMAC ipad/opad midstates
let tokens: Vec<&[u8]> = vec![];                          // the bytes after "Bearer "
let mut out: Vec<Verdict> = vec![Err(Error::Invalid); tokens.len()];
key.verify_batch(&tokens, 1_700_000_000, &mut out);       // live iff nbf <= now < exp
for r in &out {
    if let Ok(c) = r {
        let (_uid, _name) = (c.uid(), c.username());
    }
}
```

## Design

- **Safe API.** Bytes in, `Result` out, no panics on untrusted input.  `#![no_std]`; the `std` feature (default)
  adds run-time CPU detection, `alloc` is needed only for the public-key algorithms.
- **One unsafe module.** Every module is `#![forbid(unsafe_code)]` except `arch`, which holds the `core::arch`
  intrinsics.  Each `#[target_feature]` function is called only after the run-time check for its features, made
  next to the call; every `unsafe` block has a `SAFETY` comment (clippy's `undocumented_unsafe_blocks` is denied).
- **One template, many engines.** The multi-buffer SHA-256 (`sha256::kernel`) is safe generic code over a
  `Simd` lane trait; `u32` is the scalar instantiation, and `arch` instantiates it for NEON, AVX2, AVX-512VL on
  ymm, two interleaved ymm groups and zmm, each inside its own target-feature region.  The ARMv8 SHA2 engine
  interleaves 1, 2 or 4 streams of `sha256h`.
- **No zmm in the ymm engines.** C keeps the AVX-512 region on 256-bit vectors with `prefer-vector-width=256`;
  Rust cannot set that per function, so the kernels initialise and copy no arrays (the compiler would lower those
  with zmm stores, and one zmm instruction drops a Cascade Lake core's frequency licence).  `scripts/zmmcheck.py`
  checks the generated assembly in CI.

## Layout

A Cargo workspace in `rust/`, next to the C code rather than at the repository root, so the C build, its
Makefile, CI and API are untouched and the Rust tooling (target/, Cargo.lock, fuzz/) stays in one directory:

| crate | what |
|---|---|
| `cursed-jwt` | the library |
| `cjwt-sys` | test-only bindings to the C library in `../src` (differential tests, same-run benchmarks); not published |
| `fuzz` | cargo-fuzz targets (nightly) |

## Testing

```bash
cd rust
cargo test --release                      # unit, crafted cases, random HMACs vs the hmac crate, differential vs C
make -C .. build/tokens.json build/hmac_vectors.txt build/pk_vectors.txt   # the C suite's vector files (network)
CURSED_JWT_REQUIRE_VECTORS=1 cargo test --release   # + RFC 4231, NIST CAVP, Wycheproof, RFC 7515, pyca vectors
CURSED_JWT_TEST_N=20000 cargo test --release        # longer random runs
cargo bench --bench hs256                 # Rust and C in the same process
```
