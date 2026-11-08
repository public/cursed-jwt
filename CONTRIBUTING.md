# Contributing

Bug reports, test cases and pull requests are welcome.

- **Tests first.** `make test` must pass, and `make test-vectors` if you touch hashing, base64url or the claim rules.
  Run `make asan` and `make fuzz-smoke` for anything that parses input.
- **Test against something independent.** A new engine or code path is checked against OpenSSL, published vectors or
  the Python model in `tests/test_hypothesis.py`, never only against itself.
- **Speed claims need their context:** the CPU, compiler, flags and batch size, from `make bench` or `make compare`.
- **Dependencies stay fetched, not vendored.** Test vectors and optional backends are downloaded by the pinned,
  checksummed scripts in `scripts/`; don't commit them or any build output.
- **One vendored file** (`src/sha256_x86_64_ossl.S`) comes from OpenSSL; regenerate it with
  `scripts/extract-openssl-sha256.sh` rather than editing it by hand. `src/sha256_shani_mb.S` is generated too: edit
  `scripts/gen-shani-mb.py` and rerun it (`python3 scripts/gen-shani-mb.py > src/sha256_shani_mb.S`).

Contributions are accepted under the MIT licence in [LICENSE](LICENSE).
