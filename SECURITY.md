# Security

cursed-jwt verifies authentication tokens, so a bug that makes it accept a token it should reject is a security bug.
Please report those privately.

- **How to report:** use GitHub's private vulnerability reporting (the "Report a vulnerability" button under this
  repository's Security tab). Please don't open a public issue for a suspected vulnerability.
- **What helps:** the token or inputs, the engine in use (`jwt_engine()` names it), the CPU, the compiler and the build
  flags.
- **Supported versions:** there are no releases yet; fixes go to `main`.

In scope: anything that accepts a token it shouldn't (signature, `alg`, `exp`/`nbf`, the claim rules in the README),
memory-safety bugs on any input, and differences between engines. The RS256/ES256/EdDSA prototype (`-DJWT_PK`) is in
scope too, but it isn't constant-time by design, since it only handles public data; timing differences there are
not vulnerabilities.

The library has not had an external security review.
