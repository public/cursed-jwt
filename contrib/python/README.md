# cursed-crypto for Python

Batch (multi-buffer) verification for [pyca/cryptography](https://cryptography.io)'s key objects, backed by
cursed-crypto (this repository's `crypto/`). Import name `cursed_crypto`.

It is a companion to pyca/cryptography, not a replacement. pyca/cryptography has no backend plug-in point: every
`backend=` argument is ignored and `default_backend()` always returns the built-in OpenSSL backend (checked in
41.0.7 and 50.0.2). So this package doesn't shadow or patch `cryptography`. It works next to it:

- it takes pyca's public key objects and the same bytes-like inputs (`bytes`, `bytearray`, `memoryview`);
- it raises pyca's own `cryptography.exceptions.InvalidSignature`, so existing `except` clauses keep working;
- every verdict, single or batched, is the one pyca's `verify` would give for that item;
- anything it doesn't implement goes to pyca, inside a batch too.

```python
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
import cursed_crypto

es = cursed_crypto.ECDSAVerifier(ec_public_key, ec.ECDSA(hashes.SHA256()))  # build once per key, keep it
es.verify(der_signature, data)                   # returns None or raises InvalidSignature, as ec_public_key.verify
oks = es.verify_batch(signatures, datas)         # [True, False, ...]: one verdict per item

rs = cursed_crypto.RSAVerifier(rsa_public_key, padding.PKCS1v15(), hashes.SHA256())
ed = cursed_crypto.Ed25519Verifier(ed25519_public_key)
jws = cursed_crypto.ECDSAVerifier(ec_public_key, ec.ECDSA(hashes.SHA256()), signature_format="raw")  # r || s

mac = cursed_crypto.HMACSHA256(key)              # hmac.HMAC(key, hashes.SHA256()), used one-shot
mac.verify(data, tag)                            # None, or InvalidSignature
mac.verify_batch(datas, tags)                    # [True, False, ...]
mac.digest_batch(datas)                          # [32-byte MAC, ...]
cursed_crypto.sha256_batch(datas)                # [32-byte digest, ...]
```

## Batches are per item

`verify_batch(signatures, datas)` returns a list of booleans: `True` where `verify(signatures[i], datas[i])` would
return, `False` where it would raise `InvalidSignature`. One bad item never changes another item's result. This is
**not** "all valid or not" batch verification in the sense of ed25519-dalek's `verify_batch` (one combined check
that says only whether every signature is valid). The speed comes from running several verifies' arithmetic and
hashing together and from per-key tables, not from merging the checks.

## What runs natively

| class | natively | passed to pyca |
|---|---|---|
| `Ed25519Verifier(public_key)` | Ed25519 (RFC 8032, as OpenSSL decides it: S < L, cofactorless) | keys that don't decode to a point, non-canonical key encodings |
| `ECDSAVerifier(public_key, ec.ECDSA(hashes.SHA256()))` | SECP256R1 with SHA-256, DER (default) or raw r ‖ s signatures | other curves and hashes, `Prehashed` |
| `RSAVerifier(public_key, padding.PKCS1v15(), hashes.SHA256())` | PKCS #1 v1.5 with SHA-256, 2048 to 4096-bit moduli, odd 3 ≤ e < 2⁶⁴ | PSS, other hashes, `Prehashed`, other key sizes and exponents |
| `HMACSHA256(key)` | 32-byte tags, any key length | tags of any other length (pyca rejects every truncated tag) |

Key objects of the application's own subclasses of pyca's abstract key types are always passed to pyca (their
`verify` is what counts).

- **DER.** cursed-crypto verifies raw r ‖ s. DER signatures are converted in C by a strict parser that accepts
  exactly what OpenSSL's `ECDSA_verify` accepts: DER only (minimal lengths and integers, no trailing bytes), positive
  integers, and then 1 ≤ r, s < n. High-s signatures are valid, as in OpenSSL.
- **Raw r ‖ s** (`signature_format="raw"`, as in JWS ES256 / IEEE P1363): valid exactly when pyca accepts
  `encode_dss_signature(r, s)`. Any length other than twice the curve's byte length is invalid.

## Cost model

A verifier owns cursed-crypto's per-key state: comb tables of 528 KB (ECDSA P-256) or 568 KB (Ed25519), built in
about a millisecond, or RSA's Montgomery constants. Build one verifier per key and keep it; building one per call
would cost more than the verifies. There are no module-level `verify(public_key, ...)` helpers: pyca's key objects
can't be weakly referenced or hashed, so a cache keyed by them could only keep keys alive forever or re-derive their
identity on every call.

The GIL is released for every signature verify, every batch, key setup and single HMACs of 2 KB or more, so
threads verify in parallel as they do with pyca. Lists are turned into C arrays in C, with no per-item Python work.

## Errors

- An item that isn't bytes-like raises `TypeError` for the whole call, before anything is verified.
- `signatures` and `datas` of different lengths raise `ValueError`.
- `InvalidSignature` is pyca's class itself (`cursed_crypto.InvalidSignature is cryptography.exceptions.InvalidSignature`).

## HMAC

Tags are compared in constant time inside cursed-crypto (`cc_hmac_sha256_verify`), never in Python. The key's two
SHA-256 midstates live in the C object (cleared when it is freed); the key bytes are kept only for the items passed
to pyca. There is no streaming `update()`: pyca's `update()` / `finalize()` objects can't be batched, so the batch
calls are one-shot.

## Building

```sh
pip install contrib/python          # from the cursed-jwt tree, or from an sdist
make -C contrib/python venv         # or a venv for development: build/venv with cryptography, pytest, hypothesis
make -C contrib/python PYTHON=build/venv/bin/python test
```

`crypto/src/cursed_crypto.c` is compiled into the extension as one unit, as the library's Makefile builds it. On
x86-64 Linux the committed assembly kernels are assembled with `-DJWT_OSSL_SHA256 -DJWT_SHANI_MB -DJWT_OSSL_MONT`;
elsewhere the build is portable C. Engines (AVX2, AVX-512, SHA-NI, NEON, ...) are picked at run time from the CPU.
Nothing is downloaded at build time; the IFMA and s2n-bignum builds stay out. `CURSED_CRYPTO_PORTABLE=1` builds
without the assembly, `CURSED_CRYPTO_CFLAGS` adds compiler flags. Requires cryptography ≥ 42 (41 accepted other
input types). Tested on CPython 3.12.

Sdists and wheels carry `LICENSE` (MIT) and the vendored code's licences (OpenSSL, Firedancer, Intel ipsec-mb,
fiat-crypto).

## Tests

`make test` runs the differential suite against pyca/cryptography on the same inputs: Wycheproof (ECDSA P-256 /
SHA-256 in DER and P1363, RSA PKCS #1 v1.5 2048 to 4096, Ed25519, HMAC-SHA256), RFC 4231 and RFC 8032, malformed DER
(every mutation class plus random corruption, and the parser against a strict DER reader), high-s ECDSA, Ed25519 small-
order, mixed-order and non-canonical points and S + L, random keys at batch sizes 1 to 33 with invalid items in random
lanes, RSA key shapes, every delegated parameter, input types and errors, threads, and Hypothesis properties. It then
reruns the batch tests under `CC_CPU_MASK` once per engine the CPU has. `make asan` runs the suite against an ASan +
UBSan build of the extension.
