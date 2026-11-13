#!/usr/bin/env python3
"""sign_py.py — Python signing for comparison: PyJWT's jwt.encode (HS256, EdDSA) and pyca/cryptography's raw
Ed25519 sign and Python's hmac, on the claims set of bench/bench_sign.c.  ns/token, best of 5 passes."""

import hashlib
import hmac
import time

import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

CLAIMS = {"sub": "123456", "username": "alice", "iat": 1700000000, "exp": 4102444800}
KEY = b"bench-secret-0123456789abcdef0123"
SEED = bytes((i * 7 + 1) & 0xFF for i in range(32))
SI = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYiLCJ1c2VybmFtZSI6ImFsaWNlIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjQxMDI0NDQ4MDB9"


def best(name, f):
    b = 1e18
    for _ in range(5):
        n, t0 = 0, time.perf_counter()
        while time.perf_counter() - t0 < 0.2:
            for _ in range(64):
                f()
            n += 64
        b = min(b, (time.perf_counter() - t0) * 1e9 / n)
    print(f"  {name:<34} b1   {b:9.1f} ns/token")


sk = ed25519.Ed25519PrivateKey.from_private_bytes(SEED)
best("PyJWT jwt.encode HS256", lambda: jwt.encode(CLAIMS, KEY, algorithm="HS256"))
best("PyJWT jwt.encode EdDSA", lambda: jwt.encode(CLAIMS, sk, algorithm="EdDSA"))
best("Python hmac (raw, signing input)", lambda: hmac.new(KEY, SI, hashlib.sha256).digest())
best("pyca Ed25519 sign (raw)", lambda: sk.sign(SI))
ek = ec.derive_private_key(int.from_bytes(SEED, "big") >> 1, ec.SECP256R1())
best("pyca ECDSA P-256 sign (random k)", lambda: ek.sign(SI, ec.ECDSA(hashes.SHA256())))
try:
    det = ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
    best("pyca ECDSA P-256 sign (RFC 6979)", lambda: ek.sign(SI, det))
except TypeError:
    print("  pyca deterministic ECDSA: needs cryptography >= 43")
