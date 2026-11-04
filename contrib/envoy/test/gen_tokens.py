#!/usr/bin/env python3
"""gen_tokens.py OUTDIR [N] [SEED]: test keys, a JWKS and signed tokens for the benchmarks, signed with pyca/cryptography
(an implementation independent of both libraries under test).

Writes OUTDIR/jwks.json (one oct, one RSA-2048, one P-256 key, each with kid and alg) and, per alg in HS256 / RS256 /
ES256 and per claim set, OUTDIR/<alg>_<set>.txt with N distinct tokens (one per line).  Also OUTDIR/bad_<alg>.txt:
the same tokens with one signature bit flipped (both libraries must reject every one).

Claim sets:
  small      iss, sub, aud, iat, exp                                    (~140 B payload JSON)
  realistic  an Auth0 / Okta style access token: iss, sub, aud list, iat, nbf, exp, jti, azp, scope, permissions,
             namespaced roles and a nested tenant object, email, name     (~800 B payload JSON)
"""

import base64
import hashlib
import hmac
import json
import os
import random
import sys
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

out = sys.argv[1]
N = int(sys.argv[2]) if len(sys.argv) > 2 else 64
rnd = random.Random(int(sys.argv[3]) if len(sys.argv) > 3 else 1)
os.makedirs(out, exist_ok=True)


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def ib(x, n=None):
    n = n or (x.bit_length() + 7) // 8
    return x.to_bytes(n, "big")


secret = bytes(rnd.getrandbits(8) for _ in range(32))
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ec_key = ec.generate_private_key(ec.SECP256R1())
rn = rsa_key.public_key().public_numbers()
en = ec_key.public_key().public_numbers()
jwks = {
    "keys": [
        {"kty": "oct", "kid": "hs-2026-10", "alg": "HS256", "k": b64(secret)},
        {"kty": "RSA", "kid": "rs-2026-10", "alg": "RS256", "use": "sig", "n": b64(ib(rn.n)), "e": b64(ib(rn.e))},
        {
            "kty": "EC",
            "kid": "es-2026-10",
            "alg": "ES256",
            "use": "sig",
            "crv": "P-256",
            "x": b64(ib(en.x, 32)),
            "y": b64(ib(en.y, 32)),
        },
    ]
}
with open(os.path.join(out, "jwks.json"), "w") as f:
    json.dump(jwks, f, separators=(",", ":"))
KID = {"HS256": "hs-2026-10", "RS256": "rs-2026-10", "ES256": "es-2026-10"}

ISS = "https://auth.example.com/"
AUD = "https://api.example.com"
NOW = 1_790_000_000  # 2026-09-21; exp is NOW + 10 years so tokens stay live


def small(i):
    return {"iss": ISS, "sub": f"user-{100000 + i}", "aud": AUD, "iat": NOW + i, "exp": NOW + 315_360_000}


def realistic(i):
    perms = ["read:orders", "write:orders", "read:invoices", "read:customers", "write:customers", "read:reports"]
    return {
        "iss": ISS,
        "sub": "auth0|%024x" % rnd.getrandbits(96),
        "aud": [AUD, ISS + "userinfo"],
        "iat": NOW + i,
        "nbf": NOW + i,
        "exp": NOW + 315_360_000,
        "jti": str(uuid.UUID(int=rnd.getrandbits(128))),
        "azp": "Xk2mQ9vB7rT4pL1sN8dF3hJ6wY0cZ5aE",
        "scope": "openid profile email offline_access " + " ".join(perms[: 3 + i % 4]),
        "gty": "authorization_code",
        "permissions": perms[: 2 + i % 5],
        "https://example.com/roles": ["member", "billing-admin"][: 1 + i % 2],
        "https://example.com/tenant": {
            "id": "t-%04d" % (i % 9000),
            "plan": "enterprise",
            "region": "eu-west-1",
            "features": ["sso", "audit-log", "scim"],
        },
        "email": f"user{i}@example.com",
        "email_verified": True,
        "name": f"Jane Doe {i}",
        "locale": "en-GB",
        "updated_at": "2026-10-01T12:34:56.000Z",
    }


def sign(alg, si):
    if alg == "HS256":
        return hmac.new(secret, si, hashlib.sha256).digest()
    if alg == "RS256":
        return rsa_key.sign(si, padding.PKCS1v15(), hashes.SHA256())
    r, s = decode_dss_signature(ec_key.sign(si, ec.ECDSA(hashes.SHA256())))
    return ib(r, 32) + ib(s, 32)


for alg in ("HS256", "RS256", "ES256"):
    bad = []
    for name, fn in (("small", small), ("realistic", realistic)):
        toks = []
        for i in range(N):
            h = b64(json.dumps({"alg": alg, "typ": "JWT", "kid": KID[alg]}, separators=(",", ":")).encode())
            p = b64(json.dumps(fn(i), separators=(",", ":")).encode())
            si = (h + "." + p).encode()
            sig = sign(alg, si)
            toks.append(h + "." + p + "." + b64(sig))
            if name == "realistic":
                sb = bytearray(sig)
                sb[i % len(sb)] ^= 1 << (i % 8)
                bad.append(h + "." + p + "." + b64(bytes(sb)))
        with open(os.path.join(out, f"{alg}_{name}.txt"), "w") as f:
            f.write("\n".join(toks) + "\n")
    with open(os.path.join(out, f"bad_{alg}.txt"), "w") as f:
        f.write("\n".join(bad) + "\n")
lens = {n: len(open(os.path.join(out, f"RS256_{n}.txt")).readline()) - 1 for n in ("small", "realistic")}
print(f"wrote {out}: {N} tokens per set; RS256 token length small {lens['small']}, realistic {lens['realistic']}")
