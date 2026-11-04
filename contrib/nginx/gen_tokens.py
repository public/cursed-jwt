#!/usr/bin/env python3
"""gen_tokens.py OUTDIR [N]: keys (JWKS) and signed tokens for test.sh, signed with Python's `cryptography`
(OpenSSL underneath) and hmac -- independent of cursed-jwt.

Writes, per alg in hs256 rs256 es256:
  OUTDIR/<alg>.jwks                       the verification key (oct / RSA-2048 / EC P-256), kid "k1"
  OUTDIR/<alg>-<claims>.tok               N valid tokens, one per line (claims = small | real)
  OUTDIR/<alg>-<claims>.bad               N tokens with one flipped signature bit (must be rejected)
  OUTDIR/<alg>-expired.tok                tokens whose exp has passed (must be rejected)
small: {"sub", "exp", "iat"} (~100 B payload).  real: an OIDC-style access token (~700 B payload): iss, sub, aud
(array), exp, nbf, iat, jti, azp, scope, email, name, preferred_username, realm_access.roles, a nested object.
"""

import base64
import hashlib
import hmac
import json
import os
import sys
import time
import uuid
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64int(i, n):
    return b64(i.to_bytes(n, "big"))


def claims(kind, i, now):
    if kind == "small":
        return {"sub": str(1000 + i), "iat": now, "exp": now + 86400 * 365}
    return {
        "iss": "https://id.example.com/realms/prod",
        "sub": str(1000 + i),
        "aud": ["api.example.com", "account"],
        "exp": now + 86400 * 365,
        "nbf": now - 60,
        "iat": now - 60,
        "jti": str(uuid.UUID(int=i + 1)),
        "azp": "web-frontend",
        "typ": "Bearer",
        "session_state": str(uuid.UUID(int=i + 7)),
        "scope": "openid profile email offline_access orders:read orders:write",
        "email": f"user{i}@example.com",
        "email_verified": True,
        "name": f"Test User {i}",
        "preferred_username": f"user{i}",
        "given_name": "Test",
        "family_name": f"User {i}",
        "locale": "en-GB",
        "realm_access": {"roles": ["default-roles-prod", "offline_access", "uma_authorization", "customer"]},
        "resource_access": {"account": {"roles": ["manage-account", "view-profile"]}},
        "tenant": {"id": 42, "plan": "pro", "region": "eu-west-1"},
    }


def main():
    out = sys.argv[1]
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 1000
    os.makedirs(out, exist_ok=True)
    now = int(time.time())
    secret = hashlib.sha256(b"cursed-jwt-nginx-test").digest()
    rk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ek = ec.generate_private_key(ec.SECP256R1())
    rpub, epub = rk.public_key().public_numbers(), ek.public_key().public_numbers()
    keys = {
        "hs256": {"kty": "oct", "kid": "k1", "alg": "HS256", "k": b64(secret)},
        "rs256": {
            "kty": "RSA",
            "kid": "k1",
            "alg": "RS256",
            "use": "sig",
            "n": b64int(rpub.n, 256),
            "e": b64int(rpub.e, 3),
        },
        "es256": {
            "kty": "EC",
            "kid": "k1",
            "alg": "ES256",
            "use": "sig",
            "crv": "P-256",
            "x": b64int(epub.x, 32),
            "y": b64int(epub.y, 32),
        },
    }

    def sign(alg, msg):
        if alg == "hs256":
            return hmac.new(secret, msg, hashlib.sha256).digest()
        if alg == "rs256":
            return rk.sign(msg, padding.PKCS1v15(), hashes.SHA256())
        r, s = decode_dss_signature(ek.sign(msg, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def token(alg, c):
        h = b64(json.dumps({"alg": alg.upper(), "typ": "JWT", "kid": "k1"}, separators=(",", ":")).encode())
        p = b64(json.dumps(c, separators=(",", ":")).encode())
        msg = f"{h}.{p}".encode()
        return f"{h}.{p}.{b64(sign(alg, msg))}"

    for alg, key in keys.items():
        with open(f"{out}/{alg}.jwks", "w") as f:
            json.dump({"keys": [key]}, f)
        for kind in ("small", "real"):
            toks = [token(alg, claims(kind, i, now)) for i in range(n)]
            with open(f"{out}/{alg}-{kind}.tok", "w") as f:
                f.write("\n".join(toks) + "\n")
            bad = []
            for t in toks:
                h, p, s = t.split(".")
                sig = bytearray(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
                sig[len(sig) // 2] ^= 1
                bad.append(f"{h}.{p}.{b64(bytes(sig))}")
            with open(f"{out}/{alg}-{kind}.bad", "w") as f:
                f.write("\n".join(bad) + "\n")
        exp = [token(alg, {"sub": str(i + 1), "iat": now - 7200, "exp": now - 3600}) for i in range(min(n, 50))]
        with open(f"{out}/{alg}-expired.tok", "w") as f:
            f.write("\n".join(exp) + "\n")
    print(
        f"{out}: keys and {n} tokens per alg/claim set; real payload "
        f"{len(json.dumps(claims('real', 0, now), separators=(',', ':')))} B"
    )


if __name__ == "__main__":
    main()
