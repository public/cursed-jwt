#!/usr/bin/env python3
"""check_sign_pyca.py < emitted.txt

Checks what `test_sign emit N` printed against independent implementations: every HS256 token's MAC with Python's
hmac, every EdDSA token and raw Ed25519 signature with pyca/cryptography's verify, and every Ed25519 signature for
equality with pyca's own (Ed25519 is deterministic).  The header must be the canonical one and the claims must parse
back to the sub / username the test put in.
"""

import base64
import hashlib
import hmac
import json
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def unb64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def hx(s):
    return b"" if s == "-" else bytes.fromhex(s)


def claims(tok, alg, uid, user):
    h, p, s = tok.split(".")
    assert unb64u(h) == ('{"alg":"%s","typ":"JWT"}' % alg).encode(), tok
    assert b64u(unb64u(p)) == p and b64u(unb64u(s)) == s, "not canonical base64url: " + tok
    c = json.loads(unb64u(p))
    assert c["sub"] == uid and c["username"] == ("" if user == "-" else user), (c, uid, user)
    return (h + "." + p).encode(), unb64u(s)


def main():
    n = {"hs": 0, "ed": 0, "edraw": 0}
    for line in sys.stdin:
        f = line.split()
        if f[0] == "hs":
            si, mac = claims(f[2], "HS256", f[3], f[4])
            assert hmac.compare_digest(hmac.new(hx(f[1]), si, hashlib.sha256).digest(), mac), line
        elif f[0] == "ed":
            sk = ed25519.Ed25519PrivateKey.from_private_bytes(hx(f[1]))
            pub = sk.public_key()
            assert pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) == hx(f[2]), line
            si, sig = claims(f[3], "EdDSA", f[4], f[5])
            pub.verify(sig, si)
            assert sk.sign(si) == sig, "differs from pyca's signature: " + line
        elif f[0] == "edraw":
            sk = ed25519.Ed25519PrivateKey.from_private_bytes(hx(f[1]))
            msg, sig = hx(f[2]), hx(f[3])
            sk.public_key().verify(sig, msg)
            assert sk.sign(msg) == sig, "differs from pyca's signature: " + line
        else:
            raise SystemExit("unknown line: " + line)
        n[f[0]] += 1
    assert all(n.values()), n
    print(f"pyca/cryptography + hmac: {n['hs']} HS256 tokens, {n['ed']} EdDSA tokens and {n['edraw']} raw Ed25519 "
          "signatures verified; every Ed25519 signature equals pyca's")


if __name__ == "__main__":
    main()
