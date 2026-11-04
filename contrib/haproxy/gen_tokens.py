#!/usr/bin/env python3
"""gen_tokens.py OUTDIR: keys and tokens for `haproxy -U jwt-bench` / `-U jwt-diff`, and for load tests.

Writes into OUTDIR (keep it out of git; the repo ignores *.pem):
  rsa2048.pub.pem rsa4096.pub.pem rsa1024.pub.pem rsa2048e3.pub.pem ec256.pub.pem ec384.pub.pem
  bench.txt   "<label> <alg> <key> <token>": HS256 / RS256 / ES256 with small and realistic (OIDC-like) claims
  diff.txt    bench.txt plus adversarial tokens: forged and malleated signatures, wrong lengths, alg/key mismatches
  load-<alg>-<size>.txt   one token per line, for the load generator
Signatures are made with pyca/cryptography (OpenSSL), independently of both verifiers under test.
"""

import base64
import json
import os
import sys

from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

SECRET = "cursed-jwt-haproxy-secret"
LONG_SECRET = "k" * 100  # > 64 bytes: HMAC hashes it first
N256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jose(alg):
    return b64(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())


def claims(size, i=0):
    if size == "small":
        c = {"sub": str(10000 + i), "exp": 4102444800}
    else:  # an OIDC access token, ~0.9 KB encoded
        c = {
            "iss": "https://login.example.test/realms/prod",
            "sub": "f81d4fae-7dec-11d0-a765-%012d" % i,
            "aud": ["api.example.test", "account"],
            "exp": 4102444800,
            "iat": 1761900000,
            "nbf": 1761900000,
            "jti": "4a3c%028x" % (i * 7919),
            "azp": "web-frontend",
            "scope": "openid profile email feed:read feed:write",
            "email": "user%d@example.test" % i,
            "email_verified": True,
            "name": "Example User %d" % i,
            "preferred_username": "user%d" % i,
            "realm_access": {"roles": ["user", "offline_access", "uma_authorization"]},
            "resource_access": {"api": {"roles": ["read", "write"]}},
            "sid": "%032x" % (i * 104729),
        }
    return b64(json.dumps(c, separators=(",", ":")).encode())


def signing_input(alg, size, i=0):
    return ("%s.%s" % (jose(alg), claims(size, i))).encode()


def hs(key, msg):
    h = hmac.HMAC(key.encode(), hashes.SHA256())
    h.update(msg)
    return h.finalize()


def es_raw(priv, msg):
    r, s = utils.decode_dss_signature(priv.sign(msg, ec.ECDSA(hashes.SHA256())))
    return r, s


def pem_pub(k, path):
    with open(path, "wb") as f:
        f.write(
            k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        )


def rsa_raw_sign(priv, em_int):
    """s = EM^d mod n, for hand-built encodings"""
    pn = priv.private_numbers()
    return pow(em_int, pn.d, pn.public_numbers.n)


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    rsa2048 = rsa.generate_private_key(65537, 2048)
    rsa4096 = rsa.generate_private_key(65537, 4096)
    rsa1024 = rsa.generate_private_key(65537, 1024)
    rsa2048e3 = rsa.generate_private_key(3, 2048)
    ec256 = ec.generate_private_key(ec.SECP256R1())
    ec384 = ec.generate_private_key(ec.SECP384R1())
    keys = {
        "rsa2048": rsa2048,
        "rsa4096": rsa4096,
        "rsa1024": rsa1024,
        "rsa2048e3": rsa2048e3,
        "ec256": ec256,
        "ec384": ec384,
    }
    path = {}
    for name, k in keys.items():
        path[name] = os.path.join(out, name + ".pub.pem")
        pem_pub(k, path[name])

    def tok_hs(size, key=SECRET, i=0):
        m = signing_input("HS256", size, i)
        return m.decode() + "." + b64(hs(key, m))

    def tok_rs(size, k=rsa2048, i=0):
        m = signing_input("RS256", size, i)
        return m.decode() + "." + b64(k.sign(m, padding.PKCS1v15(), hashes.SHA256()))

    def tok_es(size, k=ec256, i=0):
        m = signing_input("ES256", size, i)
        r, s = es_raw(k, m)
        return m.decode() + "." + b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    bench = []
    for size in ("small", "realistic"):
        bench.append(("HS256-%s" % size, "HS256", SECRET, tok_hs(size)))
        bench.append(("RS256-%s" % size, "RS256", path["rsa2048"], tok_rs(size)))
        bench.append(("ES256-%s" % size, "ES256", path["ec256"], tok_es(size)))
    bench.append(("RS256-4096-small", "RS256", path["rsa4096"], tok_rs("small", rsa4096)))
    with open(os.path.join(out, "bench.txt"), "w") as f:
        for b in bench:
            f.write(" ".join(b) + "\n")

    diff = list(bench)
    # HS256: secret lengths around the block size, a > 64-byte secret, wrong secret
    for kl in (1, 31, 32, 63, 64, 65, 100, 300):
        k = ("s%d" % kl) * 200
        k = k[:kl]
        diff.append(("HS256-key%d" % kl, "HS256", k, tok_hs("small", k)))
    diff.append(("HS256-wrongkey", "HS256", SECRET + "x", tok_hs("small")))
    # HS256 with the PEM path as secret (alg confusion): both must agree (KO unless signed with that string)
    diff.append(("HS256-pem-as-secret", "HS256", path["rsa2048"], tok_hs("small", path["rsa2048"])))
    m = signing_input("HS256", "small")
    mac = hs(SECRET, m)
    diff.append(("HS256-short-sig", "HS256", SECRET, m.decode() + "." + b64(mac[:31])))
    diff.append(("HS256-long-sig", "HS256", SECRET, m.decode() + "." + b64(mac + b"\0")))
    # RS256: other key sizes, e = 3, and hand-built signatures
    diff.append(("RS256-1024", "RS256", path["rsa1024"], tok_rs("small", rsa1024)))
    diff.append(("RS256-4096-realistic", "RS256", path["rsa4096"], tok_rs("realistic", rsa4096)))
    diff.append(("RS256-e3", "RS256", path["rsa2048e3"], tok_rs("small", rsa2048e3)))
    n = rsa2048.public_key().public_numbers().n
    m = signing_input("RS256", "small")
    good = rsa2048.sign(m, padding.PKCS1v15(), hashes.SHA256())
    s = int.from_bytes(good, "big")
    dg = hashes.Hash(hashes.SHA256())
    dg.update(m)
    h = dg.finalize()
    di_null = bytes.fromhex("3031300d060960864801650304020105000420") + h
    di_nonull = bytes.fromhex("302f300b0609608648016503040201" "0420") + h

    def em(di):
        return int.from_bytes(b"\x00\x01" + b"\xff" * (256 - 3 - len(di)) + b"\x00" + di, "big")

    variants = {
        "RS256-good": good,
        "RS256-nonull-digestinfo": rsa_raw_sign(rsa2048, em(di_nonull)).to_bytes(256, "big"),
        "RS256-null-rebuilt": rsa_raw_sign(rsa2048, em(di_null)).to_bytes(256, "big"),
        "RS256-short-padding": rsa_raw_sign(
            rsa2048,
            int.from_bytes(b"\x00\x01" + b"\xff" * 7 + b"\x00" + di_null + b"\x00" * (256 - 10 - len(di_null)), "big"),
        ).to_bytes(256, "big"),
        "RS256-s-plus-n": (s + n).to_bytes(257, "big"),
        "RS256-s-zero-prefixed": b"\0" + good,
        "RS256-s-zero": b"\0" * 256,
        "RS256-s-one": (1).to_bytes(256, "big"),
        "RS256-s-n-minus-1": (n - 1).to_bytes(256, "big"),
        "RS256-s-n": n.to_bytes(256, "big"),
        "RS256-truncated": good[:255],
        "RS256-bitflip": bytes([good[0] ^ 1]) + good[1:],
    }
    for lab, sig in variants.items():
        diff.append((lab, "RS256", path["rsa2048"], m.decode() + "." + b64(sig)))
    # ES256: malleated and out-of-range signatures, padded and short encodings, wrong curve
    m = signing_input("ES256", "small")
    r, s = es_raw(ec256, m)
    E = {
        "ES256-good": (r.to_bytes(32, "big") + s.to_bytes(32, "big")),
        "ES256-high-s": (r.to_bytes(32, "big") + (N256 - s).to_bytes(32, "big")),
        "ES256-r-zero": (b"\0" * 32 + s.to_bytes(32, "big")),
        "ES256-s-zero": (r.to_bytes(32, "big") + b"\0" * 32),
        "ES256-r-n": (N256.to_bytes(32, "big") + s.to_bytes(32, "big")),
        "ES256-s-n": (r.to_bytes(32, "big") + N256.to_bytes(32, "big")),
        "ES256-r-plus-n": ((r + N256) % 2**256).to_bytes(32, "big") + s.to_bytes(32, "big"),
        "ES256-padded-66": (b"\0" + r.to_bytes(32, "big") + b"\0" + s.to_bytes(32, "big")),
        "ES256-short-62": (r.to_bytes(32, "big")[1:] + s.to_bytes(32, "big")[1:]),
        "ES256-odd-63": (r.to_bytes(32, "big") + s.to_bytes(32, "big"))[:63],
        "ES256-der": utils.encode_dss_signature(r, s),
        "ES256-swapped": (s.to_bytes(32, "big") + r.to_bytes(32, "big")),
    }
    for lab, sig in E.items():
        diff.append((lab, "ES256", path["ec256"], m.decode() + "." + b64(sig)))
    diff.append(("ES256-p384-key", "ES256", path["ec384"], tok_es("small")))
    # algorithm / key mismatches: OpenSSL decides them in both builds
    diff.append(("RS256-token-ec-key", "RS256", path["ec256"], tok_rs("small")))
    diff.append(("ES256-token-rsa-key", "ES256", path["rsa2048"], tok_es("small")))
    diff.append(("ES256-alg-on-rs-token", "ES256", path["ec256"], tok_rs("small")))
    diff.append(("RS256-alg-on-es-token", "RS256", path["rsa2048"], tok_es("small")))
    # many distinct tokens per algorithm (claims differ, so do signatures)
    for i in range(20):
        diff.append(("HS256-r%d" % i, "HS256", SECRET, tok_hs("realistic", SECRET, i)))
        diff.append(("RS256-r%d" % i, "RS256", path["rsa2048"], tok_rs("realistic", rsa2048, i)))
        diff.append(("ES256-r%d" % i, "ES256", path["ec256"], tok_es("realistic", ec256, i)))
    with open(os.path.join(out, "diff.txt"), "w") as f:
        for d in diff:
            f.write(" ".join(d) + "\n")

    # load-test token files (distinct tokens, as many clients would send)
    for alg, fn in (("HS256", tok_hs), ("RS256", tok_rs), ("ES256", tok_es)):
        for size in ("small", "realistic"):
            with open(os.path.join(out, "load-%s-%s.txt" % (alg, size)), "w") as f:
                for i in range(256):
                    f.write(fn(size, i=i) + "\n")


if __name__ == "__main__":
    main()
