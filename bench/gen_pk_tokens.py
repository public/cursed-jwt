#!/usr/bin/env python3
"""gen_pk_tokens.py N SEED > pk_tokens.txt — keys and live tokens for bench/bench_pk.c (pyca/cryptography).

Per algorithm (ES256, RS256 with a 2048- and a 3072-bit key), one line
    key ALG K1 K2 SPKI_DER          (hex; ES256 K1, K2 = x, y; RS256 = n, e)
followed by N lines `tok TOKEN`, payloads shaped like the HS256 benchmark's: {"sub","username","iat","exp"}."""
import base64, json, random, sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

n, rnd = int(sys.argv[1]), random.Random(int(sys.argv[2]))
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
i2b = lambda i, k=None: i.to_bytes(k or (i.bit_length() + 7) // 8, "big")
for alg, kp in (("ES256", ec.generate_private_key(ec.SECP256R1())), ("RS256", rsa.generate_private_key(65537, 2048)),
                ("RS256", rsa.generate_private_key(65537, 3072))):
    pub = kp.public_key(); pn = pub.public_numbers()
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    k1, k2 = (i2b(pn.x, 32), i2b(pn.y, 32)) if alg == "ES256" else (i2b(pn.n), i2b(pn.e))
    print(f"key {alg} {k1.hex()} {k2.hex()} {der.hex()}")
    h = b64u(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())
    for i in range(n):
        p = b64u(json.dumps({"sub": str(rnd.randrange(1, 10**6)), "username": "user%d" % rnd.randrange(10**6),
                             "iat": 1_800_000_000, "exp": 1_900_000_000}, separators=(",", ":")).encode())
        m = (h + "." + p).encode()
        if alg == "ES256":
            r, s = decode_dss_signature(kp.sign(m, ec.ECDSA(hashes.SHA256()))); sig = i2b(r, 32) + i2b(s, 32)
        else:
            sig = kp.sign(m, padding.PKCS1v15(), hashes.SHA256())
        print(f"tok {h}.{p}.{b64u(sig)}")
