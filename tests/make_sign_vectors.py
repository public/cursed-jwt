#!/usr/bin/env python3
"""make_sign_vectors.py VECTOR_DIR N_RANDOM SEED > sign_vectors.txt

Exact-output vectors for tests/test_sign.c (signing).  Sources (scripts/fetch-vectors.sh fetches the RFCs):
  RFC 8032 7.1    Ed25519 TEST 1, 2, 3, 1024 and SHA(abc): secret key, public key, message, signature
  RFC 8037 A.4    the EdDSA JWS ({"alg":"EdDSA"}, payload "Example of Ed25519 signing", not a claims set)
  RFC 7515 A.1    the HS256 JWS ({"typ":"JWT",\\r\\n "alg":"HS256"}, its CRLF-formatted claims)
  RFC 6979 A.2.5  ECDSA P-256 with SHA-256, "sample" and "test": private key, public key, nonce k, r and s
  RFC 7515 A.2    the RS256 JWS (its RSA private key as a JWK; {"alg":"RS256"}: checked at the signing input)
  pyca/cryptography and Python's hmac / hashlib: random Ed25519 keys and messages, whole HS256 and EdDSA tokens with
  the canonical headers, SHA-512 at every length around the block and padding boundaries, base64url, and reductions
  mod L of 512-bit values at the edges (0, L - 1, L, L + 1, 2^252, 2^256 - 1, 2^512 - 1, multiples of L, ...).
Every Ed25519 signature is pyca's (Ed25519 is deterministic, so ours must be byte-identical), and is checked to
verify before it is written.

Output, one per line (hex, "-" = empty):
  ed SRC SEED PUB MSG SIG              raw Ed25519
  edjws SRC SEED SIGNING_INPUT TOKEN   a JWS whose header is not the canonical one: checked at the signing input
  hsjws SRC KEY SIGNING_INPUT TOKEN
  es SRC D X Y MSG K SIG               raw ES256 (D big-endian; K the RFC 6979 nonce, or "-"; SIG r || s)
  estok SRC D PAYLOAD TOKEN            the ES256 token jwt_sign_batch_pk must issue
  rs SRC KEY MSG SIG                   raw RS256 (KEY: the private key, PKCS#8 DER; only a -DJWT_OPENSSL build signs)
  rsjws SRC KEY SIGNING_INPUT TOKEN
  rstok SRC KEY PAYLOAD TOKEN
  edtok SRC SEED PAYLOAD TOKEN         the token jwt_sign_batch_pk must issue for PAYLOAD (JSON bytes)
  hstok SRC KEY PAYLOAD TOKEN          the token jwt_sign_batch must issue
  refuse SRC PAYLOAD                   a payload both sign APIs must refuse
  sha512 SRC MSG DIGEST
  sc SRC X DIGEST                      X: 64 bytes little-endian; DIGEST: X mod L, 32 bytes little-endian
  b64 SRC BYTES TEXT                   unpadded base64url
"""

import base64
import hashlib
import hmac
import json
import os
import random
import re
import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

L = 2**252 + 27742317777372353535851937790883648493
CANON_HS = b'{"alg":"HS256","typ":"JWT"}'
CANON_ED = b'{"alg":"EdDSA","typ":"JWT"}'
CANON_ES = b'{"alg":"ES256","typ":"JWT"}'
N256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
try:  # deterministic (RFC 6979) ECDSA: cryptography >= 43 (the Makefile's pyenv-sign makes sure)
    DET = ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
except TypeError:
    raise SystemExit("make_sign_vectors.py: needs cryptography >= 43 for deterministic ECDSA (make build/pyenv-sign)")


def es_key(d):
    return ec.derive_private_key(int.from_bytes(d, "big"), ec.SECP256R1())


def es_sign(d, msg):
    sk = es_key(d)
    der = sk.sign(msg, DET)
    sk.public_key().verify(der, msg, ec.ECDSA(hashes.SHA256()))  # raises if not
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def es_pub(d):
    n = es_key(d).public_key().public_numbers()
    return n.x.to_bytes(32, "big"), n.y.to_bytes(32, "big")


def es_token(d, payload):
    si = b64u(CANON_ES) + "." + b64u(payload)
    return si + "." + b64u(es_sign(d, si.encode()))


CANON_RS = b'{"alg":"RS256","typ":"JWT"}'


def rs_der(sk):
    return sk.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def rs_sign(sk, msg):
    sig = sk.sign(msg, padding.PKCS1v15(), hashes.SHA256())
    sk.public_key().verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
    return sig


def rs_token(sk, payload):
    si = b64u(CANON_RS) + "." + b64u(payload)
    return si + "." + b64u(rs_sign(sk, si.encode()))


def rfc7515_rs(path):
    """A.2: the RS256 example, signed again from its private key (the JWK's n, e, d, p, q, dp, dq, qi)"""
    text = open(path).read()
    text = "\n".join(l for l in text.split("\n") if not re.match(r"^(Jones, et al\.|RFC 7515  )", l)).replace("\f", "")
    sec = text[text.rindex("\nA.2.  Example JWS Using RSASSA") : text.rindex("\nA.3.  Example JWS Using ECDSA")]
    jwk = sec[sec.index('{"kty":"RSA"') :]
    v = {
        f: int.from_bytes(unb64u(re.search(r'"%s":"([^"]+)"' % f, jwk, re.S).group(1)), "big")
        for f in ("n", "e", "d", "p", "q", "dp", "dq", "qi")
    }
    sk = rsa.RSAPrivateNumbers(
        v["p"], v["q"], v["d"], v["dp"], v["dq"], v["qi"], rsa.RSAPublicNumbers(v["e"], v["n"])
    ).private_key()
    tok = re.search(
        r"Compact Serialization \(with line breaks\s+for display purposes only\):\s*\n(.*?)\n\nA.2.2", sec, re.S
    ).group(1)
    tok = re.sub(r"\s+", "", tok)
    h, pl, sg = tok.split(".")
    si = (h + "." + pl).encode()
    assert rs_sign(sk, si) == unb64u(sg), "RFC 7515 A.2 disagrees with pyca"
    return [f"rsjws rfc7515-a2 {hx(rs_der(sk))} {hx(si)} {tok}"]


def rfc6979(path):
    """A.2.5: P-256 with SHA-256, "sample" and "test" (the other hashes' lines are skipped)"""
    text = open(path).read()
    sec = text[text.rindex("\nA.2.5.  ECDSA, 256 Bits") : text.rindex("\nA.2.6.  ECDSA, 384 Bits")]
    d = bytes.fromhex(re.search(r"\n   x = ([0-9A-F]+)", sec).group(1))
    ux = bytes.fromhex(re.search(r"Ux = ([0-9A-F]+)", sec).group(1))
    uy = bytes.fromhex(re.search(r"Uy = ([0-9A-F]+)", sec).group(1))
    assert es_pub(d) == (ux, uy), "RFC 6979 A.2.5 key disagrees with pyca"
    out = []
    for m in re.finditer(
        r'With SHA-256, message = "(\w+)":\s+k = ([0-9A-F]+)\s+r = ([0-9A-F]+)\s+s = ([0-9A-F]+)', sec
    ):
        msg, k, rr, ss = m.group(1).encode(), m.group(2), m.group(3), m.group(4)
        sig = bytes.fromhex(rr) + bytes.fromhex(ss)
        assert es_sign(d, msg) == sig, f"RFC 6979 A.2.5 {msg} disagrees with pyca"
        out.append(f"es rfc6979-a25-{msg.decode()} {hx(d)} {hx(ux)} {hx(uy)} {hx(msg)} {k.lower()} {hx(sig)}")
    assert len(out) == 2, out
    return out


def hx(b):
    return b.hex() or "-"


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s):
    s = re.sub(r"\s+", "", s)
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def ed_key(seed):
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


def ed_pub(sk):
    return sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def ed_sign(seed, msg):
    sk = ed_key(seed)
    sig = sk.sign(msg)
    sk.public_key().verify(sig, msg)  # raises if not
    return sig


def rfc8032(path):
    """7.1: TEST 1, 2, 3, 1024 and SHA(abc); hex blocks span lines and page breaks"""
    text = open(path).read()
    text = "\n".join(l for l in text.split("\n") if not re.match(r"^(Josefsson & Liusvaara|RFC 8032  )", l)).replace(
        "\f", ""
    )
    sec = text[text.rindex("\n7.1.  Test Vectors for Ed25519") : text.rindex("\n7.2.  Test Vectors for Ed25519ctx")]
    out = []
    for blk in sec.split("-----TEST ")[1:]:
        lines = blk.split("\n")
        name, fields, cur = lines[0].strip(), {}, None
        for l in lines[1:]:
            t = l.strip()
            if not t:
                continue
            if t.endswith(":"):
                cur = t.split(" (")[0].rstrip(":")
                fields[cur] = ""
                continue
            if cur and re.fullmatch(r"[0-9a-f]+", t):
                fields[cur] += t
            elif cur:
                cur = None
        sk, pk, msg, sig = (bytes.fromhex(fields[k]) for k in ("SECRET KEY", "PUBLIC KEY", "MESSAGE", "SIGNATURE"))
        assert ed_pub(ed_key(sk)) == pk and ed_sign(sk, msg) == sig, f"RFC 8032 TEST {name} disagrees with pyca"
        out.append(f"ed rfc8032-test-{name.replace(' ', '-')} {hx(sk)} {hx(pk)} {hx(msg)} {hx(sig)}")
    assert len(out) == 5, out
    return out


def rfc8037(path):
    text = open(path).read()
    d = unb64u(re.search(r'"d":"([^"]+)"', text).group(1))
    m = re.search(r"So the compact serialization of the JWS is.*?\n\n(.*?)\n\n", text, re.S)
    tok = re.sub(r"\s+", "", m.group(1))
    h, p, s = tok.split(".")
    si = (h + "." + p).encode()
    assert ed_sign(d, si) == unb64u(s), "RFC 8037 A.4 disagrees with pyca"
    return [f"edjws rfc8037-a4 {hx(d)} {hx(si)} {tok}", f"refuse rfc8037-a4-payload {hx(unb64u(p))}"]


def rfc7515(path):
    text = open(path).read()
    text = "\n".join(l for l in text.split("\n") if not re.match(r"^(Jones, et al\.|RFC 7515  )", l)).replace("\f", "")
    sec = text[text.rindex("\nA.1.  Example JWS Using HMAC SHA-256") : text.rindex("\nA.2.  Example JWS Using RSASSA")]
    k = unb64u(re.search(r'"k":"([^"]+)"', sec, re.S).group(1))
    tok = re.search(
        r"Compact Serialization \(with line breaks\s+for display purposes only\):\s*\n(.*?)\n\nA.1.2", sec, re.S
    ).group(1)
    tok = re.sub(r"\s+", "", tok)
    h, p, s = tok.split(".")
    si = (h + "." + p).encode()
    assert hmac.new(k, si, hashlib.sha256).digest() == unb64u(s), "RFC 7515 A.1 did not verify"
    # its claims ({"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}) are signable as they are:
    # under the canonical header the payload segment must come out exactly as A.1's
    pl = unb64u(p)
    t2 = b64u(CANON_HS) + "." + p
    t2 += "." + b64u(hmac.new(k, t2.encode(), hashlib.sha256).digest())
    return [f"hsjws rfc7515-a1 {hx(k)} {hx(si)} {tok}", f"hstok rfc7515-a1-payload {hx(k)} {hx(pl)} {t2}"]


def hs_token(key, payload):
    si = b64u(CANON_HS) + "." + b64u(payload)
    return si + "." + b64u(hmac.new(key, si.encode(), hashlib.sha256).digest())


def ed_token(seed, payload):
    si = b64u(CANON_ED) + "." + b64u(payload)
    return si + "." + b64u(ed_sign(seed, si.encode()))


def rand_claims(rnd, i):
    c = {}
    if rnd.random() < 0.7:
        c["sub"] = str(rnd.randrange(1, 10**12))
    if rnd.random() < 0.7:
        name = "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz_.-0123456789") for _ in range(rnd.randrange(0, 40)))
        if rnd.random() < 0.2:
            name += rnd.choice(['"quoted"', "\\back", "é", "ü€😀", "\n"])
        c["username"] = name
    if rnd.random() < 0.5:
        c["iat"] = 1700000000 + rnd.randrange(10**6)
    c["exp"] = 4102444800 + rnd.randrange(10**6) if rnd.random() < 0.9 else 1.5e9 + rnd.random()
    if rnd.random() < 0.3:
        c["nbf"] = 1600000000
    if rnd.random() < 0.3:
        c["roles"] = [rnd.choice(["admin", "user", "ops"]) for _ in range(rnd.randrange(0, 5))]
    if rnd.random() < 0.2:
        c["pad"] = "x" * rnd.randrange(0, 700)
    keys = list(c)
    rnd.shuffle(keys)
    c = {k: c[k] for k in keys}
    sep = (",", ":") if rnd.random() < 0.7 else (", ", ": ")
    return json.dumps(c, separators=sep, ensure_ascii=rnd.random() < 0.5).encode()


REFUSE = [
    b"",
    b"null",
    b"[]",
    b'["exp",1]',
    b"{}",
    b"  {}  ",
    b'{"sub":"1"}',  # no exp
    b'{"exp":"4102444800"}',  # exp must be a number
    b'{"exp":4102444800,"nbf":"x"}',
    b'{"exp":4102444800,"exp":4102444801}',
    b'{"exp":4102444800,"sub":"1","sub":"2"}',
    b'{"exp":4102444800,"username":"a","username":"b"}',
    b'{"exp":4102444800,"nbf":1,"nbf":2}',
    b'{"ex\\u0070":4102444800,"exp":4102444801}',  # a repeat spelled with an escape
    b'{"exp":4102444800}x',
    b'{"exp":4102444800}{}',
    b'{"exp":4102444800,}',
    b'{"exp":4102444800 "a":1}',
    b'{"exp":04102444800}',
    b'{"exp":4102444800,"a":"\xff"}',  # invalid UTF-8
    b'{"exp":4102444800,"a":"\xed\xa0\x80"}',  # a UTF-8 surrogate
    b'{"exp":4102444800,"a":"\xc0\xaf"}',  # overlong
    b'{"exp":4102444800,"a":"tab\there"}',  # raw control character
    b'{"exp":4102444800,"a":"\\x"}',
    b'{"exp":4102444800,"a":' + b"[" * 40 + b"]" * 40 + b"}",  # nesting deeper than 32
    b'{"exp":4102444800,"a":tru}',
    b'{"exp":4102444800,"a":NaN}',
    b"{'exp':4102444800}",
    b'{"exp":1e}',
    b'{"exp":4102444800,"pad":"' + b"x" * 6200 + b'"}',  # the token would exceed JWT_TOKEN_MAX
]
ACCEPT = [
    b'{"exp":4102444800}',
    b' \t\r\n{ "exp" : 4102444800 } \n',
    b'{"exp":-1}',  # issued, and rejected by the verifier at any time after 1970
    b'{"exp":1.5e9,"nbf":-2.5E+3}',
    b'{"exp":4102444800,"a":' + b"[" * 30 + b"]" * 30 + b"}",
    b'{"exp":4102444800,"alg":"none","alg":"none"}',  # alg is not a payload claim: repeats are allowed
    b'{"exp":4102444800,"sub":1,"username":null}',  # BAD_PAYLOAD for the verifier's profile, still issued
    b'{"exp":4102444800,"a":"\\ud800"}',  # a lone surrogate escape is valid JSON
    b'{"exp":4102444800,"pad":"' + b"x" * 5000 + b'"}',
]


def main():
    vdir, nrand, seed = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    V = lambda f: os.path.join(vdir, f)
    rnd = random.Random(seed)
    out = rfc8032(V("rfc8032.txt")) + rfc8037(V("rfc8037.txt")) + rfc7515(V("rfc7515.txt")) + rfc6979(V("rfc6979.txt"))
    out += rfc7515_rs(V("rfc7515.txt"))
    rs_keys = [rsa.generate_private_key(65537, b) for b in (2048, 2048, 3072, 4096)]
    rs_keys.append(rsa.generate_private_key(3, 2048))  # a small public exponent
    for i in range(min(nrand, 100)):  # raw RS256 (key generation is slow: a few keys, many messages)
        sk = rs_keys[i % len(rs_keys)]
        msg = rnd.randbytes(i % 300 if i % 10 else rnd.randrange(300, 5000))
        out.append(f"rs pyca-{i} {hx(rs_der(sk))} {hx(msg)} {hx(rs_sign(sk, msg))}")
    for i in range(nrand):  # raw Ed25519: random seeds, messages of every short length and some long ones
        sd = rnd.randbytes(32)
        msg = rnd.randbytes(i % 300 if i % 10 else rnd.randrange(300, 5000))
        out.append(f"ed pyca-{i} {hx(sd)} {hx(ed_pub(ed_key(sd)))} {hx(msg)} {hx(ed_sign(sd, msg))}")
    for i in range(nrand):  # raw ES256: random keys (and the edges 1, n - 1), messages of every short length
        d = (rnd.randrange(1, N256) if i > 1 else (1, N256 - 1)[i]).to_bytes(32, "big")
        msg = rnd.randbytes(i % 300 if i % 10 else rnd.randrange(300, 5000))
        x, y = es_pub(d)
        out.append(f"es pyca-{i} {hx(d)} {hx(x)} {hx(y)} {hx(msg)} - {hx(es_sign(d, msg))}")
    for sd in (bytes(32), b"\xff" * 32):
        out.append(f"ed pyca-edge-{sd[0]:02x} {hx(sd)} {hx(ed_pub(ed_key(sd)))} - {hx(ed_sign(sd, b''))}")
    for i in range(nrand):  # whole tokens
        key = rnd.randbytes(rnd.choice([0, 1, 6, 32, 64, 65, 100]))
        sd = rnd.randbytes(32)
        pl = rand_claims(rnd, i)
        out.append(f"hstok pyca-{i} {hx(key)} {hx(pl)} {hs_token(key, pl)}")
        out.append(f"edtok pyca-{i} {hx(sd)} {hx(pl)} {ed_token(sd, pl)}")
        d = rnd.randrange(1, N256).to_bytes(32, "big")
        out.append(f"estok pyca-{i} {hx(d)} {hx(pl)} {es_token(d, pl)}")
        if i < 60:
            sk = rs_keys[i % len(rs_keys)]
            out.append(f"rstok pyca-{i} {hx(rs_der(sk))} {hx(pl)} {rs_token(sk, pl)}")
    for j, pl in enumerate(ACCEPT):
        key, sd = rnd.randbytes(32), rnd.randbytes(32)
        out.append(f"hstok accept-{j} {hx(key)} {hx(pl)} {hs_token(key, pl)}")
        out.append(f"edtok accept-{j} {hx(sd)} {hx(pl)} {ed_token(sd, pl)}")
        out.append(f"estok accept-{j} {hx(sd)} {hx(pl)} {es_token(sd, pl)}")
    for j, pl in enumerate(REFUSE):
        out.append(f"refuse refuse-{j} {hx(pl)}")
    for n in list(range(0, 300)) + [1000, 4096, 10000]:
        m = rnd.randbytes(n)
        out.append(f"sha512 len-{n} {hx(m)} {hashlib.sha512(m).hexdigest()}")
    edges = [
        0,
        1,
        L - 1,
        L,
        L + 1,
        2 * L - 1,
        2 * L,
        2**252 - 1,
        2**252,
        2**253,
        2**256 - 1,
        2**256,
        2**504 - 1,
        2**504,
        2**512 - 1,
        2**512 - L,
        (2**512 // L) * L,
        (2**512 // L) * L - 1,
        2**255 - 19,
    ]
    edges += [rnd.randrange(2**512) for _ in range(200)] + [rnd.randrange(2**256) for _ in range(50)]
    for j, x in enumerate(edges):
        out.append(f"sc edge-{j} {hx(x.to_bytes(64, 'little'))} {hx((x % L).to_bytes(32, 'little'))}")
    for n in range(0, 70):
        b = rnd.randbytes(n)
        out.append(f"b64 len-{n} {hx(b)} {b64u(b) or '-'}")
    allb = bytes(range(256))
    out.append(f"b64 all-bytes {hx(allb)} {b64u(allb)}")
    sys.stdout.write("\n".join(out) + "\n")
    print(f"sign vectors: {len(out)} lines, every signature checked with pyca/cryptography", file=sys.stderr)


if __name__ == "__main__":
    main()
