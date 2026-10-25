#!/usr/bin/env python3
"""make_pk_vectors.py VECTOR_DIR N_RANDOM SEED > pk_vectors.txt

RS256 / ES256 vectors for tests/test_pk.c (the -DJWT_PK prototype).  Sources, all fetched by scripts/fetch-vectors.sh:
  Wycheproof ecdsa_secp256r1_sha256_p1363_test.json (JOSE's r || s format) and rsa_signature_{2048,3072,4096}_sha256;
  NIST CAVP SigVer.rsp [P-256,SHA-256] and SigVer15_186-3.rsp (SHA256, mod >= 2048, assorted public exponents;
  its messages (128 bytes) and signatures are printed without leading zero nibbles, so they are left-padded);
  RFC 7515 A.2 (RS256) and A.3 (ES256) JWS examples;
  random keys, signatures and whole JWTs from pyca/cryptography.
Every vector is first checked against pyca/cryptography, so a parsing mistake cannot pass silently.  Wycheproof's
"acceptable" cases are skipped (none of them is a correct encoding).

Output, one per line (hex, "-" = empty):
  es SRC X Y MSG SIG EXPECT                         EXPECT 1 = valid, 0 = invalid; SIG is r || s (any length)
  rs SRC N E MSG SIG EXPECT
  ed SRC A MSG SIG EXPECT                           EdDSA (Ed25519): A = the 32-byte public key
  jwt SRC ALG K1 K2 TOKEN NOW STATUS UID USERNAME   ALG ES256 (K1, K2 = x, y), RS256 (n, e) or EdDSA (A, -); USERNAME hex
  rspair SRC N E MSG1 SIG1 MSG2 SIG2                two genuine signatures turned into s1*x, s2/x: each is invalid,
                                                    but their product is unchanged (what -DJWT_RSA_SCREEN accepts)
"""
import base64, json, os, random, re, sys, zipfile
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

N256 = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551


def hx(b): return b.hex() or "-"
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def unb64u(s): s = re.sub(r"\s+", "", s); return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def i2b(i, n=None): n = n or max(1, (i.bit_length() + 7) // 8); return i.to_bytes(n, "big")


def es_ok(x, y, msg, sig):
    """pyca's verdict on a JOSE (r || s) ES256 signature: exactly 64 bytes, then ECDSA."""
    if len(sig) != 64: return False
    try:
        pub = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()
    except ValueError:
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (0 < r < N256 and 0 < s < N256): return False
    try:
        pub.verify(encode_dss_signature(r, s), msg, ec.ECDSA(hashes.SHA256())); return True
    except InvalidSignature:
        return False


def rs_ok(n, e, msg, sig):
    """pyca's verdict on RSASSA-PKCS1-v1_5 SHA-256; JWS also requires the signature to be exactly k bytes."""
    if len(sig) != (n.bit_length() + 7) // 8: return False
    try:
        rsa.RSAPublicNumbers(e, n).public_key().verify(sig, msg, padding.PKCS1v15(), hashes.SHA256()); return True
    except (InvalidSignature, ValueError):
        return False


def ed_ok(a, msg, sig):
    """pyca's verdict on an Ed25519 signature (OpenSSL underneath: RFC 8032 with S < L, cofactorless)."""
    if len(sig) != 64: return False
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(a).verify(sig, msg); return True
    except (InvalidSignature, ValueError):
        return False


def wycheproof_ed(path):
    out = []
    for g in json.load(open(path))["testGroups"]:
        a = bytes.fromhex(g["publicKey"]["pk"])
        for t in g["tests"]:
            if t["result"] == "acceptable": continue   # small- / mixed-order keys: either answer is allowed
            out.append(("ed", f"wycheproof-ed-{t['tcId']}", a, None, bytes.fromhex(t["msg"]), bytes.fromhex(t["sig"]),
                        int(t["result"] == "valid")))
    return out


def rfc8032_ed(path):
    """section 7.1: TEST 1, 2, 3, 1024 and SHA(abc); hex blocks span lines and page breaks"""
    text = open(path).read()
    text = "\n".join(l for l in text.split("\n") if not re.match(r"^(Josefsson & Liusvaara|RFC 8032  )", l)).replace("\f", "")
    sec = text[text.rindex("\n7.1.  Test Vectors for Ed25519"):text.rindex("\n7.2.  Test Vectors for Ed25519ctx")]
    out = []
    for blk in sec.split("-----TEST ")[1:]:
        lines = blk.split("\n")
        name, fields, cur = lines[0].strip(), {}, None
        for l in lines[1:]:
            t = l.strip()
            if not t: continue
            if t.endswith(":"): cur = t.split(" (")[0].rstrip(":"); fields[cur] = ""; continue
            if cur and re.fullmatch(r"[0-9a-f]+", t): fields[cur] += t
            elif cur: cur = None   # prose after the block
        a, msg, sig = (bytes.fromhex(fields[k]) for k in ("PUBLIC KEY", "MESSAGE", "SIGNATURE"))
        out.append(("ed", f"rfc8032-test-{name}", a, None, msg, sig, 1))
    assert len(out) == 5, [o[1] for o in out]
    return out


def rfc8037_ed(path):
    """A.4: the Ed25519 JWS (payload is not a JWT claims set, so it is checked as a raw signature)"""
    text = open(path).read()
    a = unb64u(re.search(r'"x":"([^"]+)"', text).group(1))
    m = re.search(r"So the compact serialization of the JWS is.*?\n\n(.*?)\n\n", text, re.S)
    tok = re.sub(r"\s+", "", m.group(1))
    h, p, sg = tok.split(".")
    si, sig = (h + "." + p).encode(), unb64u(sg)
    bad = sig[:10] + bytes([sig[10] ^ 1]) + sig[11:]
    return [("ed", "rfc8037-a4", a, None, si, sig, 1), ("ed", "rfc8037-a4-tampered", a, None, si, bad, 0)]


def wycheproof_es(path):
    out = []
    for g in json.load(open(path))["testGroups"]:
        x, y = bytes.fromhex(g["publicKey"]["wx"]), bytes.fromhex(g["publicKey"]["wy"])
        x, y = x[-32:].rjust(32, b"\0"), y[-32:].rjust(32, b"\0")
        for t in g["tests"]:
            if t["result"] == "acceptable": continue
            out.append(("es", f"wycheproof-es-{t['tcId']}", x, y, bytes.fromhex(t["msg"]), bytes.fromhex(t["sig"]), int(t["result"] == "valid")))
    return out


def wycheproof_rs(path, bits):
    out = []
    for g in json.load(open(path))["testGroups"]:
        n, e = int(g["publicKey"]["modulus"], 16), int(g["publicKey"]["publicExponent"], 16)
        for t in g["tests"]:
            if t["result"] == "acceptable": continue
            out.append(("rs", f"wycheproof-rs{bits}-{t['tcId']}", n, e, bytes.fromhex(t["msg"]), bytes.fromhex(t["sig"]), int(t["result"] == "valid")))
    return out


def cavp_es(path):
    text = zipfile.ZipFile(path).read("186-4ecdsatestvectors/SigVer.rsp").decode()
    sec = text[text.index("[P-256,SHA-256]"):]
    sec = sec[:sec.index("[", 5)]
    out = []
    for i, blk in enumerate(re.split(r"\n\s*\n", sec)):
        d = dict(re.findall(r"^(\w+) = (\S+)", blk, re.M))
        if "Msg" not in d: continue
        sig = bytes.fromhex(d["R"].rjust(64, "0")) + bytes.fromhex(d["S"].rjust(64, "0"))
        out.append(("es", f"cavp-es-{i}", bytes.fromhex(d["Qx"].rjust(64, "0")), bytes.fromhex(d["Qy"].rjust(64, "0")),
                    bytes.fromhex(d["Msg"]), sig, int(d["Result"] == "P")))
    assert len(out) == 15, len(out)
    return out


def cavp_rs(path):
    text = zipfile.ZipFile(path).read("SigVer15_186-3.rsp").decode().replace("\r", "")
    out, n, mod = [], None, 0
    for blk in re.split(r"\n\s*\n", text):
        m = re.search(r"\[mod = (\d+)\]", blk)
        if m: mod = int(m.group(1))
        d = dict(re.findall(r"^(\w+) = (\S+)", blk, re.M))
        if "n" in d: n = int(d["n"], 16)
        if "Msg" in d and d.get("SHAAlg") == "SHA256" and mod >= 2048:
            k = (n.bit_length() + 7) // 8
            out.append(("rs", f"cavp-rs{mod}-{len(out)}", n, int(d["e"], 16), bytes.fromhex(d["Msg"].rjust(256, "0")),
                        bytes.fromhex(d["S"].rjust(2 * k, "0")), int(d["Result"].startswith("P"))))
    assert len(out) >= 12, len(out)
    return out


def rfc7515(path):
    text = open(path).read()
    text = "\n".join(l for l in text.split("\n") if not re.match(r"^(Jones, et al\.|RFC 7515  )", l)).replace("\f", "")
    def section(a, b): return text[text.rindex("\n" + a):text.rindex("\n" + b)]   # rindex: skip the ToC
    def jws(sec, nxt):
        tok = re.search(r"Compact Serialization \(with line breaks\s+for display purposes only\):\s*\n(.*?)\n\n" + nxt, sec, re.S).group(1)
        return re.sub(r"\s+", "", tok)
    a2 = section("A.2.  Example JWS Using RSASSA", "A.3.  Example JWS Using ECDSA")
    n = int.from_bytes(unb64u(re.search(r'"n":"([^"]+)"', a2).group(1)), "big")
    e = int.from_bytes(unb64u(re.search(r'"e":"([^"]+)"', a2).group(1)), "big")
    a3 = section("A.3.  Example JWS Using ECDSA P-256", "A.4.  Example JWS Using ECDSA P-521")
    x, y = unb64u(re.search(r'"x":"([^"]+)"', a3).group(1)), unb64u(re.search(r'"y":"([^"]+)"', a3).group(1))
    exp, out = 1300819380, []
    for alg, k1, k2, tok in (("RS256", n, e, jws(a2, "A.2.2")), ("ES256", x, y, jws(a3, "A.3.2"))):
        h, p, s = tok.split(".")
        ok = rs_ok(k1, k2, (h + "." + p).encode(), unb64u(s)) if alg == "RS256" else es_ok(k1, k2, (h + "." + p).encode(), unb64u(s))
        assert ok, f"RFC 7515 {alg} example did not verify"
        j = len(tok) - 10; bad = tok[:j] + ("A" if tok[j] != "A" else "B") + tok[j + 1:]
        # live: signature and time fine but no sub/username -> BAD_PAYLOAD; expired -> INVALID; tampered -> INVALID
        out += [("jwt", f"rfc7515-{alg}-live", alg, k1, k2, tok, exp - 1, 2, 0, b""),
                ("jwt", f"rfc7515-{alg}-expired", alg, k1, k2, tok, exp, 1, 0, b""),
                ("jwt", f"rfc7515-{alg}-tampered", alg, k1, k2, bad, exp - 1, 1, 0, b"")]
    return out


L25519 = 2**252 + 27742317777372353535851937790883648493


def ed_pub(kp):
    from cryptography.hazmat.primitives import serialization
    return kp.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def es_sign(priv, msg):
    r, s = decode_dss_signature(priv.sign(msg, ec.ECDSA(hashes.SHA256())))
    return i2b(r, 32) + i2b(s, 32)


def rs_sign(priv, msg): return priv.sign(msg, padding.PKCS1v15(), hashes.SHA256())


def randoms(rnd, nrand):
    out, now = [], 1_800_000_000
    es_keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(8)]
    global rs_keys_for_pairs
    rs_keys = rs_keys_for_pairs = [rsa.generate_private_key(65537, b) for b in (2048, 2048, 2048, 3072, 4096)] + [rsa.generate_private_key(3, 2048)]
    ed_keys = [ed25519.Ed25519PrivateKey.generate() for _ in range(6)]
    for i in range(nrand):
        ml = rnd.choice([0, 1, 55, 56, 63, 64, 65, 119, 120, 128, rnd.randrange(0, 1101)])
        msg = rnd.randbytes(ml)
        if i % 4 == 3:   # EdDSA: corrupted signatures, S + L (non-canonical), R flipped
            kp = rnd.choice(ed_keys); a = ed_pub(kp); sig = kp.sign(msg)
            r = rnd.random()
            if r < 0.1: sig = sig[:32] + (int.from_bytes(sig[32:], "little") + L25519).to_bytes(32, "little")
            elif r < 0.25:
                j = rnd.randrange(64); sig = sig[:j] + bytes([sig[j] ^ (1 << rnd.randrange(8))]) + sig[j + 1:]
            out.append(("ed", f"random-ed-{i}", a, None, msg, sig, None))
        elif i % 3:   # ES256
            kp = rnd.choice(es_keys); pn = kp.public_key().public_numbers()
            x, y = i2b(pn.x, 32), i2b(pn.y, 32); sig = es_sign(kp, msg)
            if rnd.random() < 0.15:   # the other valid s (ECDSA is malleable; JWS does not forbid high s)
                s = N256 - int.from_bytes(sig[32:], "big"); sig = sig[:32] + i2b(s, 32)
            if rnd.random() < 0.15:
                j = rnd.randrange(64); sig = sig[:j] + bytes([sig[j] ^ (1 << rnd.randrange(8))]) + sig[j + 1:]
            out.append(("es", f"random-es-{i}", x, y, msg, sig, None))
        else:       # RS256
            kp = rnd.choice(rs_keys); pn = kp.public_key().public_numbers(); sig = rs_sign(kp, msg)
            if rnd.random() < 0.15:
                j = rnd.randrange(len(sig)); sig = sig[:j] + bytes([sig[j] ^ (1 << rnd.randrange(8))]) + sig[j + 1:]
            out.append(("rs", f"random-rs-{i}", pn.n, pn.e, msg, sig, None))
    # whole tokens, through jwt_verify_batch_pk
    for alg, keys in (("ES256", es_keys[:3]), ("RS256", rs_keys), ("EdDSA", ed_keys[:3])):
        for ki, kp in enumerate(keys):
            if alg == "EdDSA":
                k1, k2, sign = ed_pub(kp), None, lambda k, m: k.sign(m)
            else:
                pn = kp.public_key().public_numbers()
                k1, k2 = (i2b(pn.x, 32), i2b(pn.y, 32)) if alg == "ES256" else (pn.n, pn.e)
                sign = es_sign if alg == "ES256" else rs_sign
            for t in range(40):
                uid = rnd.randrange(1, 10**12); user = ("user%d" % rnd.randrange(10**6)).encode()
                hdr = rnd.choice([{"alg": alg, "typ": "JWT"}, {"typ": "JWT", "alg": alg}, {"alg": alg, "kid": "k%d" % ki}])
                claims = {"sub": str(uid), "username": user.decode(), "iat": now - 100, "exp": now + rnd.randrange(1, 10**6)}
                kind = rnd.choice(["ok"] * 5 + ["expired", "badsig", "badalg", "nouser", "padding"])
                if kind == "expired": claims["exp"] = now - rnd.randrange(0, 1000)
                if kind == "nouser": del claims["username"]
                if kind == "badalg": hdr["alg"] = {"ES256": "EdDSA", "RS256": "ES256", "EdDSA": "ES256"}[alg]
                h = b64u(json.dumps(hdr, separators=(",", ":")).encode()); p = b64u(json.dumps(claims, separators=(",", ":")).encode())
                sig = sign(kp, (h + "." + p).encode()); s64 = b64u(sig)
                if kind == "badsig": j = rnd.randrange(len(s64) - 1); s64 = s64[:j] + ("A" if s64[j] != "A" else "B") + s64[j + 1:]
                if kind == "padding": s64 += "="
                tok = h + "." + p + "." + s64
                st = {"ok": 0, "nouser": 2}.get(kind, 1)
                out.append(("jwt", f"random-jwt-{alg}-{ki}-{t}-{kind}", alg, k1, k2, tok, now, st, uid if st == 0 else 0, user if st == 0 else b""))
    return out


def main():
    vdir, nrand, seed = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    V = lambda f: os.path.join(vdir, f)
    vec = wycheproof_es(V("ecdsa_secp256r1_sha256_p1363_test.json")) + cavp_es(V("186-4ecdsatestvectors.zip"))
    for b in (2048, 3072, 4096): vec += wycheproof_rs(V(f"rsa_signature_{b}_sha256_test.json"), b)
    vec += cavp_rs(V("186-3rsatestvectors.zip"))
    vec += wycheproof_ed(V("ed25519_test.json")) + rfc8032_ed(V("rfc8032.txt")) + rfc8037_ed(V("rfc8037.txt"))
    rnd = random.Random(seed)
    vec += randoms(rnd, nrand)
    w, counts = sys.stdout.write, {}
    for v in vec:
        if v[0] in ("es", "rs", "ed"):
            kind, src, k1, k2, msg, sig, expect = v
            got = es_ok(k1, k2, msg, sig) if kind == "es" else rs_ok(k1, k2, msg, sig) if kind == "rs" else ed_ok(k1, msg, sig)
            if expect is None: expect = int(got)
            elif got != bool(expect): raise SystemExit(f"{src}: parsed vector disagrees with cryptography (expect {expect})")
            if kind == "ed": w(f"ed {src} {hx(k1)} {hx(msg)} {hx(sig)} {expect}\n")
            else:
                k1h, k2h = (hx(k1), hx(k2)) if kind == "es" else (hx(i2b(k1)), hx(i2b(k2)))
                w(f"{kind} {src} {k1h} {k2h} {hx(msg)} {hx(sig)} {expect}\n")
            counts[src.split("-")[0] + "-" + kind] = counts.get(src.split("-")[0] + "-" + kind, 0) + 1
    for v in rfc7515(V("rfc7515.txt")) + [v for v in vec if v[0] == "jwt"]:
        _, src, alg, k1, k2, tok, now, st, uid, user = v
        if alg == "ES256": k1h, k2h = hx(k1), hx(k2)
        elif alg == "EdDSA": k1h, k2h = hx(k1), "-"
        else: k1h, k2h = hx(i2b(k1)), hx(i2b(k2))
        w(f"jwt {src} {alg} {k1h} {k2h} {tok} {now} {st} {uid} {hx(user)}\n")
        counts["jwt"] = counts.get("jwt", 0) + 1
    for i in range(4):   # screening counterexamples
        kp = rs_keys_for_pairs[i % len(rs_keys_for_pairs)]; pn = kp.public_key().public_numbers(); k = (pn.n.bit_length() + 7) // 8
        m1, m2 = rnd.randbytes(100), rnd.randbytes(150)
        s1, s2 = int.from_bytes(rs_sign(kp, m1), "big"), int.from_bytes(rs_sign(kp, m2), "big")
        x = rnd.randrange(2, pn.n - 1)
        t1, t2 = i2b(s1 * x % pn.n, k), i2b(s2 * pow(x, -1, pn.n) % pn.n, k)
        assert not rs_ok(pn.n, pn.e, m1, t1) and not rs_ok(pn.n, pn.e, m2, t2)
        w(f"rspair screen-pair-{i} {hx(i2b(pn.n))} {hx(i2b(pn.e))} {hx(m1)} {hx(t1)} {hx(m2)} {hx(t2)}\n")
    print("pk vectors, all consistent with cryptography: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())), file=sys.stderr)


if __name__ == "__main__":
    main()
