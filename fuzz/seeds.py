#!/usr/bin/env python3
"""seeds.py OUTDIR — starting corpora for the fuzz harnesses (deterministic; Python stdlib only).
OUTDIR/verify: config byte + newline-separated tokens (valid ones, edge cases from the claim table, junk);
OUTDIR/b64: base64url strings; OUTDIR/pk: algorithm byte + message + mutation ops."""
import base64, hashlib, hmac, json, os, random, sys

out = sys.argv[1]
for d in ("verify", "b64", "pk"): os.makedirs(os.path.join(out, d), exist_ok=True)
rnd = random.Random(1)
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=")
SECRET = b"cursed-jwt-test-secret"
EXP = 1_800_000_000 + 3600


def tok(payload, header=b'{"alg":"HS256","typ":"JWT"}', secret=SECRET):
    si = b64u(header) + b"." + b64u(payload)
    return si + b"." + b64u(hmac.new(secret, si, hashlib.sha256).digest())


payloads = [
    {"sub": "1", "username": "alice", "iat": 1, "exp": EXP},
    {"sub": "9223372036854775807", "username": "a" * 255, "exp": EXP},
    {"sub": "0", "username": "x", "exp": EXP},
    {"sub": "007", "username": "é€\U0001f600", "exp": EXP + 0.5, "nbf": 1},
    {"sub": "1", "username": "q\"\\\n", "exp": EXP, "x": [1, {"y": None}], "z": True},
    {"exp": EXP}, {"sub": 1, "username": "n", "exp": EXP}, {"sub": "1", "username": "n", "exp": "soon"},
]
raws = [json.dumps(p, separators=(",", ":")).encode() for p in payloads] + [
    b'{"sub":"1","sub":"2","username":"d","exp":%d}' % EXP, b'{"\\u0073ub":"5","username":"\\ud800","exp":%d}' % EXP,
    b' { "sub" : "3" , "username" : "w" , "exp" : 1.8000036e9 } ', b'{"sub":"1","username":"t","exp":%d,}' % EXP,
    b'{"sub":"1","username":"\xc3\xa9","exp":1e400}', b'{"a":' + b"[" * 40 + b"]" * 40 + b',"exp":%d}' % EXP,
]
toks = [tok(r) for r in raws] + [tok(raws[0], b'{"alg":"none"}'), tok(raws[0], b'{"typ":"JWT","alg":"HS256","kid":"k"}'),
                                 tok(raws[0], secret=b"wrong"), b"a.b.c", b"..", b"", b"x" * 300, tok(raws[0]) + b"="]
for i, t in enumerate(toks):   # one token per seed, alternating re-sign on/off and now
    open(os.path.join(out, "verify", "t%02d" % i), "wb").write(bytes([i % 16]) + t)
open(os.path.join(out, "verify", "batch"), "wb").write(b"\x01" + b"\n".join(toks))
for i, t in enumerate(toks[:6]): open(os.path.join(out, "b64", "s%02d" % i), "wb").write(t.split(b".")[min(1, t.count(b"."))])
for s in (b"", b"A", b"AA", b"AAA", b"AAAA", b"AB", b"-_", b"QQ", b"QR", b"Zm9vYmFy" * 9):
    open(os.path.join(out, "b64", "e" + s[:8].hex()), "wb").write(s)
for i in range(16):   # alg/fill byte, message length, message, mutation triples
    msg = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 60)))
    ops = bytes(rnd.randrange(256) for _ in range(3 * rnd.randrange(0, 4)))
    open(os.path.join(out, "pk", "p%02d" % i), "wb").write(bytes([i, len(msg)]) + msg + ops)
print(f"seeds: {len(toks) + 1} verify, {6 + 10} b64, 16 pk -> {out}")
