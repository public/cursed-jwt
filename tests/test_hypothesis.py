#!/usr/bin/env python3
"""test_hypothesis.py LIB [EXAMPLES] — property-based tests of cursed-jwt against an independent model.

Hypothesis generates whole JWTs: claim values of every JSON type near the interesting boundaries (exp/nbf around
now, sub around 1 and 2^63-1 with leading zeros and escapes, usernames around 255 bytes with multibyte characters
and lone surrogates), random extra claims nested up to and past the 32-level limit, duplicate keys, escaped keys,
random whitespace and number spellings, header variants, wrong secrets, and byte-level corruption of the JSON,
the base64url and the signature.  Every token goes through every engine of the shared library (tests/pyshim.c,
loaded with ctypes) in a random batch, and each result must equal the model's.

The model is written from the README's claim table, not from the C: Python's json module (with NaN, duplicates and
depth checked by hand) decides JSON validity, Python's hmac computes the MAC, pyca/cryptography signs and verifies
RS256 / ES256.  Run by `make test-hypothesis`; EXAMPLES (default 3000) per property.
"""

import base64
import ctypes
import hashlib
import hmac
import json
import os
import sys
from hypothesis import HealthCheck, Phase, given, settings, strategies as st

LIB, NEX = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 3000
lib = ctypes.CDLL(os.path.abspath(LIB))
OK, INVALID, BAD = 0, 1, 2
USERNAME_MAX, TOKEN_MAX = 255, 8192


class Result(ctypes.Structure):
    _fields_ = [
        ("status", ctypes.c_uint8),
        ("username_escape", ctypes.c_uint8),
        ("username_len", ctypes.c_uint16),
        ("uid", ctypes.c_int64),
        ("username", ctypes.c_char_p),
        ("ubuf", ctypes.c_char * (USERNAME_MAX + 1)),
    ]


lib.jt_engine_name.restype = ctypes.c_char_p
lib.jt_sizeof_key.restype = lib.jt_sizeof_result.restype = ctypes.c_size_t
assert lib.jt_sizeof_result() == ctypes.sizeof(Result), "jwt_result_t layout changed"
KEYSZ = lib.jt_sizeof_key()
ENGINES = [(i, lib.jt_engine_name(i).decode()) for i in range(lib.jt_engines())]
lib.jwt_pkey_es256.restype = lib.jwt_pkey_rs256.restype = ctypes.c_void_p
lib.jwt_pkey_free.argtypes = [ctypes.c_void_p]
lib.jwt_verify_batch_pk.argtypes = [
    ctypes.c_void_p,
    ctypes.c_int,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_int64,
    ctypes.c_void_p,
]


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=")


# ------------------------------------------------------------------------------------------------- the model
B64U = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def b64u_strict(s):
    """RFC 4648 base64url without padding, canonical trailing bits; None if invalid."""
    if any(c not in B64U for c in s) or len(s) % 4 == 1:
        return None
    try:
        raw = base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))
    except Exception:
        return None
    return raw if b64u(raw) == s else None  # re-encoding catches non-zero trailing bits


class Reject(Exception):
    pass


def no_constant(name):
    raise Reject(name)  # NaN, Infinity, -Infinity are not JSON


class Obj(list):
    """a JSON object as the list of all its (key, value) pairs: duplicates included, so depth sees every value"""


def depth(v):
    if isinstance(v, Obj):
        return 1 + max((depth(x) for _, x in v), default=0)
    if isinstance(v, list):
        return 1 + max((depth(x) for x in v), default=0)
    return 0


def strict_json(raw):
    """RFC 8259 JSON (UTF-8, no NaN, nesting <= 32): (top-level pairs, value) or None.  The top object's pairs are kept
    in order with duplicates; nested objects become dicts."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    try:
        v = json.loads(text, object_pairs_hook=Obj, parse_constant=no_constant)
    except (ValueError, Reject, RecursionError):
        return None
    if depth(v) > 32:
        return None  # every value counts, including one a later duplicate key replaces
    return (list(v) if isinstance(v, Obj) else None), v


def utf8(s):  # what the C decoder produces: lone surrogates become U+FFFD
    return "".join("�" if 0xD800 <= ord(ch) <= 0xDFFF else ch for ch in s).encode()


def num_cmp(lexeme, value, now):
    """-1 / 0 / 1 for value vs now: integers exactly, anything with a fraction or exponent as a double."""
    if isinstance(value, int):
        return (value > now) - (value < now)
    return (value > now) - (value < now)


def model_claims(raw, now, nums):
    """status, uid, username bytes, escape flag for a payload whose signature checked out."""
    parsed = strict_json(raw)
    if parsed is None or parsed[0] is None:
        return (INVALID,)
    pairs, obj = parsed
    seen = {}
    for k, v in pairs:
        if k in ("sub", "username", "exp", "nbf"):
            if k in seen:
                return (INVALID,)
            seen[k] = v
    if "exp" not in seen:
        return (INVALID,)
    for k in ("exp", "nbf"):
        if k not in seen:
            continue
        v = seen[k]
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            return (INVALID,)
        c = num_cmp(None, v, now)
        if (k == "exp" and c <= 0) or (k == "nbf" and c > 0):
            return (INVALID,)
    sub, user = seen.get("sub"), seen.get("username")
    if not isinstance(sub, str) or not isinstance(user, str):
        return (BAD,)
    sb = utf8(sub)
    if not sb or not all(48 <= c <= 57 for c in sb) or not (1 <= int(sb) <= 2**63 - 1):
        return (BAD,)
    if len(sb) > 32 and nums.get("sub_escaped"):
        return (BAD,)  # escaped sub is decoded into a 32-byte buffer
    ub = utf8(user)
    if len(ub) > USERNAME_MAX:
        return (BAD,)
    return OK, int(sb), ub, int(any(c < 0x20 or c in b'"\\' for c in ub))


def model_header(raw, alg):
    parsed = strict_json(raw)
    if parsed is None or parsed[0] is None:
        return False
    algs = [v for k, v in parsed[0] if k == "alg"]
    return len(algs) == 1 and algs[0] == alg


def model(tok, now, verify_sig, alg, nums):
    """the expected result of one token; verify_sig(signing_input, sig_bytes) -> bool"""
    if not 0 < len(tok) <= TOKEN_MAX:
        return (INVALID,)
    parts = tok.split(b".")
    if len(parts) != 3 or not parts[0] or not parts[1]:
        return (INVALID,)
    h, p, s = (b64u_strict(x) for x in parts)
    if h is None or p is None or s is None or not model_header(h, alg):
        return (INVALID,)
    if not verify_sig(parts[0] + b"." + parts[1], s):
        return (INVALID,)
    return model_claims(p, now, nums)


def check(results, expect, toks, engine):
    for r, e, t in zip(results, expect, toks):
        user = ctypes.string_at(ctypes.addressof(r) + Result.ubuf.offset, r.username_len)  # not r.ubuf: it stops at NUL
        got = (r.status,) if r.status != OK else (OK, r.uid, user, r.username_escape)
        assert got == e, f"engine {engine}: token {t!r}\n  got {got}\n  want {e}"


# ------------------------------------------------------------------------------------------------- generators
NOW = 1_800_000_000
ws = st.sampled_from(["", "", "", " ", "\n", "\t", "\r\n  "])


def jstring(draw, s, escape_p):
    """a JSON string literal for s, escaping random characters (and always the ones JSON requires)"""
    out = ['"']
    for ch in s:
        o = ord(ch)
        must = ch in '"\\' or o < 0x20 or 0xD800 <= o <= 0xDFFF
        if must or draw(st.floats(0, 1)) < escape_p:
            if ch in '"\\' and draw(st.booleans()):
                out.append("\\" + ch)
            elif ch in "\n\t\r\b\f" and draw(st.booleans()):
                out.append({"\n": "\\n", "\t": "\\t", "\r": "\\r", "\b": "\\b", "\f": "\\f"}[ch])
            elif o > 0xFFFF:
                v = o - 0x10000
                out.append("\\u%04x\\u%04X" % (0xD800 + (v >> 10), 0xDC00 + (v & 0x3FF)))
            else:
                out.append(("\\u%04x" if draw(st.booleans()) else "\\u%04X") % o)
        else:
            out.append(ch)
    return "".join(out) + '"'


def jvalue(draw, v, d):
    w = lambda: draw(ws)
    if isinstance(v, tuple) and v and v[0] == "raw":
        return v[1]  # a pre-spelled number
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, str):
        return jstring(draw, v, draw(st.sampled_from([0.0, 0.0, 0.1])))
    if isinstance(v, list):
        return "[" + w() + ("," + w()).join(jvalue(draw, x, d + 1) for x in v) + w() + "]"
    if isinstance(v, dict):
        return (
            "{"
            + w()
            + ("," + w()).join(jstring(draw, k, 0.1) + w() + ":" + w() + jvalue(draw, x, d + 1) for k, x in v.items())
            + w()
            + "}"
        )
    raise TypeError(v)


json_leaf = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(-(10**20), 10**20),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(max_size=12),
)
json_tree = st.recursive(
    json_leaf, lambda c: st.lists(c, max_size=3) | st.dictionaries(st.text(max_size=5), c, max_size=3), max_leaves=8
)


def deep(n):  # n nested levels: [[[...]]] or {"a":{"a":...}}
    v = 0
    for i in range(n):
        v = [v] if i % 2 else {"a": v}
    return v


@st.composite
def number_near(draw, now):
    """an exp / nbf value near now, spelled in any valid JSON way (or not a number)"""
    k = draw(st.sampled_from(["int"] * 8 + ["float", "float", "exp", "exp", "big", "str", "other"]))
    off = draw(st.sampled_from([-2, -1, 0, 1, 2, 3600, -3600, 10**6]))
    if k == "int":
        return now + off
    if k == "float":
        return ("raw", repr(now + off + draw(st.sampled_from([0.5, -0.5, 0.25, 1e-6]))))
    if k == "exp":
        return (
            "raw",
            draw(st.sampled_from(["%de0" % (now + off), "%.9fE+9" % ((now + off) / 1e9), "%d.000" % (now + off)])),
        )
    if k == "big":
        return draw(st.sampled_from([10**30, -(10**30), ("raw", "1e400"), ("raw", "-0"), 0]))
    if k == "str":
        return str(now + off)
    return draw(json_leaf)


@st.composite
def sub_value(draw):
    k = draw(st.sampled_from(["ok"] * 5 + ["zeros", "edge", "notdigits", "nonstr"]))
    if k == "ok":
        return str(draw(st.integers(1, 2**63 - 1)))
    if k == "zeros":
        return "0" * draw(st.integers(1, 40)) + str(draw(st.integers(0, 99)))
    if k == "edge":
        return draw(
            st.sampled_from(["0", "1", str(2**63 - 1), str(2**63), str(2**64), "-1", "+1", " 1", "1.0", "", "١"])
        )
    if k == "notdigits":
        return draw(st.text(max_size=6))
    return draw(json_leaf)


@st.composite
def username_value(draw):
    k = draw(st.sampled_from(["ok"] * 4 + ["long", "long", "special", "special", "nonstr"]))
    if k == "ok":
        return draw(st.text(max_size=20))
    if k == "long":  # straddle the 255-byte limit with 1-4 byte characters
        ch = draw(st.sampled_from(["a", "é", "€", "😀"]))
        n = 255 // len(ch.encode()) + draw(st.integers(-2, 2))
        return ch * max(n, 0)
    if k == "special":
        return draw(st.sampled_from(['"', "\\", "\n", "\x00", "a\x1fb", "\ud800", "\udc00x", "😀", "/"]))
    return draw(json_leaf)


@st.composite
def payload(draw, now):
    """(payload bytes, flags for the model): an object with the claims plus noise, as raw JSON text"""
    pairs = []
    if draw(st.floats(0, 1)) < 0.95:
        pairs.append(("exp", draw(number_near(now + 3600))))
    if draw(st.booleans()):
        pairs.append(("nbf", draw(number_near(now - 2))))
    if draw(st.floats(0, 1)) < 0.95:
        pairs.append(("sub", draw(sub_value())))
    if draw(st.floats(0, 1)) < 0.95:
        pairs.append(("username", draw(username_value())))
    if draw(st.booleans()):
        pairs.append(("iat", now - 10))
    for _ in range(draw(st.integers(0, 3))):
        pairs.append((draw(st.text(max_size=6)), draw(json_tree)))
    if draw(st.floats(0, 1)) < 0.1:
        pairs.append(("x", deep(draw(st.integers(28, 34)))))
    if draw(st.floats(0, 1)) < 0.08 and pairs:
        pairs.append(draw(st.sampled_from(pairs)))  # a duplicate key
    pairs = draw(st.permutations(pairs))
    w = lambda: draw(ws)
    esc_keys = draw(st.floats(0, 1)) < 0.15
    sub_escaped = False
    items = []
    for k, v in pairs:
        ks = jstring(draw, k, 1.0 if esc_keys else 0.0)
        if k == "sub" and isinstance(v, str):
            vs = jstring(draw, v, draw(st.sampled_from([0.0, 0.0, 0.3])))
            sub_escaped = sub_escaped or "\\" in vs
        elif k == "username" and isinstance(v, str):  # the unescaped and the escaped decode paths both get used
            vs = jstring(draw, v, draw(st.sampled_from([0.0, 0.0, 0.0, 0.05, 1.0])))
        else:
            vs = jvalue(draw, v, 1)
        items.append(ks + w() + ":" + w() + vs)
    text = w() + "{" + w() + ("," + w()).join(items) + w() + "}" + w()
    raw = text.encode("utf-8", "surrogatepass")  # lone surrogates only ever appear escaped, so this never fires
    return raw, {"sub_escaped": sub_escaped}


@st.composite
def corrupt_json(draw, raw):
    """sometimes break the JSON at the byte level"""
    k = draw(
        st.sampled_from(["none"] * 40 + ["trailing_comma", "byte", "control", "truncate", "bad_utf8", "nan", "bom"])
    )
    if k == "none" or not raw:
        return raw
    i = draw(st.integers(0, len(raw) - 1))
    if k == "trailing_comma":
        return raw.rstrip()[:-1] + b",}"
    if k == "byte":
        return raw[:i] + bytes([draw(st.integers(0, 255))]) + raw[i + 1 :]
    if k == "control":
        return raw.replace(b'":"', b'":"\x01', 1)
    if k == "truncate":
        return raw[:i]
    if k == "bad_utf8":
        return raw.replace(
            b'":"', b'":"' + draw(st.sampled_from([b"\xc0\xaf", b"\xed\xa0\x80", b"\xf5\x80\x80\x80", b"\xe2\x82"])), 1
        )
    if k == "nan":
        return raw.replace(b'"iat":', b'"iat":NaN,"q":', 1) if b'"iat":' in raw else raw
    return b"\xef\xbb\xbf" + raw


@st.composite
def header(draw, alg):
    k = draw(
        st.sampled_from(
            ["canon"] * 24
            + [
                "reorder",
                "reorder",
                "kid",
                "kid",
                "escaped",
                "kid",
                "escaped",
                "wrong",
                "dup",
                "noalg",
                "notobj",
                "nested",
            ]
        )
    )
    if k == "canon":
        return b'{"alg":"%s","typ":"JWT"}' % alg.encode()
    if k == "reorder":
        return b'{"typ":"JWT", "alg" : "%s"}' % alg.encode()
    if k == "kid":
        return ('{"alg":"%s","kid":%s}' % (alg, json.dumps(draw(st.text(max_size=8))))).encode("utf-8", "surrogatepass")
    if k == "escaped":
        return ('{"\\u0061lg":%s}' % jstring(draw, alg, 0.5)).encode()
    if k == "wrong":
        return b'{"alg":"%s"}' % draw(
            st.sampled_from([b"none", b"HS512", b"hs256", b"HS256 ", b"RS256", b"ES256", b"HS2560"])
        )
    if k == "dup":
        return b'{"alg":"%s","alg":"%s"}' % (alg.encode(), alg.encode())
    if k == "noalg":
        return b'{"typ":"JWT"}'
    if k == "notobj":
        return draw(st.sampled_from([b'["alg"]', b'"HS256"', b"{}", b""]))
    return b'{"alg":"%s","x":%s}' % (alg.encode(), json.dumps(deep(draw(st.integers(30, 33)))).encode())


@st.composite
def corrupt_token(draw, tok):
    k = draw(
        st.sampled_from(["none"] * 50 + ["pad", "extra_dot", "sigchar", "trailbits", "truncate", "space", "empty_seg"])
    )
    if k == "none":
        return tok
    if k == "pad":
        return tok + b"="
    if k == "extra_dot":
        return tok + b"." + b64u(b"x")
    if k == "sigchar":
        i = draw(st.integers(tok.rindex(b".") + 1, len(tok) - 1))
        return tok[:i] + bytes([draw(st.sampled_from(b"AQgw-_+/=.!"))]) + tok[i + 1 :]
    if k == "trailbits":
        return tok[:-1] + bytes([draw(st.sampled_from(b"BCDEFGHIJKLMNOP"))])
    if k == "truncate":
        return tok[: draw(st.integers(0, len(tok)))]
    if k == "space":
        return b" " + tok
    return b"." + tok.split(b".", 1)[1]


# ------------------------------------------------------------------------------------------------- properties
SECRETS = [b"cursed-jwt-test-secret", b"", b"k", b"x" * 64, b"y" * 65, bytes(range(256))]
SET = settings(
    max_examples=NEX, deadline=None, suppress_health_check=list(HealthCheck), phases=[Phase.generate, Phase.shrink]
)


@SET
@given(st.data())
def test_hs256(data):
    draw = data.draw
    secret = draw(st.sampled_from(SECRETS))
    now = NOW + draw(st.integers(-5, 5))
    key = ctypes.create_string_buffer(KEYSZ)
    lib.jwt_key_init(key, secret, ctypes.c_size_t(len(secret)))
    toks, expect = [], []
    for _ in range(draw(st.integers(1, 12))):
        h = draw(header("HS256"))
        p, nums = draw(payload(now))
        p = draw(corrupt_json(p))
        si = b64u(h) + b"." + b64u(p)
        signer = secret if draw(st.floats(0, 1)) < 0.95 else secret + b"!"
        tok = draw(corrupt_token(si + b"." + b64u(hmac.new(signer, si, hashlib.sha256).digest())))
        toks.append(tok)
        expect.append(
            model(
                tok,
                now,
                lambda m, s: len(s) == 32 and hmac.compare_digest(hmac.new(secret, m, hashlib.sha256).digest(), s),
                "HS256",
                nums,
            )
        )
    bufs = [
        ctypes.create_string_buffer(t + b"\0" * 64) for t in toks
    ]  # 64 bytes of slack: JWT_INPUT_PADDED builds read ahead
    ptrs = (ctypes.c_char_p * len(toks))(*[ctypes.cast(b, ctypes.c_char_p) for b in bufs])
    lens = (ctypes.c_int * len(toks))(*[len(t) for t in toks])
    for i, name in ENGINES:
        out = (Result * len(toks))()
        lib.jt_verify(i, key, len(toks), ptrs, lens, ctypes.c_int64(now), out)
        check(out, expect, toks, name)
    stats["hs"] += len(toks)
    for e in expect:
        stats["hs_" + "OIB"[e[0]]] += 1


try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

    HAVE_PK = hasattr(lib, "jwt_verify_batch_pk")
except ImportError:
    HAVE_PK = False

if HAVE_PK:
    N256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    EC_KEYS = [ec.generate_private_key(ec.SECP256R1()) for _ in range(3)]
    RS_KEYS = [rsa.generate_private_key(65537, 2048), rsa.generate_private_key(65537, 3072)]
    ED_KEYS = [ed25519.Ed25519PrivateKey.generate() for _ in range(3)]
    L25519 = 2**252 + 27742317777372353535851937790883648493
    lib.jwt_pkey_ed25519.restype = ctypes.c_void_p

    def ed_ok(pub, m, sig):
        if len(sig) != 64:
            return False
        try:
            pub.verify(sig, m)
            return True
        except InvalidSignature:
            return False

    def es_sign(k, m):
        r, s = decode_dss_signature(k.sign(m, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def es_ok(pub, m, sig):
        if len(sig) != 64:
            return False
        r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
        if not (0 < r < N256 and 0 < s < N256):
            return False
        try:
            pub.verify(encode_dss_signature(r, s), m, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    def rs_ok(pub, m, sig):
        if len(sig) != (pub.key_size + 7) // 8:
            return False
        try:
            pub.verify(sig, m, padding.PKCS1v15(), hashes.SHA256())
            return True
        except (InvalidSignature, ValueError):
            return False

    @st.composite
    def mutate_sig(draw, sig, order):
        """near-valid signatures: bit flips, the other valid s (ECDSA), r or s replaced by 0, n, n-1, n+1"""
        k = draw(st.sampled_from(["none"] * 16 + ["high_s", "high_s", "flip", "edge_r", "edge_s", "zero", "short"]))
        if k == "none":
            return sig
        if k == "flip":
            i = draw(st.integers(0, len(sig) * 8 - 1))
            return sig[: i // 8] + bytes([sig[i // 8] ^ (1 << (i % 8))]) + sig[i // 8 + 1 :]
        if k == "short":
            return sig[:-1]
        if k == "zero":
            return bytes(len(sig))
        if order == "ed":  # S + L, S + 1, R with the sign bit flipped
            if k == "high_s":
                return sig[:32] + (int.from_bytes(sig[32:], "little") + L25519).to_bytes(32, "little")
            if k == "edge_r":
                return sig[:31] + bytes([sig[31] ^ 0x80]) + sig[32:]
            return sig[:32] + ((int.from_bytes(sig[32:], "little") + 1) % 2**256).to_bytes(32, "little")
        if order is None:
            return sig[:-1] + bytes([sig[-1] ^ 1])
        v = draw(st.sampled_from([0, 1, order - 1, order, order + 1, 2**256 - 1]))
        if k == "high_s":
            return sig[:32] + (order - int.from_bytes(sig[32:], "big")).to_bytes(32, "big")
        if k == "edge_r":
            return v.to_bytes(32, "big") + sig[32:]
        return sig[:32] + v.to_bytes(32, "big")

    @SET
    @given(st.data())
    def test_pk(data):
        draw = data.draw
        alg = draw(st.sampled_from(["ES256", "RS256", "EdDSA"]))
        priv = draw(st.sampled_from({"ES256": EC_KEYS, "RS256": RS_KEYS, "EdDSA": ED_KEYS}[alg]))
        pub = priv.public_key()
        if alg == "EdDSA":
            raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            pk = lib.jwt_pkey_ed25519(raw)
            sign, ok, order = (lambda k, m: k.sign(m)), ed_ok, "ed"
        elif alg == "ES256":
            pn = pub.public_numbers()
            pk = lib.jwt_pkey_es256(pn.x.to_bytes(32, "big"), pn.y.to_bytes(32, "big"))
            sign, ok, order = es_sign, es_ok, N256
        else:
            pn = pub.public_numbers()
            nb = pn.n.to_bytes((pn.n.bit_length() + 7) // 8, "big")
            eb = pn.e.to_bytes(3, "big")
            pk = lib.jwt_pkey_rs256(nb, ctypes.c_size_t(len(nb)), eb, ctypes.c_size_t(len(eb)))
            sign, ok, order = (lambda k, m: k.sign(m, padding.PKCS1v15(), hashes.SHA256())), rs_ok, None
        assert pk, "key setup failed"
        try:
            now = NOW
            toks, expect = [], []
            for _ in range(draw(st.integers(1, 10))):
                h = draw(header(alg))
                p, nums = draw(payload(now))
                p = draw(corrupt_json(p))
                si = b64u(h) + b"." + b64u(p)
                sig = draw(mutate_sig(sign(priv, si), order))
                tok = draw(corrupt_token(si + b"." + b64u(sig)))
                toks.append(tok)
                expect.append(model(tok, now, lambda m, s: ok(pub, m, s), alg, nums))
            bufs = [ctypes.create_string_buffer(t + b"\0" * 64) for t in toks]
            ptrs = (ctypes.c_char_p * len(toks))(*[ctypes.cast(b, ctypes.c_char_p) for b in bufs])
            lens = (ctypes.c_int * len(toks))(*[len(t) for t in toks])
            out = (Result * len(toks))()
            lib.jwt_verify_batch_pk(pk, len(toks), ptrs, lens, ctypes.c_int64(now), out)
            check(out, expect, toks, alg)
            stats["pk"] += len(toks)
            for e in expect:
                stats["pk_" + "OIB"[e[0]]] += 1
        finally:
            lib.jwt_pkey_free(pk)


if __name__ == "__main__":
    from collections import Counter

    stats = Counter()
    print(f"engines: {' '.join(n for _, n in ENGINES)}; {NEX} examples per property")
    test_hs256()
    print(
        f"  HS256: {stats['hs']} tokens (OK {stats['hs_O']}, INVALID {stats['hs_I']}, BAD_PAYLOAD {stats['hs_B']}) x {len(ENGINES)} engines"
    )
    if HAVE_PK:
        test_pk()
        print(
            f"  RS256/ES256/EdDSA: {stats['pk']} tokens (OK {stats['pk_O']}, INVALID {stats['pk_I']}, BAD_PAYLOAD {stats['pk_B']})"
        )
    print("OK: every token matched the model")
