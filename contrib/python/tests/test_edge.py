"""Edge cases where implementations disagree: malformed DER, high-s ECDSA, Ed25519 small-order / non-canonical /
mixed-order points and S >= L.  Whatever pyca/cryptography decides is the expected verdict."""

import os
import random

import pytest
from conftest import check, pyca_ok
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

import cursed_crypto
import ed25519_ref as ref

N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
SHA = ec.ECDSA(hashes.SHA256())


# ---------------------------------------------------------------------------------- DER
def der_len(n):
    return (
        bytes([n])
        if n < 0x80
        else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    )


def der_int_bytes(v, pad=0, longform=False):
    """INTEGER v (two's complement, minimal) with pad extra leading 00s, optionally a long-form length."""
    if v >= 0:
        b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big")
    else:
        n = 1
        while not -(1 << (8 * n - 1)) <= v:
            n += 1
        b = (v % (1 << (8 * n))).to_bytes(n, "big")
    b = b"\0" * pad + b
    ln = bytes([0x81, len(b)]) if longform else der_len(len(b))
    return b"\x02" + ln + b


def seq(body, longform=False, delta=0):
    ln = len(body) + delta
    return b"\x30" + (bytes([0x81, ln]) if longform else der_len(ln)) + body


def der_variants(r, s):
    """(label, bytes) mutations of the DER signature of (r, s)."""
    ri, si = der_int_bytes(r), der_int_bytes(s)
    good = seq(ri + si)
    assert good == encode_dss_signature(r, s)
    out = [
        ("canonical", good),
        ("high-s", encode_dss_signature(r, N - s)),
        ("r pad 00", seq(der_int_bytes(r, 1) + si)),
        ("s pad 00", seq(ri + der_int_bytes(s, 1))),
        ("r pad 0000", seq(der_int_bytes(r, 2) + si)),
        ("r negative", seq(der_int_bytes(-r) + si)),
        ("s negative", seq(ri + der_int_bytes(-s))),
        ("r = r - 2^256 (negative)", seq(der_int_bytes(r - (1 << 256)) + si)),
        ("r long-form length", seq(der_int_bytes(r, longform=True) + si)),
        ("s long-form length", seq(ri + der_int_bytes(s, longform=True))),
        ("seq long-form length", seq(ri + si, longform=True)),
        ("seq 82 length", b"\x30\x82" + len(ri + si).to_bytes(2, "big") + ri + si),
        ("seq indefinite", b"\x30\x80" + ri + si + b"\0\0"),
        ("seq length +1", seq(ri + si, delta=1)),
        ("seq length -1", seq(ri + si, delta=-1)),
        ("seq length +1, extra byte", seq(ri + si + b"\0", delta=0)),
        ("trailing 00", good + b"\0"),
        ("trailing 05 00", good + b"\x05\x00"),
        ("trailing copy", good + good),
        ("extra INTEGER", seq(ri + si + der_int_bytes(0))),
        ("only r", seq(ri)),
        ("r, s swapped", seq(si + ri)),
        ("empty INTEGER r", seq(b"\x02\x00" + si)),
        ("SET tag", b"\x31" + good[1:]),
        ("BIT STRING tag r", seq(b"\x03" + ri[1:] + si)),
        ("constructed tag", seq(b"\x22" + ri[1:] + si)),
        ("r + n", seq(der_int_bytes(r + N) + si)),
        ("s + n", seq(ri + der_int_bytes(s + N))),
        ("r + 2^256", seq(der_int_bytes(r + (1 << 256)) + si)),
        ("r = 0", seq(der_int_bytes(0) + si)),
        ("s = 0", seq(ri + der_int_bytes(0))),
        ("r = n", seq(der_int_bytes(N) + si)),
        ("s = n", seq(ri + der_int_bytes(N))),
        ("s = n - 1", seq(ri + der_int_bytes(N - 1))),
        ("r = 1", seq(der_int_bytes(1) + si)),
        ("empty", b""),
        ("30 00", b"\x30\x00"),
        ("raw r || s", r.to_bytes(32, "big") + s.to_bytes(32, "big")),
    ]
    # missing leading zero: where r's top bit is set, drop its 00 (making it negative)
    if r >> 255:
        out.append(("r missing 00", seq(b"\x02\x20" + r.to_bytes(32, "big") + si)))
    if s >> 255:
        out.append(("s missing 00", seq(ri + b"\x02\x20" + s.to_bytes(32, "big"))))
    # INTEGER length off by one in either direction
    for d in (-1, 1):
        out.append((f"r length {d:+}", seq(bytes([2, ri[1] + d]) + ri[2:] + si)))
        out.append((f"s length {d:+}", seq(ri + bytes([2, si[1] + d]) + si[2:])))
    # every truncation
    for k in range(len(good)):
        out.append((f"truncated to {k}", good[:k]))
    return out


def der_ref(d):
    """What a strict DER reader makes of d: r || s if d is the canonical DER of two integers in [0, 2^256)."""
    try:
        r, s = decode_dss_signature(d)
    except ValueError:
        return None
    if encode_dss_signature(r, s) != d or not (0 <= r < 1 << 256 and 0 <= s < 1 << 256):
        return None
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


@pytest.fixture(scope="module")
def p256():
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, cursed_crypto.ECDSAVerifier(priv.public_key(), SHA)


def test_der_variants(p256):
    priv, v = p256
    pub, rng = priv.public_key(), random.Random(5)
    items, labels = [], []
    # many signatures, so that short (leading-zero) r and s and top-bit-set r and s all occur
    for i in range(600):
        msg = os.urandom(rng.randrange(0, 100))
        r, s = decode_dss_signature(priv.sign(msg, SHA))
        variants = der_variants(r, s) if i < 40 or r < 1 << 248 or s < 1 << 248 else der_variants(r, s)[:6]
        for label, d in variants:
            items.append((d, msg))
            labels.append(label)
            # the parser itself against a strict DER reader (pyca's asn1)
            assert cursed_crypto._native.der_to_raw(d) == der_ref(d), (label, d.hex())
    want = [pyca_ok(pub.verify, d, m, SHA) for d, m in items]
    assert sum(want) > 600  # the canonical and high-s ones
    for i, (d, m) in enumerate(items):
        assert pyca_ok(v.verify, d, m) == want[i], (labels[i], d.hex())
    check(v, items, want, rng, rounds=1, label="der")


def test_der_random_bytes(p256):
    """Random bytes and random byte-level corruptions of valid signatures."""
    priv, v = p256
    pub, rng = priv.public_key(), random.Random(9)
    items = []
    for _ in range(3000):
        msg = bytes([rng.randrange(256)]) * rng.randrange(3)
        d = bytearray(priv.sign(msg, SHA)) if rng.random() < 0.8 else bytearray(os.urandom(rng.randrange(80)))
        for _ in range(rng.randrange(1, 3)):
            op = rng.randrange(4)
            if op == 0 and d:
                d[rng.randrange(len(d))] ^= 1 << rng.randrange(8)
            elif op == 1 and d:
                del d[rng.randrange(len(d))]
            elif op == 2:
                d.insert(rng.randrange(len(d) + 1), rng.choice((0, 0x80, 0xFF, rng.randrange(256))))
            elif op == 3 and len(d) > 1:
                d[1] = rng.randrange(256)
        items.append((bytes(d), msg))
    want = [pyca_ok(pub.verify, d, m, SHA) for d, m in items]
    check(v, items, want, rng, rounds=1, label="der-random")


def test_raw_format_matches_der(p256):
    priv, _ = p256
    pub = priv.public_key()
    v = cursed_crypto.ECDSAVerifier(pub, SHA, signature_format="raw")
    items, want = [], []
    for i in range(200):
        msg = os.urandom(i % 70)
        r, s = decode_dss_signature(priv.sign(msg, SHA))
        for rr, ss in (
            (r, s),
            (r, N - s),
            (r + 1, s),
            (0, s),
            (r, 0),
            (N, s),
            (r, N),
            (r, s + N if s + N < 1 << 256 else s),
        ):
            items.append((rr.to_bytes(32, "big") + ss.to_bytes(32, "big"), msg))
            want.append(pyca_ok(pub.verify, encode_dss_signature(rr, ss), msg, SHA))
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        for bad in (raw[:63], raw + b"\0", b"\0" + raw, b""):
            items.append((bad, msg))
            want.append(False)
    check(v, items, want, label="raw")


# ---------------------------------------------------------------------------------- Ed25519
def ed_keys():
    """(label, 32-byte encoding, secret scalar or None) for small-order, non-canonical and mixed-order keys."""
    out = []
    small = ref.small_order_points()
    for i, p in enumerate(small):
        out.append((f"small-order {i}", ref.encode(p), None))
        if p[1] + ref.P < 1 << 255:
            out.append((f"small-order {i} non-canonical y", ref.encode(p, y_add=ref.P), None))
        if p[0] == 0:
            out.append((f"small-order {i} x=0 sign 1", ref.encode(p, sign_flip=True), None))
    for y in range(2, 19):  # y + p for small y: non-canonical encodings of ordinary points
        x = ref.recover_x(y, 0)
        if x is not None:
            out.append((f"y={y} non-canonical", ref.encode((x, y), y_add=ref.P), None))
    a = 0x1234567 * 8
    A = ref.mul(a, ref.B)
    out.append(("ordinary", ref.encode(A), a))
    for i, t in enumerate(small[1:]):
        out.append((f"mixed-order +T{i}", ref.encode(ref.add(A, t)), a))
    out.append(("not a point", None, None))
    return out


def ed_items(enc, a, rng):
    msgs = [b"", b"m", os.urandom(40)]
    small = ref.small_order_points()
    items = []
    for m in msgs:
        for i, t in enumerate(small):  # R small order, S = 0 and S = 1
            for S in (0, 1, ref.L, ref.L + 1, 2**253):
                items.append((ref.encode(t) + S.to_bytes(32, "little"), m))
            if t[1] + ref.P < 1 << 255:
                items.append((ref.encode(t, y_add=ref.P) + bytes(32), m))
        if a is not None:
            sig, _ = ref.sign_with(a, enc, m, r=rng.randrange(1, ref.L))
            S = int.from_bytes(sig[32:], "little")
            items += [
                (sig, m),
                (sig[:32] + (S + ref.L).to_bytes(32, "little"), m),  # S + L: non-canonical S
                (sig[:32] + (S + 8 * ref.L).to_bytes(32, "little"), m) if S + 8 * ref.L < 1 << 256 else (sig, m),
            ]
            R = ref.decode(sig[:32])
            if R[1] + ref.P < 1 << 255:
                items.append((ref.encode(R, y_add=ref.P) + sig[32:], m))  # non-canonical R
            for t in small[1:]:  # R with torsion added
                items.append((ref.encode(ref.add(R, t)) + sig[32:], m))
    return items


def test_ed25519_edge_matrix():
    rng = random.Random(3)
    keys = ed_keys()
    while len(keys) < 60:  # pad with a few more mixed-order keys under fresh scalars
        a = rng.randrange(1, ref.L) * 8
        A = ref.mul(a, ref.B)
        t = ref.small_order_points()[rng.randrange(1, 8)]
        keys.append((f"mixed-order random {len(keys)}", ref.encode(ref.add(A, t)), a))
    for label, enc, a in keys:
        if enc is None:  # a y with no x: find one
            y = 2
            while ref.recover_x(y, 0) is not None:
                y += 1
            enc = y.to_bytes(32, "little")
        try:
            pub = ed25519.Ed25519PublicKey.from_public_bytes(enc)
        except ValueError:
            continue  # pyca refuses the key itself: nothing to compare
        v = cursed_crypto.Ed25519Verifier(pub)
        items = ed_items(enc, a, rng)
        want = [pyca_ok(pub.verify, s, m) for s, m in items]
        check(v, items, want, rng, rounds=1, label=label)


def test_ed25519_random_s_plus_l():
    rng = random.Random(4)
    for _ in range(10):
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()
        v = cursed_crypto.Ed25519Verifier(pub)
        items = []
        for i in range(20):
            m = os.urandom(i * 7)
            sig = priv.sign(m)
            S = int.from_bytes(sig[32:], "little")
            items += [(sig, m), (sig[:32] + (S + ref.L).to_bytes(32, "little"), m)]
            if S + 2 * ref.L < 1 << 256:
                items.append((sig[:32] + (S + 2 * ref.L).to_bytes(32, "little"), m))
        want = [pyca_ok(pub.verify, s, m) for s, m in items]
        assert want[0::1].count(True) >= 20
        check(v, items, want, rng, rounds=1, label="S+L")
