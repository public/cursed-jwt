"""pyca-generated keys and signatures, corrupted ones, batch sizes 1..33 with invalid items in random lanes, the
delegation path (parameters cursed-crypto doesn't handle), input types and errors, and threads."""

import os
import random
import threading

import pytest
from conftest import check, pyca_ok
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils

import cursed_crypto

SHA = ec.ECDSA(hashes.SHA256())
LENS = [0, 1, 31, 32, 55, 56, 63, 64, 65, 119, 120, 570, 1000, 4097]


def corrupt(sig, rng):
    """A random corruption of sig: bit flip, truncation, extension, empty, zeros."""
    op = rng.randrange(6)
    b = bytearray(sig)
    if op == 0 and b:
        b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
    elif op == 1:
        b = b[: rng.randrange(len(b))] if b else b
    elif op == 2:
        b += b"\0"
    elif op == 3:
        b = b"\0" + b
    elif op == 4:
        b = bytearray(len(b))
    else:
        b = bytearray()
    return bytes(b)


class Alg:
    """One key: sign(msg) with pyca, pyca's own verdict, and our verifier."""

    def __init__(self, name, priv, verifier, sign, verify):
        self.name, self.priv, self.v, self.sign, self.pyca = name, priv, verifier, sign, verify


def make(name):
    if name == "ed25519":
        p = ed25519.Ed25519PrivateKey.generate()
        return Alg(name, p, cursed_crypto.Ed25519Verifier(p.public_key()), p.sign, p.public_key().verify)
    if name == "es256":
        p = ec.generate_private_key(ec.SECP256R1())
        pub = p.public_key()
        return Alg(
            name, p, cursed_crypto.ECDSAVerifier(pub, SHA), lambda m: p.sign(m, SHA), lambda s, m: pub.verify(s, m, SHA)
        )
    if name.startswith("rs256"):
        bits = int(name[5:] or 2048)
        p = rsa.generate_private_key(65537, bits)
        pub = p.public_key()
        pk = (padding.PKCS1v15(), hashes.SHA256())
        return Alg(
            name, p, cursed_crypto.RSAVerifier(pub, *pk), lambda m: p.sign(m, *pk), lambda s, m: pub.verify(s, m, *pk)
        )
    if name == "hs256":
        key = os.urandom(32)

        def mac(m):
            h = hmac.HMAC(key, hashes.SHA256())
            h.update(m)
            return h.finalize()

        def ver(t, m):
            h = hmac.HMAC(key, hashes.SHA256())
            h.update(m)
            h.verify(t)

        # HMACSHA256 takes (data, tag): wrap it to (sig, data) like the others
        hv = cursed_crypto.HMACSHA256(key)

        class Swap:
            def verify(self, t, m):
                return hv.verify(m, t)

            def verify_batch(self, ts, ms):
                return hv.verify_batch(ms, ts)

        return Alg(name, key, Swap(), mac, ver)
    raise ValueError(name)


ALGS = ["ed25519", "es256", "rs256", "rs2563072", "rs2564096", "hs256"]


@pytest.fixture(scope="module", params=ALGS)
def alg(request):
    a = make(request.param)
    if request.param != "hs256":
        assert a.v._k is not None, "must take the native path"
    return a


def test_lanes(alg):
    """Every batch size 1..33, invalid items in random lanes, against pyca's single verify."""
    rng = random.Random(hash(alg.name) & 0xFFFF)
    for n in range(1, 34):
        items = []
        for _ in range(n):
            m = os.urandom(rng.choice(LENS))
            s = alg.sign(m)
            kind = rng.randrange(4)
            if kind == 1:
                s = corrupt(s, rng)
            elif kind == 2:
                m = m + b"x"
            items.append((s, m))
        want = [pyca_ok(alg.pyca, s, m) for s, m in items]
        check(alg.v, items, want, rng, rounds=2, label=f"{alg.name} n={n}")


def test_cross_key(alg):
    """Signatures under another key of the same kind are invalid."""
    other = make(alg.name)
    items = [(other.sign(m), m) for m in (b"", b"abc", os.urandom(570))]
    want = [pyca_ok(alg.pyca, s, m) for s, m in items]
    assert want == [False] * 3
    check(alg.v, items, want)


def test_high_s():
    a = make("es256")
    n = ec.SECP256R1().key_size and 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    items = []
    for i in range(50):
        m = os.urandom(i)
        r, s = utils.decode_dss_signature(a.sign(m))
        items += [(utils.encode_dss_signature(r, s), m), (utils.encode_dss_signature(r, n - s), m)]
    want = [pyca_ok(a.pyca, s, m) for s, m in items]
    assert all(want), "OpenSSL accepts high-s"
    check(a.v, items, want)


def test_rsa_signature_values():
    a = make("rs256")
    nn = a.priv.public_key().public_numbers().n
    k = (nn.bit_length() + 7) // 8
    m = b"hello"
    s = int.from_bytes(a.sign(m), "big")
    sigs = [
        a.sign(m),
        (s + nn).to_bytes(k + 1, "big")[-k:] if s + nn < 1 << (8 * k) else a.sign(m),
        nn.to_bytes(k, "big"),
        (nn - 1).to_bytes(k, "big"),
        bytes(k),
        (1).to_bytes(k, "big"),
        s.to_bytes(k, "big")[1:],  # one byte short
        b"\0" + s.to_bytes(k, "big"),  # one byte long
    ]
    items = [(x, m) for x in sigs]
    want = [pyca_ok(a.pyca, x, m) for x, m in items]
    assert want[0]
    check(a.v, items, want)


def rsa_key(bits, e=65537):
    """An RSA key with modulus of exactly `bits` bits and public exponent e (pyca generates only e = 3 / 65537)."""
    while True:
        p = rsa.generate_private_key(65537, bits)
        pn = p.private_numbers()
        lam = (pn.p - 1) * (pn.q - 1)
        try:
            d = pow(e, -1, lam)
        except ValueError:
            continue
        pub = rsa.RSAPublicNumbers(e, pn.public_numbers.n)
        priv = rsa.RSAPrivateNumbers(
            pn.p, pn.q, d, d % (pn.p - 1), d % (pn.q - 1), pow(pn.q, -1, pn.p), pub
        ).private_key()
        return priv


@pytest.mark.parametrize(
    "bits,e,native",
    [
        (2048, 3, True),
        (2048, 65537, True),
        (2048, 2**61 - 1, True),
        (2048, 2**64 + 13, False),  # cursed-crypto takes e < 2^64
        (2047, 65537, False),  # below 2048 bits: pyca
        (2049, 65537, True),
        (4095, 65537, True),
        (4096, 65537, True),
        (1024, 65537, False),
    ],
)
def test_rsa_key_shapes(bits, e, native):
    priv = rsa_key(bits, e)
    pub = priv.public_key()
    pk = (padding.PKCS1v15(), hashes.SHA256())
    v = cursed_crypto.RSAVerifier(pub, *pk)
    assert (v._k is not None) == native, (bits, e)
    rng = random.Random(bits)
    items = []
    for i in range(12):
        m = os.urandom(i * 11)
        s = priv.sign(m, *pk)
        items.append((s if i % 3 else corrupt(s, rng), m))
    want = [pyca_ok(pub.verify, s, m, *pk) for s, m in items]
    check(v, items, want, rng, label=f"rsa {bits} e={e}")


# ---------------------------------------------------------------------------------- delegation
def delegated_cases():
    out = []
    p384 = ec.generate_private_key(ec.SECP384R1())
    p256 = ec.generate_private_key(ec.SECP256R1())
    for priv, alg in [
        (p384, ec.ECDSA(hashes.SHA384())),
        (p384, ec.ECDSA(hashes.SHA256())),
        (p256, ec.ECDSA(hashes.SHA384())),
        (p256, ec.ECDSA(hashes.SHA512())),
    ]:
        out.append(("ecdsa", priv, alg, None))
    r = rsa.generate_private_key(65537, 2048)
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
    out.append(("rsa", r, pss, hashes.SHA256()))
    out.append(("rsa", r, padding.PKCS1v15(), hashes.SHA512()))
    out.append(("rsa", r, padding.PKCS1v15(), hashes.SHA1()))
    return out


@pytest.mark.parametrize("case", range(7))
def test_delegated(case):
    kind, priv, a1, a2 = delegated_cases()[case]
    pub = priv.public_key()
    rng = random.Random(case)
    if kind == "ecdsa":
        v = cursed_crypto.ECDSAVerifier(pub, a1)
        sign, ver = (lambda m: priv.sign(m, a1)), (lambda s, m: pub.verify(s, m, a1))
    else:
        v = cursed_crypto.RSAVerifier(pub, a1, a2)
        sign, ver = (lambda m: priv.sign(m, a1, a2)), (lambda s, m: pub.verify(s, m, a1, a2))
    assert v._k is None
    items = []
    for i in range(20):
        m = os.urandom(i * 5)
        s = sign(m)
        items.append((s if rng.random() < 0.6 else corrupt(s, rng), m))
    want = [pyca_ok(ver, s, m) for s, m in items]
    check(v, items, want, rng, rounds=1, label=f"delegated {case}")


def test_delegated_raw_p384():
    priv = ec.generate_private_key(ec.SECP384R1())
    pub, alg = priv.public_key(), ec.ECDSA(hashes.SHA384())
    v = cursed_crypto.ECDSAVerifier(pub, alg, signature_format="raw")
    assert v._k is None
    items, want = [], []
    for i in range(10):
        m = os.urandom(i)
        r, s = utils.decode_dss_signature(priv.sign(m, alg))
        raw = r.to_bytes(48, "big") + s.to_bytes(48, "big")
        items += [(raw, m), (raw[:-1], m), (raw, m + b"!")]
        want += [True, False, False]
    check(v, items, want)


def test_prehashed_delegated():
    priv = ec.generate_private_key(ec.SECP256R1())
    alg = ec.ECDSA(utils.Prehashed(hashes.SHA256()))
    v = cursed_crypto.ECDSAVerifier(priv.public_key(), alg)
    assert v._k is None
    dg = hashes.Hash(hashes.SHA256())
    dg.update(b"x")
    d = dg.finalize()
    check(v, [(priv.sign(d, alg), d), (priv.sign(d, alg), d[::-1])], [True, False])


@pytest.mark.parametrize("klen", [0, 1, 31, 32, 63, 64, 65, 200])
def test_hmac_keys_and_tags(klen):
    rng = random.Random(klen)
    key = os.urandom(klen)
    h = cursed_crypto.HMACSHA256(key)

    def ref(m):
        x = hmac.HMAC(key, hashes.SHA256())
        x.update(m)
        return x.finalize()

    items = []
    for ln in LENS:
        m = os.urandom(ln)
        t = ref(m)
        assert h.digest(m) == t
        items += [(m, t), (m, t[:16]), (m, t[:31]), (m, t + b"\0"), (m, b""), (m, corrupt(t, rng))]
    for n in range(1, 34):
        items.append((os.urandom(n), ref(os.urandom(1))))
    want = []
    for m, t in items:
        x = hmac.HMAC(key, hashes.SHA256())
        x.update(m)
        want.append(pyca_ok(x.verify, t))
    check(h, items, want, rng, label=f"hmac key {klen}")
    ms = [m for m, _ in items]
    assert h.digest_batch(ms) == [ref(m) for m in ms]


def test_sha256_batch():
    import hashlib

    for n in (0, 1, 2, 7, 16, 33, 300):
        ms = [os.urandom(random.randrange(2000)) for _ in range(n)]
        assert cursed_crypto.sha256_batch(ms) == [hashlib.sha256(m).digest() for m in ms]


# ---------------------------------------------------------------------------------- types and errors
def test_buffer_types():
    a = make("ed25519")
    m = os.urandom(100)
    s = a.sign(m)
    big = bytearray(b"pad" + m + b"pad")
    for sig in (s, bytearray(s), memoryview(s), memoryview(bytearray(b"..." + s))[3:]):
        for msg in (m, bytearray(m), memoryview(m), memoryview(big)[3:-3]):
            a.v.verify(sig, msg)
            assert a.v.verify_batch([sig], [msg]) == [True]
            assert a.v.verify_batch((sig,), iter([msg])) == [True]
            assert a.v.verify_batch((x for x in [sig, b"bad"]), [msg, msg]) == [True, False]


def test_errors_match_pyca():
    a = make("es256")
    pub = a.priv.public_key()
    m = b"msg"
    s = a.sign(m)
    for bad in ("str", 5, None, [1, 2]):
        with pytest.raises(TypeError):
            pub.verify(bad, m, SHA)
        with pytest.raises(TypeError):
            a.v.verify(bad, m)
        with pytest.raises(TypeError):
            a.v.verify_batch([s, bad], [m, m])
        with pytest.raises(TypeError):
            a.v.verify_batch([s, s], [m, bad])
    with pytest.raises(ValueError):
        a.v.verify_batch([s, s], [m])
    with pytest.raises(InvalidSignature):
        a.v.verify(s, m + b"x")
    assert a.v.verify_batch([], []) == []
    # InvalidSignature is pyca's own class
    assert cursed_crypto.InvalidSignature is InvalidSignature
    nc = memoryview(bytes(range(64)))[::2]  # non-contiguous
    for exc_pyca in (None,):
        try:
            pub.verify(nc, m, SHA)
        except Exception as e:  # pyca's error type for a non-contiguous buffer
            exc_pyca = type(e)
        assert exc_pyca is not None
        with pytest.raises((exc_pyca, BufferError, TypeError)):
            a.v.verify_batch([nc], [m])


def test_hmac_errors():
    with pytest.raises(TypeError):
        hmac.HMAC("str", hashes.SHA256())
    for bad in ("str", 5, [1, 2], None):  # bytes(5) would be five zero bytes: must raise as pyca does
        with pytest.raises(TypeError):
            hmac.HMAC(bad, hashes.SHA256())
        with pytest.raises(TypeError):
            cursed_crypto.HMACSHA256(bad)
    k = bytearray(b"key")
    h = cursed_crypto.HMACSHA256(memoryview(k))
    k[0] = 0  # pyca copies the key at construction; so does HMACSHA256
    assert h.digest(b"m") == cursed_crypto.HMACSHA256(b"key").digest(b"m")
    h = cursed_crypto.HMACSHA256(b"k")
    with pytest.raises(TypeError):
        h.verify_batch([b"a", "b"], [b"x" * 32, b"x" * 32])
    with pytest.raises(ValueError):
        h.verify_batch([b"a"], [])
    with pytest.raises(InvalidSignature):
        h.verify(b"a", b"x" * 32)


def test_custom_subclass_is_delegated():
    class MyKey(ed25519.Ed25519PublicKey):
        def __init__(self, inner):
            self.inner = inner

        def public_bytes(self, *a):
            return self.inner.public_bytes(*a)

        def public_bytes_raw(self):
            return self.inner.public_bytes_raw()

        def verify(self, signature, data):
            return None  # accepts everything: its verify is what counts

        def __eq__(self, other):
            return self is other

        def __copy__(self):
            return self

        def __deepcopy__(self, memo):
            return self

    k = MyKey(ed25519.Ed25519PrivateKey.generate().public_key())
    v = cursed_crypto.Ed25519Verifier(k)
    assert v._k is None
    assert v.verify_batch([b"x"], [b"y"]) == [True]


def test_threads():
    a = make("es256")
    items = [(a.sign(m), m) for m in (os.urandom(i) for i in range(64))]
    items[5] = (items[6][0], items[5][1])
    want = [pyca_ok(a.pyca, s, m) for s, m in items]
    errs = []

    def run():
        for _ in range(20):
            if a.v.verify_batch([s for s, _ in items], [m for _, m in items]) != want:
                errs.append(1)

    ts = [threading.Thread(target=run) for _ in range(4)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errs
