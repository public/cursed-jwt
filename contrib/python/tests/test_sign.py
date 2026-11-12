"""Ed25519Signer: every signature must be byte-identical to pyca/cryptography's ``private_key.sign`` (Ed25519 is
deterministic), single and batched, and must verify with pyca and with cursed_crypto's own Ed25519Verifier.
Plus RFC 8032 section 7.1 (secret key -> public key and signature), HMACSHA256.digest as HS256 signing, the
error behaviour of the batch API, and threads."""

import random
import re
import threading

import pytest
from conftest import batches, vector
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ed25519
from hypothesis import given, settings
from hypothesis import strategies as st

import cursed_crypto


def key(seed):
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


def test_rfc8032():
    text = open(vector("rfc8032.txt")).read()
    text = "\n".join(l for l in text.split("\n") if not re.match(r"^(Josefsson & Liusvaara|RFC 8032  )", l))
    sec = text[text.rindex("\n7.1.  Test Vectors for Ed25519") : text.rindex("\n7.2.  Test Vectors for Ed25519ctx")]
    n = 0
    for blk in sec.replace("\f", "").split("-----TEST ")[1:]:
        fields, cur = {}, None
        for l in blk.split("\n")[1:]:
            t = l.strip()
            if t.endswith(":"):
                cur = t.split(" (")[0].rstrip(":")
                fields[cur] = ""
            elif cur and re.fullmatch(r"[0-9a-f]+", t):
                fields[cur] += t
            elif t:
                cur = None
        sk, pk, msg, sig = (bytes.fromhex(fields[k]) for k in ("SECRET KEY", "PUBLIC KEY", "MESSAGE", "SIGNATURE"))
        s = cursed_crypto.Ed25519Signer(key(sk))
        assert s._k is not None and s._k.public_bytes() == pk
        assert s.sign(msg) == sig and s.sign_batch([msg, msg]) == [sig, sig]
        n += 1
    assert n == 5


def test_random_keys_equal_pyca():
    rng = random.Random(8032)
    for i in range(60):
        sk = key(rng.randbytes(32))
        s = cursed_crypto.Ed25519Signer(sk)
        msgs = [rng.randbytes(rng.choice([0, 1, 31, 32, 64, 111, 112, 127, 128, 129, 300, 2000])) for _ in range(40)]
        ref = [sk.sign(m) for m in msgs]
        assert [s.sign(m) for m in msgs] == ref
        assert s.sign_batch(msgs) == ref
        for b in batches(len(msgs), rng):
            assert s.sign_batch([msgs[j] for j in b]) == [ref[j] for j in b]
        v = cursed_crypto.Ed25519Verifier(sk.public_key())
        assert v.verify_batch(ref, msgs) == [True] * len(msgs)
        sk.public_key().verify(ref[0], msgs[0])


@settings(max_examples=200, deadline=None)
@given(st.binary(min_size=32, max_size=32), st.lists(st.binary(max_size=300), max_size=40))
def test_property(seed, msgs):
    sk = key(seed)
    assert cursed_crypto.Ed25519Signer(sk).sign_batch(msgs) == [sk.sign(m) for m in msgs]


def test_buffers_and_errors():
    sk = key(bytes(range(32)))
    s = cursed_crypto.Ed25519Signer(sk)
    m = b"bytes-like inputs"
    want = sk.sign(m)
    assert s.sign(bytearray(m)) == want and s.sign(memoryview(m)) == want
    assert s.sign_batch(iter([m, bytearray(m)])) == [want, want]  # an iterator, not only a list
    assert s.sign_batch([]) == []
    with pytest.raises(TypeError):
        s.sign("text")
    with pytest.raises(TypeError):
        s.sign_batch([m, "text"])
    with pytest.raises(TypeError):
        cursed_crypto.Ed25519Signer(sk.public_key())
    assert s.public_key().public_bytes_raw() == sk.public_key().public_bytes_raw()


def test_subclass_keeps_its_own_sign():
    class Mine(ed25519.Ed25519PrivateKey):
        def __init__(self, inner):
            self.inner = inner

        def sign(self, data):
            return self.inner.sign(data)

        def public_key(self):
            return self.inner.public_key()

        def private_bytes(self, *a, **k):
            raise NotImplementedError

        def private_bytes_raw(self):
            raise AssertionError("must not be read")

        def __copy__(self):
            return self

        def __deepcopy__(self, memo):
            return self

    inner = key(b"\x07" * 32)
    s = cursed_crypto.Ed25519Signer(Mine(inner))
    assert s._k is None
    assert s.sign_batch([b"a", b"b"]) == [inner.sign(b"a"), inner.sign(b"b")]
    with pytest.raises(TypeError):
        s.sign_batch([b"a", 3])


def test_threads():
    sk = key(b"\x2a" * 32)
    s = cursed_crypto.Ed25519Signer(sk)
    msgs = [bytes([i]) * i for i in range(64)]
    ref = [sk.sign(m) for m in msgs]
    bad = []

    def work():
        for _ in range(5):
            if s.sign_batch(msgs) != ref or s.sign(msgs[7]) != ref[7]:
                bad.append(1)

    ts = [threading.Thread(target=work) for _ in range(4)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not bad


def test_hs256_signing_is_digest():
    # HS256 signing is the MAC of the signing input: digest / digest_batch, equal to pyca's HMAC
    rng = random.Random(7515)
    for kl in (0, 1, 32, 64, 65, 100):
        k = rng.randbytes(kl)
        h = cursed_crypto.HMACSHA256(k)
        msgs = [rng.randbytes(rng.randrange(0, 400)) for _ in range(33)]
        ref = []
        for m in msgs:
            p = hmac.HMAC(k, hashes.SHA256())
            p.update(m)
            ref.append(p.finalize())
        assert h.digest_batch(msgs) == ref and [h.digest(m) for m in msgs] == ref
        h.verify(msgs[0], ref[0])
        with pytest.raises(InvalidSignature):
            h.verify(msgs[0], bytes(32))
