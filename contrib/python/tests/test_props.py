"""Hypothesis properties: for any list of items (messages of any length, signatures or tags valid, corrupted at any
byte, truncated, extended, or arbitrary bytes), verify_batch equals pyca's per-item verdicts, and so does verify.
HYPOTHESIS_EXAMPLES (default 200) examples per property."""

import os

from conftest import pyca_ok
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from hypothesis import HealthCheck, given, settings, strategies as st

import cursed_crypto

EX = int(os.environ.get("HYPOTHESIS_EXAMPLES", "200"))
CFG = settings(max_examples=EX, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
SHA = ec.ECDSA(hashes.SHA256())

ED = ed25519.Ed25519PrivateKey.generate()
ES = ec.generate_private_key(ec.SECP256R1())
RS = rsa.generate_private_key(65537, 2048)
PK = (padding.PKCS1v15(), hashes.SHA256())
HK = os.urandom(48)
KEYS = {
    "ed": (ED.sign, ED.public_key().verify, cursed_crypto.Ed25519Verifier(ED.public_key())),
    "es": (
        lambda m: ES.sign(m, SHA),
        lambda s, m: ES.public_key().verify(s, m, SHA),
        cursed_crypto.ECDSAVerifier(ES.public_key(), SHA),
    ),
    "rs": (
        lambda m: RS.sign(m, *PK),
        lambda s, m: RS.public_key().verify(s, m, *PK),
        cursed_crypto.RSAVerifier(RS.public_key(), *PK),
    ),
}


def hmac_tag(m):
    h = hmac.HMAC(HK, hashes.SHA256())
    h.update(m)
    return h.finalize()


def hmac_ok(t, m):
    h = hmac.HMAC(HK, hashes.SHA256())
    h.update(m)
    h.verify(t)


KEYS["hs"] = (hmac_tag, hmac_ok, None)
HV = cursed_crypto.HMACSHA256(HK)

mutation = st.one_of(
    st.just(("keep",)),
    st.tuples(st.just("flip"), st.integers(0, 600), st.integers(0, 7)),
    st.tuples(st.just("cut"), st.integers(0, 600)),
    st.tuples(st.just("append"), st.binary(min_size=1, max_size=3)),
    st.tuples(st.just("prepend"), st.binary(min_size=1, max_size=3)),
    st.tuples(st.just("replace"), st.binary(max_size=80)),
    st.tuples(st.just("msg"), st.binary(max_size=3)),
)
item = st.tuples(st.binary(max_size=700), mutation)


def apply(sig, msg, mu):
    k = mu[0]
    if k == "flip" and sig:
        b = bytearray(sig)
        b[mu[1] % len(b)] ^= 1 << mu[2]
        return bytes(b), msg
    if k == "cut":
        return sig[: mu[1] % (len(sig) + 1)], msg
    if k == "append":
        return sig + mu[1], msg
    if k == "prepend":
        return mu[1] + sig, msg
    if k == "replace":
        return mu[1], msg
    if k == "msg":
        return sig, msg + mu[1]
    return sig, msg


@CFG
@given(alg=st.sampled_from(sorted(KEYS)), items=st.lists(item, min_size=0, max_size=40))
def test_batch_equals_pyca(alg, items):
    sign, ver, v = KEYS[alg]
    pairs = [apply(sign(m), m, mu) for m, mu in items]
    want = [pyca_ok(ver, s, m) for s, m in pairs]
    if alg == "hs":
        assert HV.verify_batch([m for _, m in pairs], [s for s, _ in pairs]) == want
        assert [pyca_ok(HV.verify, m, s) for s, m in pairs] == want
    else:
        assert v.verify_batch([s for s, _ in pairs], [m for _, m in pairs]) == want
        assert [pyca_ok(v.verify, s, m) for s, m in pairs] == want
