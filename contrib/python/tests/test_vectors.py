"""Wycheproof, RFC 4231 and RFC 8032 vectors: every verdict, single and batched, must equal pyca/cryptography's.

pyca is the oracle, not the vectors' "result" field: where Wycheproof marks a case "acceptable", what counts is
what pyca does with it.  Vectors come from scripts/fetch-vectors.sh (pinned SHA-256s)."""

import importlib.util
import json
import os
import random

import pytest
from conftest import check, pyca_ok, vector
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

import cursed_crypto


def groups(name):
    with open(vector(name)) as f:
        return json.load(f)["testGroups"]


def cases(g):
    return [(bytes.fromhex(t["sig"]), bytes.fromhex(t["msg"])) for t in g["tests"]]


def test_ecdsa_p256_der():
    n = 0
    for gi, g in enumerate(groups("ecdsa_secp256r1_sha256_test.json")):
        pub = serialization.load_der_public_key(bytes.fromhex(g["publicKeyDer"]))
        alg = ec.ECDSA(hashes.SHA256())
        v = cursed_crypto.ECDSAVerifier(pub, alg)
        assert v._k is not None, "a P-256 / SHA-256 key must take the native path"
        items = cases(g)
        ref = [pyca_ok(pub.verify, s, m, alg) for s, m in items]
        check(v, items, ref, random.Random(gi), label=f"group {gi}")
        n += len(items)
    assert n > 400


def p1363_ref(pub, alg, sig, msg):
    if len(sig) != 64:
        return False
    return pyca_ok(
        pub.verify, encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")), msg, alg
    )


def test_ecdsa_p256_p1363():
    n = 0
    for gi, g in enumerate(groups("ecdsa_secp256r1_sha256_p1363_test.json")):
        pub = serialization.load_der_public_key(bytes.fromhex(g["publicKeyDer"]))
        alg = ec.ECDSA(hashes.SHA256())
        v = cursed_crypto.ECDSAVerifier(pub, alg, signature_format="raw")
        assert v._k is not None
        items = cases(g)
        ref = [p1363_ref(pub, alg, s, m) for s, m in items]
        check(v, items, ref, random.Random(gi), label=f"group {gi}")
        # the raw format agrees with Wycheproof's own verdicts too (no "acceptable" cases in this file)
        assert ref == [t["result"] == "valid" for t in g["tests"]]
        n += len(items)
    assert n > 200


@pytest.mark.parametrize("bits", [2048, 3072, 4096])
def test_rsa_pkcs1v15_sha256(bits):
    n = 0
    for gi, g in enumerate(groups(f"rsa_signature_{bits}_sha256_test.json")):
        pub = serialization.load_der_public_key(bytes.fromhex(g["publicKeyDer"]))
        v = cursed_crypto.RSAVerifier(pub, padding.PKCS1v15(), hashes.SHA256())
        assert v._k is not None
        items = cases(g)
        ref = [pyca_ok(pub.verify, s, m, padding.PKCS1v15(), hashes.SHA256()) for s, m in items]
        check(v, items, ref, random.Random(gi), label=f"{bits} group {gi}")
        n += len(items)
    assert n > 100


def test_ed25519_wycheproof():
    n = 0
    for gi, g in enumerate(groups("ed25519_test.json")):
        pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(g["publicKey"]["pk"]))
        v = cursed_crypto.Ed25519Verifier(pub)
        items = cases(g)
        ref = [pyca_ok(pub.verify, s, m) for s, m in items]
        check(v, items, ref, random.Random(gi), label=f"group {gi}")
        n += len(items)
    assert n > 100


def repo_module(name):
    """A helper script of the cursed-jwt tree's tests/ (its vector parsers), or skip outside the tree (an sdist)."""
    path = os.path.join(os.path.dirname(__file__), "..", "..", "..", "tests", name + ".py")
    if not os.path.isfile(path):
        pytest.skip(f"tests/{name}.py is only in the cursed-jwt tree")
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_ed25519_rfc8032():
    vs = repo_module("make_pk_vectors").rfc8032_ed(vector("rfc8032.txt"))
    assert len(vs) == 5
    for _, _, pub_b, _, msg, sig, _ in vs:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(pub_b)
        v = cursed_crypto.Ed25519Verifier(pub)
        bad = bytes([sig[0] ^ 1]) + sig[1:]
        items = [(sig, msg), (bad, msg), (sig, msg + b"x")]
        ref = [pyca_ok(pub.verify, s, m) for s, m in items]
        assert ref == [True, False, False]
        check(v, items, ref)


def hmac_ref(key, msg, tag):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(msg)
    return pyca_ok(h.verify, tag)


def test_hmac_wycheproof():
    n = 0
    for gi, g in enumerate(groups("hmac_sha256_test.json")):
        for t in g["tests"]:  # one key per test: group them by key
            key, msg, tag = (bytes.fromhex(t[k]) for k in ("key", "msg", "tag"))
            h = cursed_crypto.HMACSHA256(key)
            ref = [hmac_ref(key, msg, tag)]
            check(h, [(msg, tag)], ref, label=f"tcId {t['tcId']}")
            if len(tag) == 32:
                assert h.digest(msg) == (tag if ref[0] else h.digest(msg))
            n += 1
    assert n > 100


def test_hmac_rfc4231():
    mod = repo_module("make_vectors")
    for name, key, msg, tag, _ in mod.rfc4231(vector("rfc4231.txt")):
        h = cursed_crypto.HMACSHA256(key)
        items = [(msg, tag), (msg, bytes([tag[0] ^ 1]) + tag[1:]), (msg + b"\0", tag)]
        ref = [hmac_ref(key, m, t) for m, t in items]
        # test case 5's tag is truncated to 128 bits, which pyca's HMAC.verify rejects (it compares all 32 bytes)
        assert ref == [len(tag) == 32, False, False], name
        check(h, items, ref, label=name)
        if len(tag) == 32:  # test case 5 is truncated to 128 bits
            assert h.digest(msg) == tag and h.digest_batch([msg, msg]) == [tag, tag]
