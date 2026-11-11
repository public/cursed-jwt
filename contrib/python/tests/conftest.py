"""Shared helpers for the differential suite: pyca/cryptography is the oracle for every verdict."""

import os
import random

import pytest

import cursed_crypto

VECTORS = os.environ.get(
    "CURSED_VECTORS", os.path.join(os.path.dirname(__file__), "..", "..", "..", "third_party", "vectors")
)
# CURSED_ENGINE=name: fail unless cursed-crypto picked that engine (the CPU-mask runs set it, so a mask that didn't
# take can't pass silently)
WANT_ENGINE = os.environ.get("CURSED_ENGINE")


def pytest_report_header(config):
    return f"cursed_crypto engine: {cursed_crypto.engine()}, cpu features: {cursed_crypto._native.cpu_features():#x}"


@pytest.fixture(scope="session", autouse=True)
def _engine_check():
    if WANT_ENGINE:
        assert cursed_crypto.engine() == WANT_ENGINE, (cursed_crypto.engine(), WANT_ENGINE)


def vector(name):
    p = os.path.join(VECTORS, name)
    if not os.path.isfile(p):
        pytest.skip(f"{name} not found in {VECTORS}: run scripts/fetch-vectors.sh (make -C contrib/python test does)")
    return p


def batches(n, rng, sizes=range(1, 34)):
    """Random partitions of a random permutation of range(n), batch sizes drawn from sizes."""
    idx = list(range(n))
    rng.shuffle(idx)
    out, i = [], 0
    sizes = list(sizes)
    while i < n:
        k = rng.choice(sizes)
        out.append(idx[i : i + k])
        i += k
    return out


def check(verifier, items, ref, rng=None, rounds=3, label=""):
    """items: list of (a, b) argument pairs for verifier.verify(a, b) / verify_batch([a..], [b..]); ref: pyca's
    verdict per item.  Single calls, one batch of everything, and random batches of 1..33 must all match ref."""
    from cryptography.exceptions import InvalidSignature

    rng = rng or random.Random(1)
    assert len(items) == len(ref)
    for i, (a, b) in enumerate(items):
        try:
            verifier.verify(a, b)
            got = True
        except InvalidSignature:
            got = False
        assert got == ref[i], f"{label} single item {i}: got {got}, pyca {ref[i]}"
    if not items:
        return
    got = verifier.verify_batch([a for a, _ in items], [b for _, b in items])
    assert (
        got == ref
    ), f"{label} batch of {len(items)}: mismatches at {[i for i in range(len(ref)) if got[i] != ref[i]]}"
    for _ in range(rounds):
        for part in batches(len(items), rng):
            got = verifier.verify_batch([items[i][0] for i in part], [items[i][1] for i in part])
            want = [ref[i] for i in part]
            assert got == want, f"{label} batch {part}: got {got}, pyca {want}"


def pyca_ok(fn, *args):
    from cryptography.exceptions import InvalidSignature

    try:
        fn(*args)
        return True
    except InvalidSignature:
        return False
