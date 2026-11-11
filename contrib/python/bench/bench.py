"""bench.py [DATADIR] [--rounds R] [--sizes 1,8,16,64] [--algs EdDSA,ES256,RS256,HS256] [--threads N]

Verify cost per item, in ns, from Python, for Ed25519, ES256, RS256 and HS256 at each batch size, as five arms:
  pyca-loop     pyca/cryptography, public_key.verify(...) (HS256: hmac.HMAC + update + verify) in a for loop
  pyca-pool     the same calls through concurrent.futures.ThreadPoolExecutor(N).map (N = vCPUs by default)
  cc-single     cursed_crypto's verifier, .verify() per item
  cc-batch      cursed_crypto's verifier, .verify_batch() per batch
  cc-overhead   the binding's work in verify_batch without the crypto (lists to C arrays, buffers, GIL, result list)
Arms run interleaved in a rotated order each round.  ES256 signatures are DER for every arm, as pyca takes them.

DATADIR holds ALG.prim files (line 1 the key in hex, then 'message_hex signature_hex' lines; ES256 raw r || s):
JWS signing inputs of about 570 bytes.  Without DATADIR, keys and 570-byte messages are generated here.
Output: TSV on stdout (round, pos, alg, arm, batch, threads, ns_per_item) and a median summary on stderr."""

import argparse
import concurrent.futures as cf
import os
import statistics
import sys
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

import cursed_crypto

SHA = ec.ECDSA(hashes.SHA256())
PK = (padding.PKCS1v15(), hashes.SHA256())


def load(datadir, alg):
    lines = open(os.path.join(datadir, f"{alg}.prim")).read().split("\n")
    key = lines[0].split()
    items = [tuple(bytes.fromhex(x) for x in ln.split()) for ln in lines[1:] if ln.strip()]
    if alg == "ES256":
        items = [
            (m, encode_dss_signature(int.from_bytes(s[:32], "big"), int.from_bytes(s[32:], "big"))) for m, s in items
        ]
    if alg == "RS256":
        pub = rsa.RSAPublicNumbers(int(key[1], 16), int(key[0], 16)).public_key()
    elif alg == "ES256":
        pub = ec.EllipticCurvePublicNumbers(int(key[0], 16), int(key[1], 16), ec.SECP256R1()).public_key()
    elif alg == "EdDSA":
        pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(key[0]))
    else:
        pub = bytes.fromhex(key[0])
    return pub, items


def generate(alg, n=1024):
    msgs = [os.urandom(285).hex().encode() for _ in range(n)]  # 570 bytes, like a JWS signing input
    if alg == "EdDSA":
        k = ed25519.Ed25519PrivateKey.generate()
        return k.public_key(), [(m, k.sign(m)) for m in msgs]
    if alg == "ES256":
        k = ec.generate_private_key(ec.SECP256R1())
        return k.public_key(), [(m, k.sign(m, SHA)) for m in msgs]
    if alg == "RS256":
        k = rsa.generate_private_key(65537, 2048)
        return k.public_key(), [(m, k.sign(m, *PK)) for m in msgs]
    key = os.urandom(32)
    out = []
    for m in msgs:
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(m)
        out.append((m, h.finalize()))
    return key, out


def arms(alg, pub, pool):
    """name -> fn(sigs, msgs) returning a list of verdicts (each must be all True)."""
    if alg == "HS256":
        key = pub

        def one(s, m):
            h = hmac.HMAC(key, hashes.SHA256())
            h.update(m)
            try:
                h.verify(s)
                return True
            except InvalidSignature:
                return False

        v = cursed_crypto.HMACSHA256(key)

        def cc_one(s, m):
            try:
                v.verify(m, s)
                return True
            except InvalidSignature:
                return False

        return {
            "pyca-loop": lambda S, M: [one(s, m) for s, m in zip(S, M)],
            "pyca-pool": lambda S, M: list(pool.map(one, S, M)),
            "cc-single": lambda S, M: [cc_one(s, m) for s, m in zip(S, M)],
            "cc-batch": lambda S, M: v.verify_batch(M, S),
            "cc-overhead": lambda S, M: [True for _ in cursed_crypto._native._overhead(M, S)[0]],
        }
    if alg == "EdDSA":
        v = cursed_crypto.Ed25519Verifier(pub)
        ver = pub.verify
    elif alg == "ES256":
        v = cursed_crypto.ECDSAVerifier(pub, SHA)

        def ver(s, m):
            pub.verify(s, m, SHA)
    else:
        v = cursed_crypto.RSAVerifier(pub, *PK)

        def ver(s, m):
            pub.verify(s, m, *PK)

    assert v._k is not None

    def one(s, m):
        try:
            ver(s, m)
            return True
        except InvalidSignature:
            return False

    def cc_one(s, m):
        try:
            v.verify(s, m)
            return True
        except InvalidSignature:
            return False

    return {
        "pyca-loop": lambda S, M: [one(s, m) for s, m in zip(S, M)],
        "pyca-pool": lambda S, M: list(pool.map(one, S, M)),
        "cc-single": lambda S, M: [cc_one(s, m) for s, m in zip(S, M)],
        "cc-batch": lambda S, M: v.verify_batch(S, M),
        "cc-overhead": lambda S, M: [True for _ in cursed_crypto._native._overhead(S, M)[0]],
    }


def measure(fn, batches, target_s):
    """ns per item: whole passes over the prepared batches until target_s has passed."""
    items = sum(len(b[0]) for b in batches)
    for S, M in batches[:2]:  # warm-up, and every arm must accept everything
        assert all(fn(S, M)), "a valid signature was rejected"
    reps, t0 = 0, time.perf_counter_ns()
    while True:
        for S, M in batches:
            fn(S, M)
        reps += 1
        el = time.perf_counter_ns() - t0
        if el >= target_s * 1e9:
            return el / (reps * items)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("datadir", nargs="?")
    ap.add_argument("--rounds", type=int, default=7)
    ap.add_argument("--sizes", default="1,8,16,64")
    ap.add_argument("--algs", default="EdDSA,ES256,RS256,HS256")
    ap.add_argument("--threads", type=int, default=os.cpu_count())
    ap.add_argument("--target", type=float, default=0.12, help="seconds per measurement")
    ap.add_argument("--items", type=int, default=256, help="distinct items per measurement")
    a = ap.parse_args()
    sizes = [int(x) for x in a.sizes.split(",")]
    pool = cf.ThreadPoolExecutor(a.threads)
    print("round\tpos\talg\tarm\tbatch\tthreads\tns_per_item", flush=True)
    rows = {}
    for alg in a.algs.split(","):
        pub, items = load(a.datadir, alg) if a.datadir else generate(alg)
        items = items[: a.items]
        fns = arms(alg, pub, pool)
        names = list(fns)
        for size in sizes:
            k = max(size, (len(items) // size) * size)
            pool_items = [items[i % len(items)] for i in range(k)]
            batches = [
                ([s for _, s in pool_items[j : j + size]], [m for m, _ in pool_items[j : j + size]])
                for j in range(0, k, size)
            ]
            for r in range(a.rounds):
                order = names[r % len(names) :] + names[: r % len(names)]
                for pos, name in enumerate(order):
                    ns = measure(fns[name], batches, a.target)
                    rows.setdefault((alg, name, size), []).append(ns)
                    print(f"{r}\t{pos}\t{alg}\t{name}\t{size}\t{a.threads}\t{ns:.1f}", flush=True)
    pool.shutdown()
    print(f"engine {cursed_crypto.engine()}, threads {a.threads}; median ns/item", file=sys.stderr)
    for (alg, name, size), v in sorted(rows.items()):
        print(f"{alg:6} {name:12} b{size:<3} {statistics.median(v):10.0f}", file=sys.stderr)


if __name__ == "__main__":
    main()
