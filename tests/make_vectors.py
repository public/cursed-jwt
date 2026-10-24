#!/usr/bin/env python3
"""make_vectors.py VECTOR_DIR N_RANDOM SEED > hmac_vectors.txt

Turns the fetched HMAC-SHA256 vectors (scripts/fetch-vectors.sh) plus N_RANDOM random cases into one file for
tests/test_vectors.c. Every vector is first checked against pyca/cryptography's HMAC, so a parsing mistake here
cannot pass silently: a published valid tag must match cryptography, an invalid (Wycheproof) tag must not.
The random cases' tags are computed by cryptography (OpenSSL underneath, but a separate code path from the C
tests' direct libcrypto calls); keys 0-200 bytes (hashed above 64), messages 0-1100 bytes.

Output, one vector per line:  hmac SOURCE KEY_HEX MSG_HEX TAG_HEX EXPECT    (EXPECT 1 = tag valid, 0 = invalid;
the tag may be truncated: compare that many leading bytes; "-" = empty)
                              jws SOURCE KEY_HEX TOKEN NOW STATUS            (jwt_verify_batch must return STATUS)
"""
import json, os, random, re, sys, zipfile
from cryptography.hazmat.primitives import hashes, hmac


def mac(k, m):
    h = hmac.HMAC(k, hashes.SHA256()); h.update(m); return h.finalize()


def hx(b): return b.hex() or "-"


def rfc4231(path):
    text = open(path).read()
    out = []
    for m in re.finditer(r"^4\.(\d+)\.  Test Case (\d+)\n(.*?)(?=^4\.\d+\.  Test Case|^5\.)", text, re.S | re.M):
        body = "\n".join(l for l in m.group(3).split("\n") if "[Page" not in l and not l.startswith(("RFC 4231", "\f")))
        fields, cur = {}, None
        for line in body.split("\n"):
            if not line.strip(): continue
            f = re.match(r"\s+(Key|Data|HMAC-SHA-\d+)\s+=?\s+(.*)", line)   # test case 3's "Key" has no "="
            if f: cur = f.group(1); rest = f.group(2)
            elif cur and re.match(r"\s{10,}[0-9a-f]{2}", line): rest = line
            else: cur = None; continue
            hexpart = re.match(r"\s*((?:[0-9a-f]{2})+)", rest)
            if hexpart: fields[cur] = fields.get(cur, "") + hexpart.group(1)
        out.append(("rfc4231-tc" + m.group(2), bytes.fromhex(fields["Key"]), bytes.fromhex(fields["Data"]),
                    bytes.fromhex(fields["HMAC-SHA-256"]), 1))
    assert len(out) == 7, len(out)
    return out


def nist(path):
    text = zipfile.ZipFile(path).read("HMAC.rsp").decode()
    sec = text[text.index("[L=32]"):]
    nxt = sec.find("[L=", 6)
    if nxt > 0: sec = sec[:nxt]
    out = []
    for blk in re.split(r"\n\s*\n", sec):
        d = dict(re.findall(r"^(\w+) = (\S+)", blk, re.M))
        if "Mac" in d:
            out.append(("nist-cavp-L32-c" + d["Count"] + "-k" + d["Klen"] + "-t" + d["Tlen"], bytes.fromhex(d["Key"]),
                        bytes.fromhex(d["Msg"]), bytes.fromhex(d["Mac"]), 1))
    assert len(out) >= 200, len(out)
    return out


def wycheproof(path):
    d = json.load(open(path)); out = []
    for g in d["testGroups"]:
        for t in g["tests"]:
            if t["result"] == "acceptable": continue
            out.append((f"wycheproof-{t['tcId']}", bytes.fromhex(t["key"]), bytes.fromhex(t["msg"]), bytes.fromhex(t["tag"]),
                        1 if t["result"] == "valid" else 0))
    return out


def rfc7515(path):
    text = open(path).read()
    a1 = text[text.rindex("\nA.1.  Example JWS Using HMAC SHA-256"):text.rindex("\nA.2.  Example JWS Using RSASSA")]   # rindex: skip the ToC
    k = re.search(r'"k":"([^"]+)"', a1, re.S).group(1)
    k = re.sub(r"\s+", "", k)
    tok = re.search(r"Compact Serialization \(with line breaks\s+for display purposes only\):\s*\n(.*?)\n\nA\.1\.2", a1, re.S).group(1)
    tok = re.sub(r"\s+", "", tok)
    import base64
    key = base64.urlsafe_b64decode(k + "=" * (-len(k) % 4))
    head, payload, sig = tok.split(".")
    assert base64.urlsafe_b64decode(sig + "=") == mac(key, (head + "." + payload).encode()), "RFC 7515 A.1 did not verify"
    exp = 1300819380   # the example's "exp"
    j = len(tok) - 10; bad = tok[:j] + ("A" if tok[j] != "A" else "B") + tok[j + 1:]   # inside the signature
    # live: signature and time fine, but the example has no sub/username claims -> BAD_PAYLOAD; expired -> INVALID
    return [("rfc7515-a1-live", key, tok, exp - 1, 2), ("rfc7515-a1-expired", key, tok, exp, 1),
            ("rfc7515-a1-tampered-sig", key, bad, exp - 1, 1)]


def main():
    vdir, nrand, seed = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    vec = rfc4231(os.path.join(vdir, "rfc4231.txt")) + nist(os.path.join(vdir, "hmactestvectors.zip")) + \
          wycheproof(os.path.join(vdir, "hmac_sha256_test.json"))
    for src, k, m, t, ok in vec:   # the parsed vectors must agree with cryptography
        got = mac(k, m)[:len(t)] == t
        if got != bool(ok): raise SystemExit(f"{src}: parsed vector disagrees with cryptography (expect {ok})")
    rnd = random.Random(seed)
    for i in range(nrand):
        kl = rnd.choice([0, 1, 31, 32, 33, 63, 64, 65, 100, 128, 200, rnd.randrange(0, 201)])
        ml = rnd.choice([0, 1, 55, 56, 63, 64, 65, 119, 120, 128, rnd.randrange(0, 1101)])
        k, m = rnd.randbytes(kl), rnd.randbytes(ml)
        t = mac(k, m)
        if rnd.random() < 0.1:   # a wrong tag must be rejected
            j = rnd.randrange(32); t = t[:j] + bytes([t[j] ^ (1 << rnd.randrange(8))]) + t[j + 1:]; vec.append((f"random-{i}-bad", k, m, t, 0))
        else: vec.append((f"random-{i}", k, m, t, 1))
    w = sys.stdout.write
    for src, k, m, t, ok in vec: w(f"hmac {src} {hx(k)} {hx(m)} {hx(t)} {ok}\n")
    for src, k, tok, now, st in rfc7515(os.path.join(vdir, "rfc7515.txt")): w(f"jws {src} {hx(k)} {tok} {now} {st}\n")
    print(f"{len(vec)} HMAC vectors + 3 JWS checks, all consistent with cryptography", file=sys.stderr)


if __name__ == "__main__":
    main()
