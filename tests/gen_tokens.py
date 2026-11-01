#!/usr/bin/env python3
"""gen_tokens.py SECRET N > tokens.json: N deterministic HS256 test tokens (Python stdlib only).

Each record is {"id":N,"username":"...","token":"..."}. Payloads are compact JSON in the key order
{"sub":"<id>","username":"<name>","iat":<s>,"exp":<s>}, the shape most JWT minting libraries emit for
these claims (and the one jwt.c's shape-matched fast path recognises; everything else goes through the
strict parser). exp is in 2036, so the tokens stay live for the tests.
"""

import base64
import hashlib
import hmac
import json
import sys

ADJ = ["golden", "silver", "swift", "quiet", "amber", "crimson", "lunar", "rapid", "misty", "brave"]
NOUN = ["ember", "comet", "nebula", "harbor", "falcon", "meadow", "quartz", "willow", "tundra", "orbit"]


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=")


def main():
    secret, n = sys.argv[1].encode(), int(sys.argv[2])
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    out = []
    for i in range(1, n + 1):
        name = f"{ADJ[i % 10]}_{NOUN[(i // 10) % 10]}_{i}"
        pl = {"sub": str(i), "username": name, "iat": 1792832174, "exp": 2108192174}
        msg = head + b"." + b64(json.dumps(pl, separators=(",", ":")).encode())
        sig = b64(hmac.new(secret, msg, hashlib.sha256).digest())
        out.append({"id": i, "username": name, "token": (msg + b"." + sig).decode()})
    sys.stdout.write(json.dumps(out, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
