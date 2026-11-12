"""run_engines.py PYTEST_ARGS...: run the suite once per distinct CPU feature set reachable with CC_CPU_MASK on this
machine (scalar, AVX2, AVX-512VL, SHA-NI, zmm, ...), each in its own process (the mask is read once, at load).
Each run sets CURSED_ENGINE, so conftest.py fails it if the mask didn't take."""

import os
import subprocess
import sys

# CC_CPU_* bit sets: scalar, AVX2, +BMI2/ADX, +AVX-512VL, SHA-NI on AVX2, fast SHA-NI (Zen), zmm, Intel zmm HMAC, all
MASKS = ["0x0", "0x1", "0x5", "0x7", "0x9", "0x10d", "0x18f", "0x807", "0xffffffff"]


def probe(mask):
    env = dict(os.environ, CC_CPU_MASK=mask)
    out = subprocess.run(
        [sys.executable, "-c", "import cursed_crypto as c; print(c.engine(), c._native.cpu_features())"],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    return out[0], int(out[1])


def main():
    seen, failed = {}, []
    for m in MASKS:
        eng, feat = probe(m)
        if feat in seen:
            continue
        seen[feat] = m
        print(f"== CC_CPU_MASK={m}: engine {eng}, features {feat:#x}", flush=True)
        env = dict(os.environ, CC_CPU_MASK=m, CURSED_ENGINE=eng)
        r = subprocess.run([sys.executable, "-m", "pytest", *sys.argv[1:]], env=env)
        if r.returncode:
            failed.append(m)
    print(f"== {len(seen)} feature sets, failed: {failed or 'none'}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
