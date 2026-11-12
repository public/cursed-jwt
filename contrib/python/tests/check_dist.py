"""check_dist.py DIR: the sdist and the wheel in DIR both carry LICENSE and every vendored licence text, the sdist
the C sources, the wheel the built extension."""

import glob
import sys
import tarfile
import zipfile

NEED = [
    "LICENSE",
    "OpenSSL-LICENSE.txt",
    "Firedancer-LICENSE.txt",
    "intel-ipsec-mb-LICENSE.txt",
    "fiat-crypto-LICENSE-MIT.txt",
    "s2n-bignum-LICENSE.txt",
]

d = sys.argv[1]
(sd,), (wh,) = glob.glob(f"{d}/*.tar.gz"), glob.glob(f"{d}/*.whl")
names = {"sdist": tarfile.open(sd).getnames(), "wheel": zipfile.ZipFile(wh).namelist()}
bad = [(k, n) for k, ns in names.items() for n in NEED if not any(x.endswith("/" + n) for x in ns)]
for need in ("/_native.c", "/cursed_crypto.c", "/sha256_shani_mb.S"):
    if not any(x.endswith(need) for x in names["sdist"]):
        bad.append(("sdist", need))
if not any("_native" in x and x.endswith((".so", ".pyd")) for x in names["wheel"]):
    bad.append(("wheel", "_native extension"))
print(f"{sd}\n{wh}\nmissing: {bad or 'nothing'}")
sys.exit(1 if bad else 0)
