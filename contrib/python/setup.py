"""Build of cursed_crypto._native: the binding (src/cursed_crypto/_native.c) plus cursed-crypto itself.

cursed-crypto is compiled exactly as the library's Makefile compiles it: crypto/src/cursed_crypto.c as one
translation unit at -O3 for the baseline ISA (the engines are picked at run time from the CPU), and on x86-64 ELF
the committed .S kernels with -DJWT_OSSL_SHA256 -DJWT_SHANI_MB -DJWT_OSSL_MONT.  Elsewhere it is the portable
build (the Makefile's OSSL_SHA=).  Nothing is fetched at build time.

In the cursed-jwt tree the sources sit two levels up (../../crypto, ../../LICENSE, ../../licenses).  They are
copied into vendor/ before every build, so the sdist carries them and a wheel built from the sdist is identical to
one built in the tree.  In an unpacked sdist vendor/ is already there.

Environment:
  CURSED_CRYPTO_PORTABLE=1   build without the assembly kernels on x86-64 too (the Makefile's OSSL_SHA=)
  CURSED_CRYPTO_CFLAGS=...   extra compiler flags for both units (e.g. -march=native, or a sanitizer build)
  CURSED_CRYPTO_LDFLAGS=...  extra linker flags
"""

import os
import platform
import shlex
import shutil
import sys

from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
VENDOR = os.path.join(HERE, "vendor")
ASM = [
    "sha256_x86_64_ossl.S",
    "sha256_shani_mb.S",
    "sha256_x16_avx512.S",
    "bn_mont_x86_64_ossl.S",
    "bn_mont5_x86_64_ossl.S",
]


def sync_vendor():
    """Copy cursed-crypto's sources and the licence texts from the tree into vendor/ (no-op in an sdist)."""
    src = os.path.join(ROOT, "crypto")
    if not os.path.isfile(os.path.join(src, "src", "cursed_crypto.c")) or not os.path.isfile(
        os.path.join(ROOT, "LICENSE")
    ):
        if not os.path.isfile(os.path.join(VENDOR, "crypto", "src", "cursed_crypto.c")):
            sys.exit("cursed_crypto: neither ../../crypto (the cursed-jwt tree) nor vendor/ (an sdist) found")
        return
    if os.path.isdir(VENDOR):
        shutil.rmtree(VENDOR)
    # the IFMA (crypto_mb) glue is opt-in in the library and fetched code; it stays out of this package
    skip = shutil.ignore_patterns("cmb_ec", "cmb_rsa", "*.o", "*.a")
    shutil.copytree(src, os.path.join(VENDOR, "crypto"), ignore=skip)
    shutil.copy2(os.path.join(ROOT, "LICENSE"), os.path.join(VENDOR, "LICENSE"))
    shutil.copytree(os.path.join(ROOT, "licenses"), os.path.join(VENDOR, "licenses"))
    shutil.copy2(
        os.path.join(src, "src", "fiat", "LICENSE-MIT"),
        os.path.join(VENDOR, "licenses", "fiat-crypto-LICENSE-MIT.txt"),
    )


sync_vendor()

x86_elf = (
    platform.machine().lower() in ("x86_64", "amd64")
    and sys.platform.startswith(("linux", "freebsd"))
    and os.environ.get("CURSED_CRYPTO_PORTABLE", "") != "1"
)
csrc = os.path.join("vendor", "crypto", "src")
macros = [("JWT_OSSL_SHA256", None), ("JWT_SHANI_MB", None), ("JWT_OSSL_MONT", None)] if x86_elf else []
extra_c = shlex.split(os.environ.get("CURSED_CRYPTO_CFLAGS", ""))
extra_ld = shlex.split(os.environ.get("CURSED_CRYPTO_LDFLAGS", ""))
cflags = [
    "-O3",
    "-g0",
    "-fvisibility=hidden",
    "-Wall",
    "-Wextra",
    "-Wno-unused-function",
    "-Wno-unused-parameter",
    "-Wno-missing-field-initializers",
]


class BuildExt(build_ext):
    """Assembles the .S kernels (setuptools' compiler driver doesn't take .S) and links them into the extension."""

    def build_extension(self, ext):
        if x86_elf:
            objdir = os.path.join(self.build_temp, "asm")
            os.makedirs(objdir, exist_ok=True)
            objs = []
            for s in ASM:
                o = os.path.join(objdir, s[:-2] + ".o")
                self.spawn(self.compiler.compiler_so[:1] + ["-c", os.path.join(csrc, s), "-o", o])
                objs.append(o)
            ext.extra_objects = objs
        super().build_extension(ext)


setup(
    ext_modules=[
        Extension(
            "cursed_crypto._native",
            sources=["src/cursed_crypto/_native.c", os.path.join(csrc, "cursed_crypto.c")],
            include_dirs=[os.path.join("vendor", "crypto", "include"), csrc],
            define_macros=macros,
            extra_compile_args=cflags + extra_c,
            extra_link_args=extra_ld,
        )
    ],
    cmdclass={"build_ext": BuildExt},
)
