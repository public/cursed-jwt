#!/bin/sh
# extract-openssl-mont.sh: regenerate src/bn_mont_x86_64_ossl.S and src/bn_mont5_x86_64_ossl.S, OpenSSL's x86-64
# Montgomery multiplication (bn_mul_mont, and the 8-way squaring in x86_64-mont5 that it calls), vendored.  Two files,
# because the two generated sources reuse the same local labels.
#
# The source is OpenSSL 3.6.0 (Apache-2.0), commit 7b371d8, the same pin as extract-openssl-sha256.sh.  The perlasm
# files are fetched pinned and SHA-256-checked into third_party/openssl-perlasm (git-ignored), generated for ELF
# (Linux) and adapted:
#   - every global bn_* symbol becomes jwt_ossl_bn_* and is marked .hidden, so it never clashes with a libcrypto
#     linked into the same program;
#   - OPENSSL_ia32cap_P becomes jwt_ossl_ia32cap_P, which src/jwt.c already fills from CPUID; the code reads
#     word 2 (CPUID.7.0:EBX) for BMI2 + ADX and takes its mulx/adcx/adox paths only when both are present.
# The output is committed, so building needs neither perl nor the network; this script only reproduces it.
# Needs perl and a C compiler for the assembler-version probe ($CC, default cc).
set -e
cd "$(dirname "$0")/.."
D=third_party/openssl-perlasm
C=7b371d80d959ec9ab4139d09d78e83c090de9779
mkdir -p $D
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
get() { # path-in-repo sha256
  f="${D:?}/$(basename "$1")"
  if [ -f "$f" ] && [ "$(sha "$f")" = "$2" ]; then return; fi
  echo "$1: fetching OpenSSL $C"
  curl -fsSL "https://raw.githubusercontent.com/openssl/openssl/$C/$1" -o "$f.tmp"
  got=$(sha "$f.tmp")
  [ "$got" = "$2" ] || {
    echo "$1: SHA-256 mismatch (got $got, want $2)" >&2
    rm -f "${f:?}.tmp"
    exit 1
  }
  mv "$f.tmp" "$f"
}
get crypto/bn/asm/x86_64-mont.pl f7665798a2ad0435fc5b145e72faccd8aacfd357c4561982ff01ceb93c06ca29
get crypto/bn/asm/x86_64-mont5.pl f4e02c65a22276451ec1249a5a72dde1ed7227cdf544b6bde3402bd9d96a2d97
get crypto/perlasm/x86_64-xlate.pl 8305200de6f523fa6a7f64bf1889e1e5dda4e20bff58d61887608dd8edd3a9f8
CC=${CC:-cc} perl $D/x86_64-mont.pl elf $D/x86_64-mont.S
CC=${CC:-cc} perl $D/x86_64-mont5.pl elf $D/x86_64-mont5.S
SYMS='bn_mul_mont_gather5|bn_mul_mont|bn_power5|bn_sqr8x_internal|bn_sqrx8x_internal|bn_get_bits5|bn_scatter5|bn_gather5'
gen() { # perlasm-output output.S source-name
  {
    cat <<HDR
/* $(basename "$2"): OpenSSL's x86-64 Montgomery multiplication ($3; mulx/adcx/adox paths dispatched on a CPU
 * capability word), generated from OpenSSL 3.6.0 crypto/bn/asm/$3 by scripts/extract-openssl-mont.sh and renamed for
 * cursed-jwt.  Do not edit; regenerate.
 *
 * Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 * Written by Andy Polyakov for the OpenSSL project.
 * Licensed under the Apache License 2.0; see THIRD_PARTY.md and https://www.openssl.org/source/license.html */
HDR
    sed -E -e "s/\\b($SYMS)\\b/jwt_ossl_\\1/g" -e 's/OPENSSL_ia32cap_P/jwt_ossl_ia32cap_P/g' "$1" |
      awk '{ print } /^\.globl[[:space:]]+jwt_ossl_/ && !seen[$2]++ { print ".hidden\t" $2 }'
    printf '\n.section .note.GNU-stack,"",@progbits\n' # no executable stack (the elf flavour omits it)
  } >"$2"
  echo "$2: $(wc -l <"$2") lines"
}
gen $D/x86_64-mont.S src/bn_mont_x86_64_ossl.S x86_64-mont.pl
gen $D/x86_64-mont5.S src/bn_mont5_x86_64_ossl.S x86_64-mont5.pl
