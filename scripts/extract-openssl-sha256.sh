#!/bin/sh
# extract-openssl-sha256.sh: regenerate crypto/src/sha256_x86_64_ossl.S, OpenSSL's x86-64 SHA-256 block function, vendored.
#
# The source is OpenSSL 3.6.0 (Apache-2.0), commit 7b371d8.  The two perlasm files are fetched pinned and
# SHA-256-checked into third_party/openssl-perlasm (git-ignored), then generated for ELF (Linux) and adapted:
#   - sha256_block_data_order* becomes jwt_ossl_sha256_block* and is marked .hidden, so it never clashes with a
#     libcrypto linked into the same program;
#   - OPENSSL_ia32cap_P becomes jwt_ossl_ia32cap_P, which src/jwt.c fills from CPUID with the bits the
#     dispatcher reads (SHA-NI, AVX2+BMI1+BMI2, AVX, SSSE3).
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
get crypto/sha/asm/sha512-x86_64.pl bd4b1466b0b79cdd03266bcebb86637422a56f507d9e1d4ff8589f5d5a44486b
get crypto/perlasm/x86_64-xlate.pl 8305200de6f523fa6a7f64bf1889e1e5dda4e20bff58d61887608dd8edd3a9f8
OUT=crypto/src/sha256_x86_64_ossl.S
CC=${CC:-cc} perl $D/sha512-x86_64.pl elf $D/sha256-x86_64.S # "256" in the output name selects SHA-256
{
  cat <<'EOF'
/* sha256_x86_64_ossl.S: OpenSSL's sha256_block_data_order for x86-64 (SHA-NI, AVX2+BMI2, AVX, SSSE3 and plain
 * x86-64 paths, dispatched on a CPU capability word), generated from OpenSSL 3.6.0 crypto/sha/asm/sha512-x86_64.pl
 * by scripts/extract-openssl-sha256.sh and renamed for cursed-jwt.  Do not edit; regenerate.
 *
 * Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 * Written by Andy Polyakov for the OpenSSL project.
 * Licensed under the Apache License 2.0; see THIRD_PARTY.md and https://www.openssl.org/source/license.html */
EOF
  sed -e 's/sha256_block_data_order/jwt_ossl_sha256_block/g' -e 's/OPENSSL_ia32cap_P/jwt_ossl_ia32cap_P/g' \
    -e 's/^\(\.globl[[:space:]]*jwt_ossl_sha256_block\)$/\1\n.hidden	jwt_ossl_sha256_block/' $D/sha256-x86_64.S
  printf '\n.section .note.GNU-stack,"",@progbits\n' # no executable stack (the elf flavour omits it)
} >$OUT
echo "$OUT: $(wc -l <$OUT) lines"
