#!/bin/sh
# extract-openssl-nistz256.sh: regenerate crypto/src/ecp_nistz256_x86_64_ossl.S, OpenSSL's x86-64 P-256 field and point
# arithmetic (ecp_nistz256: Gueron and Krasnov's constant-time P-256, with its 37 x 64-point table for the generator),
# vendored for ES256 signing's [k] G under -DCC_TUNED_ES256_NISTZ (make TUNED=1).
#
# The source is OpenSSL 3.6.0 (Apache-2.0), commit 7b371d8, the same pin as extract-openssl-sha256.sh and
# extract-openssl-mont.sh.  The perlasm file, its table and the translator are fetched pinned and SHA-256-checked into
# third_party/openssl-perlasm (git-ignored), generated for ELF (Linux) and adapted:
#   - every global ecp_nistz256_* symbol becomes cc_ossl_ecp_nistz256_* and is marked .hidden, so it never clashes with
#     a libcrypto linked into the same program;
#   - OPENSSL_ia32cap_P becomes cc_ossl_ia32cap_P, which crypto/src/cc_sha256.c fills from CPUID; the code reads word 2
#     (CPUID.7.0:EBX) for AVX2 (the table gather) and BMI2 + ADX (its mulx/adcx/adox paths, taken only when both are
#     present).
# The output is committed, so building needs neither perl nor the network; this script only reproduces it.
# Needs perl and a C compiler for the assembler-version probe ($CC, default cc).
set -e
cd "$(dirname "$0")/.."
D=third_party/openssl-perlasm
C=7b371d80d959ec9ab4139d09d78e83c090de9779
OUT=crypto/src/ecp_nistz256_x86_64_ossl.S
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
get crypto/ec/asm/ecp_nistz256-x86_64.pl f60598454105b0257dcc4a45c81c7a8508c5939d5030400e127daa69c73e490b
get crypto/ec/ecp_nistz256_table.c f63257de55a91e95880ae7a20eb1874869a5889d0fc5f9dcf670c4abaaec4493
get crypto/perlasm/x86_64-xlate.pl 8305200de6f523fa6a7f64bf1889e1e5dda4e20bff58d61887608dd8edd3a9f8
# the perlasm script opens ecp_nistz256_table.c from the current directory
(cd $D && CC=${CC:-cc} perl ecp_nistz256-x86_64.pl elf ecp_nistz256-x86_64.S)
{
  cat <<HDR
/* $(basename "$OUT"): OpenSSL's x86-64 ecp_nistz256 (P-256 field and point arithmetic, constant
 * time, with the 37 x 64 Montgomery-affine table of the generator; mulx/adcx/adox paths dispatched on a CPU capability
 * word), generated from
 * OpenSSL 3.6.0 crypto/ec/asm/ecp_nistz256-x86_64.pl and crypto/ec/ecp_nistz256_table.c by
 * scripts/extract-openssl-nistz256.sh and renamed for cursed-crypto.  Do not edit; regenerate.
 *
 * Copyright 2014-2025 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2014, Intel Corporation. All Rights Reserved.
 * Copyright (c) 2015 CloudFlare, Inc.
 * Originally written by Shay Gueron (1, 2), and Vlad Krasnov (1, 3); (1) Intel Corporation, Israel Development Center,
 * Haifa, Israel; (2) University of Haifa, Israel; (3) CloudFlare, Inc.
 * Licensed under the Apache License 2.0; see THIRD_PARTY.md and https://www.openssl.org/source/license.html
 *
 * Modified (Apache-2.0 section 4(b)): ecp_nistz256_* renamed cc_ossl_ecp_nistz256_* and hidden, OPENSSL_ia32cap_P
 * renamed cc_ossl_ia32cap_P, a .note.GNU-stack section added.  The code and the table are OpenSSL's, unchanged. */
HDR
  sed -E -e 's/\becp_nistz256_/cc_ossl_ecp_nistz256_/g' -e 's/OPENSSL_ia32cap_P/cc_ossl_ia32cap_P/g' \
    $D/ecp_nistz256-x86_64.S |
    awk '{ print } /^\.globl[[:space:]]+cc_ossl_/ && !seen[$2]++ { print ".hidden\t" $2 }'
  printf '\n.section .note.GNU-stack,"",@progbits\n' # no executable stack (the elf flavour omits it)
} >"$OUT"
echo "$OUT: $(wc -l <"$OUT") lines"
