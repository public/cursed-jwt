#!/bin/sh
# extract-ippcp-mont.sh: regenerate crypto/src/ippcp_mont_k0.asm, Intel Cryptography Primitives' (ippcp) x86-64
# schoolbook multiply, squaring and Montgomery reduction (cpMulAdc_BNU_school, cpSqrAdc_BNU_school, cpMontRedAdc_BNU)
# as ippcp builds them for its k0 (AVX-512 Skylake) and l9 (AVX2) targets: mulx with plain add/adc carry chains, no
# adcx/adox.  ippcp takes them for RSA on BMI2 CPUs without ADX; cursed-crypto does the same under -DCC_TUNED_RSA_IPP
# (make TUNED=1).
#
# The source is ippcp v2.4.0 (Apache-2.0), commit d9ac7a1, the version whose RSA verify was measured against ours.  The
# NASM files are fetched pinned and SHA-256-checked into third_party/ippcp-asm (git-ignored), run through NASM's
# preprocessor for the k0 target (-D_K0 -DLINUX32E), and adapted:
#   - the three global functions become cc_ipp_mul_school, cc_ipp_sqr_school and cc_ipp_mont_red, marked hidden, so
#     they never clash with an ippcp linked into the same program;
#   - the preprocessor's %line markers and blank lines are dropped, and its expansion of `align` back to the directive
#     (with ippcp's own `%use smartalign` / `ALIGNMODE p6,16`), so NASM emits exactly ippcp's padding.
# The result assembles to the same .text bytes as ippcp's own k0 object (checked here when NASM is new enough to
# assemble the original).  The output is committed; building it needs NASM (only with TUNED=1); this script needs
# NASM, curl and python3.
set -e
cd "$(dirname "$0")/.."
D=third_party/ippcp-asm
C=d9ac7a1dbe2276fd69bb637f23288858a03fbb8b
OUT=crypto/src/ippcp_mont_k0.asm
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
get() { # path-in-repo sha256
  f="${D:?}/$1"
  if [ -f "$f" ] && [ "$(sha "$f")" = "$2" ]; then return; fi
  echo "$1: fetching ippcp $C"
  mkdir -p "$(dirname "$f")"
  curl -fsSL "https://raw.githubusercontent.com/intel/cryptography-primitives/$C/$1" -o "$f.tmp"
  got=$(sha "$f.tmp")
  [ "$got" = "$2" ] || {
    echo "$1: SHA-256 mismatch (got $got, want $2)" >&2
    rm -f "${f:?}.tmp"
    exit 1
  }
  mv "$f.tmp" "$f"
}
get sources/include/asmdefs.inc 148b008420f81741e35c7669aa73c664caf89fd109dbe0f3f8ae77cb733ea8fd
get sources/include/ia_32e.inc fd8c3c93e0051cb672571adc090ca42cdbaed1b769aacf9d5b91f57b9290ba1b
get sources/include/ia_common.inc ab7cb1e8b817a47f9bf95b4166bda9ffb029cfa856d0897deded3191cb8cd489
get sources/include/noexec_stack.inc 4fc13e6db8482c8c769a3c2c0eac7186833c8d0a1bf06056476eaa4b52d922f2
get sources/include/utils.inc 5b13d4b7fcf3c8d9bd0e8a1aa6c8ad688b32f64fbef9bd58500bbaefbe0cde75
A=sources/ippcp/asm_intel64
get $A/pcpbnumul_basic.inc bf7d3ee95de6a69804dd53457f413af96f59dba9f9c6f7165325898c923f2873
get $A/pcpbnumul_fix.inc 1e46291e3438a7da5110ffe7f292b97e1ee40767420e32bbd0ed5cc3cdaed6cb
get $A/pcpbnumul.inc 163b0b4337aea72b171056fbe897d1308f94b55df2dd89e2d6f4671bd4a3e3e8
get $A/pcpbnumulschoolsrvl9.asm cb189733caa07d54625e1e29cb01b7f3d47c9d8adadf50bd25e13db6a0a88eaf
get $A/pcpbnusqr_basic.inc 59c9b0f1b8ed1627c3155c7a80bed69ec0bc5d2e81d04eea0f89a8ea19e8c2a3
get $A/pcpbnusqr.inc 5c40b07bd7356f11bb2c759298bbc6711b06159b359e382ba3d670f08cd3b89e
get $A/pcpmred_basic.inc a27687b7a2e93315f3d7acce4e0f0e72d792d13761acb5a602c25c60835576fe
get $A/pcpmred.inc e8bd4bc9cc437066ed22dd52dc4adc43ae83ba43299f515e62fbbcdb46739d5c
get $A/pcpmulx.inc 7bf58569f8a37b136117e7385cb12afc1cc98105d6c7c29b7002814f729b758f
get $A/pcpvariant.inc 6dc3f96c5eb42b81462f3ad3c7c9a20c6605065beb129a20a605c1eaaf08dbe0
NASMF="-f elf64 -D_K0 -DLINUX32E -I$D/sources/include/ -I$D/$A/"
nasm -E $NASMF $D/$A/pcpbnumulschoolsrvl9.asm -o $D/pre.asm
python3 -I - "$D/pre.asm" "$OUT" <<'EOF'
import re, sys
src, out = sys.argv[1], sys.argv[2]
s = open(src).read()
s = "\n".join(l for l in s.split("\n") if l.strip() and not l.startswith("%line")) + "\n"
s, n = re.subn(r"\[sectalign (\d+)\]\ntimes \(\(\(\1\) - \(\(\$-\$\$\) % \(\1\)\)\) % \(\1\)\) nop\n", r"align \1\n", s)
assert n > 0, "no align expansions found"
names = {"cpMulAdc_BNU_school": "cc_ipp_mul_school", "cpSqrAdc_BNU_school": "cc_ipp_sqr_school",
         "cpMontRedAdc_BNU": "cc_ipp_mont_red"}
for a, b in names.items():
    s, n = re.subn(r"\b%s\b" % a, b, s)
    assert n > 0, a
    s, n = re.subn(r"\[global %s:function " % b, "[global %s:function hidden " % b, s)
    assert n == 1, b
assert len(re.findall(r"\[global ", s)) == 3, "unexpected globals"
hdr = """; ippcp_mont_k0.asm: Intel Cryptography Primitives' (ippcp) x86-64 schoolbook multiply / square and Montgomery
; reduction for BMI2 CPUs without ADX (mulx, add/adc carry chains), as ippcp builds them for its k0 target.  Generated
; from ippcp v2.4.0 (commit d9ac7a1) sources/ippcp/asm_intel64/pcpbnumulschoolsrvl9.asm and the files it includes by
; scripts/extract-ippcp-mont.sh.  Do not edit; regenerate.
;
; Copyright (C) 2013-2024 Intel Corporation
; Licensed under the Apache License, Version 2.0; see THIRD_PARTY.md and http://www.apache.org/licenses/LICENSE-2.0
;
; Modified for cursed-crypto (Apache-2.0 section 4(b)): the NASM preprocessor's output for the k0 target, with its
; line markers and blank lines removed, its align expansions folded back into `align`, and the three functions
; renamed cpMulAdc_BNU_school -> cc_ipp_mul_school, cpSqrAdc_BNU_school -> cc_ipp_sqr_school,
; cpMontRedAdc_BNU -> cc_ipp_mont_red and given hidden visibility.  The machine code is ippcp's, unchanged.
%use smartalign
ALIGNMODE p6,16
"""
open(out, "w").write(hdr + s)
EOF
echo "$OUT: $(wc -l <"$OUT") lines"
# the same machine code as ippcp's own k0 build of the original file
nasm $NASMF $D/$A/pcpbnumulschoolsrvl9.asm -o $D/orig.o
nasm -f elf64 $OUT -o $D/ours.o
objcopy -O binary -j .text $D/orig.o $D/orig.bin
objcopy -O binary -j .text $D/ours.o $D/ours.bin
cmp $D/orig.bin $D/ours.bin && echo "$OUT: .text identical to ippcp's k0 object ($(wc -c <$D/ours.bin) bytes)"
