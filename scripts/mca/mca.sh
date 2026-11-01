#!/bin/sh
# mca.sh - static throughput estimates of the SHA-256 block functions (scripts/mca/kernels.c) per engine and CPU
# model, with llvm-mca (LLVM, Apache-2.0; e.g. `brew install llvm`, or apt's llvm) and, once fetched, uiCA
# (scripts/mca/fetch-uica.sh; uops.info, AGPL-3.0, never vendored; Intel only). Reported: cycles per byte per
# message = block rthroughput / (lanes x 64): independent back-to-back calls, L1 hits, no mispredicts. Use it to
# rank engines and to look at CPUs we can't run on; real verify times also pay for parsing, padding and dispatch.
#   scripts/mca/mca.sh [LLVM_BIN_DIR]     (default: $LLVM, then /opt/homebrew/opt/llvm/bin, then PATH)
#   MEASURED=file scripts/mca/mca.sh      + measured columns from scripts/mca/validate.sh's output
cd "$(dirname "$0")/../.." || exit 1
M=${1:-${LLVM:-/opt/homebrew/opt/llvm/bin}}
[ -x "$M/llvm-mca" ] || M=$(dirname "$(command -v llvm-mca)")
[ -x "$M/llvm-mca" ] || {
  echo "llvm-mca not found (brew install llvm, or apt install llvm)"
  exit 1
}
S=$(mktemp -d "${TMPDIR:-/tmp}/mca.XXXXXX")
trap 'rm -rf "$S"' EXIT
X86_CPUS="cascadelake icelake-server sapphirerapids graniterapids znver3 znver4 znver5 alderlake sierraforest"
ARM_CPUS="neoverse-n1 neoverse-n2 neoverse-v1 neoverse-v2 neoverse-v3 ampere1b apple-m4"
# cross-compiling needs system headers: on macOS the SDK's (Apple triples), elsewhere the host's (Linux triples)
if [ "$(uname)" = Darwin ]; then
  X86=x86_64-apple-macos13
  ARM=arm64-apple-macos13
  SYS="-isysroot $(xcrun --show-sdk-path)"
else
  X86=x86_64-linux-gnu
  ARM=aarch64-linux-gnu
  SYS=
fi
U=${UICA:-third_party/uiCA}
UPY=${PYTHON:-build/venv/bin/python} # UICA=: an existing uiCA checkout (fetch-uica.sh)
[ -x "$UPY" ] && UPY=$(cd "$(dirname "$UPY")" && pwd)/$(basename "$UPY")
for spec in "x86|$X86" "arm|$ARM"; do
  arch=${spec%%|*}
  tgt=${spec#*|}
  # baseline flags: jwt.c's own target regions give each engine its ISA, as in the library. Arm: plain armv8-a
  # like a Linux build (macOS's default CPU has SHA-3, so the compiler would fuse XORs into EOR3, which N1-N2/V2-V3 lack)
  base=-march=x86-64
  [ "$arch" = arm ] && base="-march=armv8-a -mcpu=generic" # Apple triples default to apple-m1 otherwise
  "$M/clang" -target "$tgt" $SYS -O3 -S -w $base -Iinclude scripts/mca/kernels.c -o "$S/$arch.s" || exit 1
  # each region into its own file (instructions and local labels only), so a CPU model without AVX-512 only
  # loses those regions; a region with a branch inside (a loop) is flagged: mca would count its body once
  python3 - "$S/$arch.s" "$S/$arch" "$S/loops" <<'PY'
import re, sys
keep, name, br, out = False, None, set(), {}
for l in open(sys.argv[1]):
    m = re.search(r"LLVM-MCA-(BEGIN|END) (\S+)", l)
    if m: keep, name = m.group(1) == "BEGIN", m.group(2); out.setdefault(name, []); continue
    t = l.strip()
    if keep and t and not t.startswith((".", "#", "//", ";")):
        out[name].append(l)
        if (t.endswith(":") and not t.startswith("Lloh")) or re.match(r"(j[a-z]+|b\.[a-z]+|b|cbn?z|tbn?z)\s", t): br.add(name)
for n, ls in out.items(): open(f"{sys.argv[2]}.{n}.s", "w").write("".join(ls))
with open(sys.argv[3], "a") as f:
    for n in br: f.write(n + "\n")
PY
  case "$tgt" in x86_64-apple*) mt=x86_64-linux-gnu ;; *) mt=$tgt ;; esac
  case "$arch" in x86) cpus=$X86_CPUS ;; *) cpus=$ARM_CPUS ;; esac
  for f in "$S/$arch".*.s; do
    reg=${f#"$S/$arch."}
    reg=${reg%.s}
    for c in $cpus; do
      ma=
      [ "$arch" = arm ] && ma=-mattr=+sha2 # some Arm CPU models leave the crypto extension off by default
      t=$("$M/llvm-mca" -mtriple="$mt" -mcpu="$c" $ma -iterations=100 "$f" 2>/dev/null | awk '/Block RThroughput:/{print $3}')
      [ -n "$t" ] && echo "$c $reg $t"
    done
    if [ "$arch" = x86 ] && [ -f $U/uiCA.py ] && [ -f $U/instrData/CLX_data.py ]; then # uiCA: the host's object format
      if [ "$(uname)" = Darwin ]; then ot=x86_64-apple-macos13; else ot=x86_64-linux-gnu; fi
      perl -pe 's/\bL(CPI|_)/_x$1/g; s/##.*$//' "$f" >"$S/u.s"
      "$M/llvm-mc" -triple $ot -filetype=obj "$S/u.s" -o "$S/u.o" 2>/dev/null &&
        for a in CLX ICL TGL; do t=$(cd $U && "$UPY" uiCA.py "$S/u.o" -arch $a -TPonly 2>/dev/null) && echo "uica-$a $reg $t"; done
    fi
  done
done >"$S/out"
touch "$S/loops"
[ -n "$MEASURED" ] && grep -v '^#' "$MEASURED" | awk '{print "measured-" $2, $1, $3}' >>"$S/out"
python3 - "$S/out" "$S/loops" <<'PY'
import re, sys, collections
loops = {l.strip() for l in open(sys.argv[2])}
d = collections.OrderedDict(); cpus = []
for l in open(sys.argv[1]):
    cpu, reg, t = l.split()
    lanes = int(re.match(r"x(\d+)_", reg).group(1)) if re.match(r"x(\d+)_", reg) else 1
    d.setdefault(reg, {})[cpu] = float(t) / (lanes * 64)
    if cpu not in cpus: cpus.append(cpu)
kind = lambda c: "arm" if c.startswith(("neoverse", "ampere", "apple")) else "uica" if c.startswith("uica") else "meas" if c.startswith("measured") else "x86"
for arch in ("x86", "uica", "arm"):
    cs = [c for c in cpus if kind(c) == "meas" and arch != "arm"] + [c for c in cpus if kind(c) == arch]
    if not any(kind(c) == arch for c in cs): continue
    same = {}
    for i, c in enumerate(cs):
        for e in cs[:i]:
            if kind(c) == kind(e) and all(v.get(c) == v.get(e) for v in d.values()) and e not in same: same[c] = e; break
    print(f"\n{'cycles per byte per message':28s}" + "".join(f"{c[:13]:>14s}" for c in cs))
    for reg, v in d.items():
        if reg == "empty" or not any(c in v and kind(c) == arch for c in cs): continue
        print(f"{reg + (' *' if reg in loops else ''):28s}" + "".join(f"{v[c]:14.2f}" if c in v else f"{'-':>14s}" for c in cs))
    for c, e in same.items(): print(f"  {c}: same numbers as {e} ({'uiCA' if arch == 'uica' else 'LLVM'} has no separate model for it)")
print("\nrows: x<lanes>_<engine>, one 64-byte block per lane; * = the region has a branch (mca counts a loop body once)")
PY
