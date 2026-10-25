#!/bin/sh
# validate.sh - measures what mca.sh estimates, on the machine it runs on (x86-64 Linux with perf): each SHA-256
# engine's compress (scripts/mca/kernels.c), N back-to-back calls on L1-hot state under `perf stat -e cycles`,
# minus the empty kernel's call overhead, in both modes of kbench.c: chain (one message's blocks: latency) and
# indep (four streams in turn: what mca's throughput assumes). Prints "kernel mode cycles-per-call" lines:
#   scripts/mca/validate.sh > measured.txt          (perf needs perf_event_paranoid <= 2 or root)
#   MEASURED=measured.txt scripts/mca/mca.sh        adds measured-chain / measured-indep columns
# The README's calibration table is this script on a Xeon Platinum 8260, clang 18. Pin it (taskset -c N) on a busy box.
cd "$(dirname "$0")/../.."
CC=${CC:-$(command -v clang || command -v gcc)}; N=${N:-2000000}
command -v perf >/dev/null || { echo "perf not found" >&2; exit 1; }
case "$(uname -m)" in x86_64) ;; *) echo "validate.sh: x86-64 only (the engines below are x86)" >&2; exit 1;; esac
S=$(mktemp -d "${TMPDIR:-/tmp}/kb.XXXXXX"); trap 'rm -rf "$S"' EXIT
echo "# $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //'); $($CC --version | head -1)" >&2
$CC -O3 -w -march=x86-64 -Iinclude scripts/mca/kbench.c -o "$S/kb" || exit 1   # jwt.c's target regions, as in the library
cyc() { perf stat -x, -e cycles "$S/kb" "$1" "$N" "$2" 2>&1 >/dev/null | awk -F, '/cycles/{print $1}'; }
for mode in chain indep; do
  base=$(cyc empty $mode)
  for k in x1_scalar x8_avx2 x16_avx2x2 x8_avx512 x16_avx512x2 x16_zmm; do
    case "$k" in *avx512*|*zmm) grep -q avx512bw /proc/cpuinfo || continue;; esac
    c=$(cyc "$k" $mode); [ -n "$c" ] && echo "$k $mode $(awk -v c="$c" -v b="$base" -v n="$N" 'BEGIN{printf "%.1f", (c - b) / n}')"
  done
done
