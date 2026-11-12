#!/bin/sh
# Trace-equivalence constant-time check of the HMAC engines and of signing (see tests/ct_trace.c). Each engine runs
# under two keys at batch 1, 3 and 16 (signing Ed25519: 1 and 3); the run fails if any engine's instruction / memory-
# address trace differs between the keys, or if the leaky control's doesn't.
#
#   ct-trace.sh SDE CT_TRACE [ENGINES]                 x86-64 under Intel SDE (-icx: AVX-512 and SHA-NI)
#   ct-trace.sh --qemu QEMU EXECLOG CT_TRACE [ENGINES] AArch64 under qemu-aarch64 with its execlog plugin (a static,
#                                                      non-PIE CT_TRACE; the plugin logs no data values)
set -eu
if [ "$1" = --qemu ]; then
  MODE=qemu QEMU="$2" EXECLOG="$3" BIN="$4"
  shift 4
  ENGINES="${1:-scalar neon sha2_1 sha2_2 sha2 verify sign_hs sign_ed sign_es}"
  NM="${NM:-aarch64-linux-gnu-nm}"
  # execlog prints each pc as 0x%x; nm pads to 16 digits
  BEGIN="0x$("$NM" "$BIN" | awk '$3=="ct_trace_begin"{print $1}' | sed 's/^0*//')"
  END="0x$("$NM" "$BIN" | awk '$3=="ct_trace_end"{print $1}' | sed 's/^0*//')"
  if [ "$BEGIN" = 0x ] || [ "$END" = 0x ]; then
    echo "ct-trace: no ct_trace_begin / ct_trace_end symbols in $BIN"
    exit 2
  fi
else
  MODE=sde SDE="$1" BIN="$2"
  ENGINES="${3:-scalar ossl avx2 shani_1 shani_2 shani_4 avx512 zmm shani_4r x16 shani_x16 verify sign_hs sign_ed sign_es}"
fi
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
run() { # run ARGS...: the binary under the emulator, no tracing
  if [ $MODE = qemu ]; then "$QEMU" "$BIN" "$@"; else "$SDE" -icx -- "$BIN" "$@"; fi
}
norm() { # control flow (instruction address + disassembly) and memory addresses; every data value dropped
  if [ $MODE = qemu ]; then
    # lines are: cpu, pc, opcode, "disas"[, load|store, addr]... (no values); cut at the two markers
    awk -F', ' -v b="$BEGIN" -v e="$END" '$2==b{on=1; next} $2==e{exit} on' "$1"
  else
    awk '/^INS /{sub(/ *\|.*/,""); print; next}
         /^(Read|Write) /{if (match($0,/\*\([A-Z0-9_]+\*\)0x[0-9a-f]+/)) print $1, substr($0,RSTART,RLENGTH)}' "$1"
  fi
}
counts() { # counts FILE: instructions and memory accesses in a normalised trace
  if [ $MODE = qemu ]; then
    echo "$(wc -l <"$1") instructions, $(grep -o -E ', (load|store), ' "$1" | wc -l) memory accesses"
  else
    echo "$(grep -c '^INS' "$1") instructions, $(grep -c -v '^INS' "$1") memory accesses"
  fi
}
trace() { # trace ENGINE KEY BATCH OUT
  if [ $MODE = qemu ]; then
    "$QEMU" -plugin "$EXECLOG" -d plugin -D "$T/raw" "$BIN" "$1" "$2" "$3" >/dev/null || [ "$1" = leaky ]
  else
    setarch -R "$SDE" -icx -debugtrace -dt_out "$T/raw" -start_ssc_mark 111 -stop_ssc_mark 222 -- "$BIN" "$1" "$2" \
      "$3" >/dev/null || [ "$1" = leaky ]
  fi
  norm "$T/raw" >"$4"
}
fail=0
trace leaky 0 1 "$T/a" && trace leaky 1 1 "$T/b"
if cmp -s "$T/a" "$T/b"; then
  echo "ct-trace: the leaky control's traces are identical: the method is broken"
  exit 1
fi
echo "ct-trace: leaky control differs (as it must)"
for e in $ENGINES; do
  run "$e" 0 1 >/dev/null 2>&1 || {
    echo "ct-trace: $e not in this build, skipped"
    continue
  }
  case $e in
    sign_ed | sign_es) ns="1 3" ;; # ~1M instructions per signature with key setup: batch 3 already covers the batched inversion
    *) ns="1 3 16" ;;
  esac
  for n in $ns; do
    trace "$e" 0 "$n" "$T/a" && trace "$e" 1 "$n" "$T/b"
    if [ ! -s "$T/a" ]; then
      echo "ct-trace: $e b$n: EMPTY TRACE"
      fail=1
    elif cmp -s "$T/a" "$T/b"; then
      echo "ct-trace: $e b$n: identical ($(counts "$T/a"))"
    else
      echo "ct-trace: $e b$n: TRACES DIFFER"
      diff "$T/a" "$T/b" | head -6
      fail=1
    fi
  done
done
exit $fail
