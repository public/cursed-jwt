#!/bin/sh
# ct-trace.sh SDE CT_TRACE [ENGINES]: trace-equivalence constant-time check of the HMAC engines under Intel SDE (see
# tests/ct_trace.c). Emulates Ice Lake server (-icx: AVX-512 and SHA-NI). Fails if any engine's trace under two keys
# differs, or if the leaky control's doesn't.
set -eu
SDE="$1" BIN="$2"
ENGINES="${3:-scalar ossl avx2 avx2x2 shani_1 shani_2 shani_4 avx512 zmm}"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
norm() { # control flow (instruction address + disassembly) and memory addresses; every data value dropped
  awk '/^INS /{sub(/ *\|.*/,""); print; next}
         /^(Read|Write) /{if (match($0,/\*\([A-Z0-9_]+\*\)0x[0-9a-f]+/)) print $1, substr($0,RSTART,RLENGTH)}' "$1"
}
trace() { # trace ENGINE KEY BATCH OUT
  setarch -R "$SDE" -icx -debugtrace -dt_out "$T/raw" -start_ssc_mark 111 -stop_ssc_mark 222 -- "$BIN" "$1" "$2" "$3" \
    >/dev/null || [ "$1" = leaky ]
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
  "$SDE" -icx -- "$BIN" "$e" 0 1 >/dev/null 2>&1 || {
    echo "ct-trace: $e not in this build, skipped"
    continue
  }
  for n in 1 3 16; do
    trace "$e" 0 "$n" "$T/a" && trace "$e" 1 "$n" "$T/b"
    if cmp -s "$T/a" "$T/b"; then
      echo "ct-trace: $e b$n: identical ($(grep -c '^INS' "$T/a") instructions, $(grep -c -v '^INS' "$T/a") memory accesses)"
    else
      echo "ct-trace: $e b$n: TRACES DIFFER"
      diff "$T/a" "$T/b" | head -6
      fail=1
    fi
  done
done
exit $fail
