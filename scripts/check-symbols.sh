#!/usr/bin/env bash
# check-symbols.sh [--cc-only] ARCHIVE...: every global symbol an archive defines must be cursed-crypto's (cc_*) or
# cursed-jwt's (jwt_*), so the libraries link statically next to OpenSSL, AWS-LC, crypto_mb or s2n-bignum without a
# clash.  --cc-only: cc_* only (cursed-crypto's own archive: the jwt_* names belong to the JWT layer).
set -euo pipefail
NM="${NM:-nm}"
bad=0
ok='^(cc_|jwt_)' what='cc_* / jwt_*'
if [ "${1:-}" = --cc-only ]; then
  ok='^cc_' what='cc_*'
  shift
fi
for a in "$@"; do
  # defined globals only; Mach-O prefixes every C name with an underscore
  syms=$("$NM" -g --defined-only "$a" 2>/dev/null || "$NM" -g -U "$a")
  out=$(echo "$syms" | awk 'NF >= 3 {print $NF}' | sed 's/^_//' | grep -v -E "$ok" || true)
  n=$(echo "$syms" | awk 'NF >= 3' | wc -l | tr -d ' ')
  if [ -n "$out" ]; then
    echo "check-symbols: $a exports symbols outside $what:"
    echo "$out" | sed 's/^/  /'
    bad=1
  else
    echo "check-symbols: $a: $n globals, all $what"
  fi
done
exit $bad
