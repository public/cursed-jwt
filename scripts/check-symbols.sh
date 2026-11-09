#!/usr/bin/env bash
# check-symbols.sh ARCHIVE...: every global symbol an archive defines must be cursed-crypto's (cc_*) or cursed-jwt's
# (jwt_*), so the libraries link statically next to OpenSSL, AWS-LC, crypto_mb or s2n-bignum without a clash.
set -euo pipefail
NM="${NM:-nm}"
bad=0
for a in "$@"; do
  # defined globals only; Mach-O prefixes every C name with an underscore
  syms=$("$NM" -g --defined-only "$a" 2>/dev/null || "$NM" -g -U "$a")
  out=$(echo "$syms" | awk 'NF >= 3 {print $NF}' | sed 's/^_//' | grep -v -E '^(cc_|jwt_)' || true)
  n=$(echo "$syms" | awk 'NF >= 3' | wc -l | tr -d ' ')
  if [ -n "$out" ]; then
    echo "check-symbols: $a exports symbols outside cc_* / jwt_*:"
    echo "$out" | sed 's/^/  /'
    bad=1
  else
    echo "check-symbols: $a: $n globals, all cc_* / jwt_*"
  fi
done
exit $bad
