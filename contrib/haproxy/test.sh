#!/usr/bin/env bash
# test.sh: builds the patched HAProxy with its unit tests, then checks it against itself with the cursed paths
# off (the stock code) and against HAProxy's own JWT regtests.
#   1. haproxy -U jwt-diff: stock and cursed jwt_verify / jwt_header_query / jwt_payload_query results on every
#      token from gen_tokens.py (signed by pyca/cryptography, i.e. neither verifier) and random mutants of each,
#      plus a base64url differential on random strings. Any mismatch fails.
#   2. reg-tests/jwt/*.vtc under VTest2 (fetched at a pinned commit), the cursed build as HAPROXY_PROGRAM.
# Needs what build.sh needs, python3 with cryptography (python3-cryptography), git, and libpcre2-dev for VTest2.
#   MUTANTS  mutants per token for jwt-diff (default 300)
#   NO_VTEST=1 skips step 2
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
O="$HERE/build"
UNIT=1 "$HERE/build.sh" cursed
H="$O/cursed/haproxy"
R="$O/run"
mkdir -p "$R"
python3 -I "$HERE/gen_tokens.py" "$R" >/dev/null
"$H" -U jwt-diff "$R/diff.txt" "${MUTANTS:-300}" | tee "$R/jwt-diff.txt"
[ "$(grep -c ' 0 mismatches' "$R/jwt-diff.txt")" = 2 ] || { echo "jwt-diff: mismatches" >&2 && exit 1; }

[ "${NO_VTEST:-0}" = 1 ] && exit 0
VTEST_REPO=https://github.com/vtest/VTest2.git # tag "last", the final GitHub release before VTest2 moved
VTEST_COMMIT=803dcd000b1328f6e766774e23aedbd7f53e7d97
if ! git -C "$O/VTest2" cat-file -e "$VTEST_COMMIT" 2>/dev/null; then
  rm -rf "$O/VTest2"
  git clone -q "$VTEST_REPO" "$O/VTest2"
fi
git -C "$O/VTest2" -c advice.detachedHead=false checkout -q "$VTEST_COMMIT"
[ -x "$O/VTest2/vtest" ] || make -s -C "$O/VTest2" FLAGS="-O2 -s -Wall"
cd "$O/cursed"
VTEST_PROGRAM="$O/VTest2/vtest" HAPROXY_PROGRAM="$H" ./scripts/run-regtests.sh reg-tests/jwt
