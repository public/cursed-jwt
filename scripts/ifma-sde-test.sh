#!/bin/sh
# ifma-sde-test.sh — run the AVX-512 IFMA public-key tests under Intel SDE with FAST_ZMM forced, so the IFMA RSA
# kernels are exercised on a machine without an IFMA/FAST_ZMM CPU (CI runners, this developer box). Needs sde64 on
# PATH (Intel SDE) and the usual build deps (libssl-dev). The build and run commands are the ones the Makefile uses.
#
#   SDE=sde64 ./scripts/ifma-sde-test.sh      # or set SDE to the full path
# Validated locally at SDE 10.13.1: test_rsaz 3122 cases, test_pk_rsaz8 49360/49360.
set -e
SDE="${SDE:-sde64}"
command -v "$SDE" >/dev/null 2>&1 || { echo "ifma-sde-test: '$SDE' not found on PATH (install Intel SDE)"; exit 2; }
make build/test_rsaz build/test_rsaz8 build/test_pk_rsaz8 build/pk_vectors.txt
echo "== RSAZ (OpenSSL IFMA almost-mont) vs BN_mod_exp =="
"$SDE" -icx -- env JWT_CPU_FORCE_ZMM=1 ./build/test_rsaz 2 20
echo "== RSAZ8 (crypto_mb 8-lane IFMA) vs BN_mod_exp =="
"$SDE" -icx -- env JWT_CPU_FORCE_ZMM=1 ./build/test_rsaz8 2 20
echo "== full RS256/ES256/EdDSA suite on the 8-lane path =="
"$SDE" -icx -- env JWT_CPU_FORCE_ZMM=1 ./build/test_pk_rsaz8 build/pk_vectors.txt
