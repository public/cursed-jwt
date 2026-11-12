#!/bin/sh
# fuzz.sh [amd64|arm64] [seconds per harness] — coverage-guided fuzzing (libFuzzer + ASan + UBSan, clang 18) of the
# harnesses in fuzz/, in the Ubuntu 24.04 test image.  The checkout is mounted read-only; corpora, crashes and logs
# go to build/fuzz-<arch>/ (kept between runs, so each run starts from the last one's corpus).
#   verify      HS256: every engine and batch split agree, fast JSON paths == strict parser, result invariants
#   b64         base64url: SIMD == scalar == an RFC 4648 reference
#   sign        signing: payload checks agree with the verifier both ways, engines / batch splits agree, the encoder
#   pk, pk_screen, pk_ossl   RS256 / ES256 (portable C, screening, libcrypto BN) vs OpenSSL's verdict
# DOCKER_CPUS (default 8-13) pins the container; JOBS (default 1) parallel workers per harness.  The defaults are a smoke run (~1 min);
# use e.g. `JOBS=6 ./scripts/fuzz.sh arm64 600` for a real campaign.
set -e
cd "$(dirname "$0")/.."
ARCH=${1:-$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')}
SECS=${2:-10}
OUT=build/fuzz-$ARCH
mkdir -p "$OUT"
python3 -I fuzz/seeds.py "$OUT/seeds" >/dev/null
IMG=cursed-jwt-test:$ARCH
docker build -q --platform linux/$ARCH -t $IMG ci >/dev/null
docker run --rm --platform linux/$ARCH --cpuset-cpus "${DOCKER_CPUS:-8-13}" -v "$PWD":/src:ro -v "$PWD/$OUT":/out $IMG sh -c "
  set -e; cd /src
  case \$(uname -m) in x86_64) A='-march=haswell -DJWT_OSSL_SHA256'; S=crypto/src/sha256_x86_64_ossl.S;; *) A='-march=armv8.2-a+crypto+sha3'; S=;; esac
  F=\"-O1 -g -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all -w -Iinclude -Isrc -Itests \$A\"
  PK=''
  clang \$F fuzz/fuzz_verify.c \$S -lcrypto -o /tmp/verify
  clang \$F fuzz/fuzz_b64.c \$S -o /tmp/b64
  clang \$F fuzz/fuzz_sign.c \$S -o /tmp/sign
  clang \$F \$PK fuzz/fuzz_pk.c \$S -lcrypto -o /tmp/pk
  clang \$F \$PK -DJWT_RSA_SCREEN fuzz/fuzz_pk.c \$S -lcrypto -o /tmp/pk_screen
  clang \$F \$PK -DJWT_OPENSSL fuzz/fuzz_pk.c \$S -lcrypto -o /tmp/pk_ossl
  for h in verify b64 sign pk pk_screen pk_ossl; do
    seed=\${h%%_*}; mkdir -p /out/corpus/\$seed /out/crash-\$h
    echo \"== \$h (\$(uname -m), ${SECS} s)\"
    cd /out && ASAN_OPTIONS=detect_leaks=0 /tmp/\$h -max_total_time=$SECS -jobs=${JOBS:-1} -workers=${JOBS:-1} -max_len=12000 \
      -artifact_prefix=/out/crash-\$h/ /out/corpus/\$seed /out/seeds/\$seed > /out/\$h.log 2>&1 || { echo \"   FAILED: see $OUT/\$h.log\"; continue; }
    cat /out/fuzz-*.log > /out/\$h.workers.log 2>/dev/null; rm -f /out/fuzz-*.log
    echo \"   runs: \$(grep -ho 'Done [0-9]* runs' /out/\$h.workers.log | awk '{s+=\$2} END{print s+0}'), coverage: \$(grep -o 'cov: [0-9]*' /out/\$h.workers.log | tail -1)\"
    echo \"   corpus: \$(ls /out/corpus/\$seed | wc -l) inputs, crashes: \$(ls /out/crash-\$h | wc -l)\"
  done"
