#!/bin/sh
# build-deps.sh: build abseil, protobuf and BoringSSL (the versions ./fetch.sh deps pins, i.e. Envoy v1.40.2's) as
# static libraries into build/<arch>/prefix, for the differential test and the benchmark (not the filter).
# Needs cmake and ninja (the Dockerfile here has them).  -O2 like Envoy's `-c opt` release build.  JOBS defaults to 4.
set -e
cd "$(dirname "$0")"
A=$(uname -m)
P=$PWD/build/$A/prefix
W=$PWD/build/$A/deps
J=${JOBS:-4}
mkdir -p "$P" "$W"
C="-DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS_RELEASE=-O2 -DCMAKE_CXX_FLAGS_RELEASE=-O2 -DCMAKE_CXX_STANDARD=20
   -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_INSTALL_PREFIX=$P -DCMAKE_PREFIX_PATH=$P -G Ninja"
if [ ! -f "$P/.abseil" ]; then
  cmake -S third_party/abseil -B "$W/abseil" $C -DABSL_PROPAGATE_CXX_STD=ON -DABSL_BUILD_TESTING=OFF >/dev/null
  ninja -C "$W/abseil" -j"$J" install >/dev/null && touch "$P/.abseil"
fi
if [ ! -f "$P/.protobuf" ]; then
  cmake -S third_party/protobuf -B "$W/protobuf" $C -Dprotobuf_BUILD_TESTS=OFF -Dprotobuf_ABSL_PROVIDER=package \
    -Dprotobuf_BUILD_PROTOC_BINARIES=OFF -Dprotobuf_BUILD_LIBUPB=OFF -Dprotobuf_INSTALL=ON >/dev/null
  ninja -C "$W/protobuf" -j"$J" install >/dev/null && touch "$P/.protobuf"
fi
if [ ! -f "$P/.boringssl" ]; then
  cmake -S third_party/boringssl -B "$W/boringssl" $C -DBUILD_TESTING=OFF >/dev/null
  ninja -C "$W/boringssl" -j"$J" crypto >/dev/null
  mkdir -p "$P/bssl/lib" && cp "$W/boringssl/libcrypto.a" "$P/bssl/lib/" && cp -r third_party/boringssl/include "$P/bssl/"
  touch "$P/.boringssl"
fi
echo "deps in $P"
