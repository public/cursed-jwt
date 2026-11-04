# Build and test image for contrib/envoy: Ubuntu 24.04 (Envoy's release images use it too) with clang 18, cmake and
# ninja (for ./build-deps.sh), python3-cryptography (test tokens), compiler-rt (make asan) and curl (the functional test's client).
FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    clang-18 lld-18 libclang-rt-18-dev make cmake ninja-build python3 python3-cryptography curl ca-certificates git perl golang-go \
    && rm -rf /var/lib/apt/lists/*
ENV CC=clang-18 CXX=clang++-18
