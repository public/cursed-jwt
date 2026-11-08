# CodSpeed benchmarks (Google Benchmark, CodSpeed's fork); see README.md, Benchmarks.
#   cmake -S bench/codspeed -B build/codspeed -DCMAKE_BUILD_TYPE=Release -DCODSPEED_MODE=simulation
#   cmake --build build/codspeed -j && codspeed run -m simulation -- ./build/codspeed/bench_codspeed
cmake_minimum_required(VERSION 3.16)
project(cursed_jwt_codspeed LANGUAGES C CXX ASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

include(FetchContent)
set(BENCHMARK_DOWNLOAD_DEPENDENCIES ON)
set(BENCHMARK_ENABLE_TESTING OFF)
FetchContent_Declare(
  google_benchmark
  GIT_REPOSITORY https://github.com/CodSpeedHQ/codspeed-cpp
  GIT_TAG v2.4.0
  SOURCE_SUBDIR google_benchmark)
FetchContent_MakeAvailable(google_benchmark)

set(ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)

# The library exactly as the Makefile builds it: baseline ISA, engines picked at run time from the CPU, and on
# x86-64 Linux OpenSSL's extracted SHA-256 block function for batch 1 / leftover lanes and the SHA-NI kernels.
add_library(cursedjwt STATIC ${ROOT}/src/jwt.c)
target_include_directories(cursedjwt PUBLIC ${ROOT}/include PRIVATE ${ROOT}/src)
target_compile_options(cursedjwt PRIVATE -O3 -g)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64" AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_sources(cursedjwt PRIVATE ${ROOT}/src/sha256_x86_64_ossl.S ${ROOT}/src/sha256_shani_mb.S
                                   ${ROOT}/src/sha256_x16_avx512.S)
  target_compile_definitions(cursedjwt PUBLIC JWT_OSSL_SHA256 JWT_SHANI_MB)
endif()

add_executable(bench_codspeed bench_codspeed.cpp)
target_link_libraries(bench_codspeed PRIVATE cursedjwt benchmark::benchmark)
