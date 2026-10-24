# cursed-jwt
#   make              build/libcursedjwt.a + build/verify (the library has no dependencies)
#   make test         differential test vs OpenSSL (needs libcrypto: Homebrew openssl@3 / libssl-dev)
#   make test-quick   the same with fewer random iterations (CI)
#   make asan         ASan + UBSan build of the test (quick mode)
#   make bench        ns/token per engine and batch size, vs OpenSSL
#   make avx512       real AVX-512VL build of the test and bench (run them on an AVX-512 CPU)
#   make licence      AVX-512 frequency-licence probe (meaningful only on AVX-512 hardware)
# Engine selection is compile-time, from ARCHFLAGS (see README.md).
CC ?= cc
PYTHON ?= python3
B := build
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
ARCHFLAGS ?= -march=haswell
else ifeq ($(UNAME_M),aarch64)
ARCHFLAGS ?= -march=armv8.2-a+crypto+sha3
else ifeq ($(UNAME_M),arm64)
ARCHFLAGS ?= -mcpu=native
endif
SSLDIR := $(shell brew --prefix openssl@3 2>/dev/null)
ifneq ($(SSLDIR),)
SSLINC := -I$(SSLDIR)/include
SSLLIB := -L$(SSLDIR)/lib
endif
CFLAGS ?= -O3
WARN := -Wall -Wextra -Wno-deprecated-declarations -Wno-unused-function
INC := -Iinclude -Isrc -Itests
SRC := src/jwt.c src/jwt_mb.inc include/jwt.h
SAN := -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
TEST_SECRET := cursed-jwt-test-secret
NTOKENS ?= 20000

all: $(B)/libcursedjwt.a $(B)/verify

$(B):
	mkdir -p $(B)
$(B)/jwt.o: $(SRC) | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(WARN) -Iinclude -c src/jwt.c -o $@
$(B)/libcursedjwt.a: $(B)/jwt.o
	ar rcs $@ $<
$(B)/verify: examples/verify.c $(B)/libcursedjwt.a
	$(CC) $(CFLAGS) $(WARN) -Iinclude $< $(B)/libcursedjwt.a -o $@

# test tokens: deterministic, generated with Python's hmac module (an independent HS256 implementation)
$(B)/tokens.json: tests/gen_tokens.py | $(B)
	$(PYTHON) tests/gen_tokens.py $(TEST_SECRET) $(NTOKENS) > $@

$(B)/test_jwt: tests/test_jwt.c tests/ossl_min.h $(SRC) | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(WARN) $(INC) -include stdarg.h $(SSLINC) $< $(SSLLIB) -lcrypto -o $@
$(B)/asan_jwt: tests/test_jwt.c tests/ossl_min.h $(SRC) | $(B)
	$(CC) $(SAN) $(ARCHFLAGS) $(WARN) $(INC) -include stdarg.h $(SSLINC) $< $(SSLLIB) -lcrypto -o $@
$(B)/bench_jwt: bench/bench_jwt.c tests/ossl_min.h $(SRC) | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(WARN) $(INC) $(SSLINC) $< $(SSLLIB) -lcrypto -o $@

# the example must accept a generated token and reject a tampered one
example-check: $(B)/verify $(B)/tokens.json
	@t=$$($(PYTHON) -c "import json;print(json.load(open('$(B)/tokens.json'))[0]['token'])"); \
	  ./$(B)/verify $(TEST_SECRET) $$t | grep -q "OK sub=1 " && \
	  ! ./$(B)/verify $(TEST_SECRET) $${t%?}A >/dev/null && echo "example: OK"

test: $(B)/test_jwt $(B)/tokens.json example-check
	./$(B)/test_jwt $(B)/tokens.json
test-quick: $(B)/test_jwt $(B)/tokens.json example-check
	JWT_TEST_QUICK=1 ./$(B)/test_jwt $(B)/tokens.json
asan: $(B)/asan_jwt $(B)/tokens.json
	ASAN_OPTIONS=detect_leaks=0 JWT_TEST_QUICK=1 ./$(B)/asan_jwt $(B)/tokens.json
bench: $(B)/bench_jwt $(B)/tokens.json
	./$(B)/bench_jwt $(B)/tokens.json

AVX512 := -march=cascadelake -DJWT_AVX512
avx512: tests/test_jwt.c bench/bench_jwt.c $(SRC) | $(B)
	$(CC) $(CFLAGS) $(AVX512) $(WARN) $(INC) -include stdarg.h $(SSLINC) tests/test_jwt.c $(SSLLIB) -lcrypto -o $(B)/test_jwt_avx512
	$(CC) $(CFLAGS) $(AVX512) $(WARN) $(INC) $(SSLINC) bench/bench_jwt.c $(SSLLIB) -lcrypto -o $(B)/bench_jwt_avx512
	@echo "vprord/vpternlogd in the test binary: $$(objdump -d $(B)/test_jwt_avx512 | grep -c -E 'vprord|vpternlogd')"
licence: bench/licence_probe.c $(SRC) | $(B)
	$(CC) $(CFLAGS) $(AVX512) $(WARN) $(INC) $< -o $(B)/licence_probe && ./$(B)/licence_probe

clean:
	rm -rf $(B)
.PHONY: all test test-quick asan bench avx512 licence example-check clean
