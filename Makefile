# cursed-jwt
#   make              build/libcursedjwt.a + build/verify (the library has no dependencies)
#   make test         differential test vs OpenSSL (needs libcrypto: Homebrew openssl@3 / libssl-dev)
#   make test-quick   the same with fewer random iterations (CI)
#   make test-vectors + RFC 4231, NIST CAVP, Wycheproof, RFC 7515 and pyca/cryptography vectors (network)
#   make asan         ASan + UBSan build of the test (quick mode)
#   make bench        ns/token per engine and batch size, vs OpenSSL
#   make compare      full verify vs jwt-cpp and golang-jwt (fetched at pinned commits; go optional)
#   make avx512       real AVX-512VL build of the test and bench (run them on an AVX-512 CPU)
#   make licence      AVX-512 frequency-licence probe (meaningful only on AVX-512 hardware)
#   make pk-test      RS256 / ES256 prototype (-DJWT_PK) vs Wycheproof, NIST CAVP, RFC 7515, pyca (network)
#   make pk-bench     RS256 / ES256 ns/token vs OpenSSL (network for the fiat-crypto fetch)
#   make pk-test-s2n / pk-bench-s2n   the same with s2n-bignum's verified asm kernels (-DJWT_S2N; fetched pinned)
#   make pk-test-fast / pk-bench-fast s2n-bignum for P-256 + OpenSSL's BN asm for RSA (-DJWT_S2N -DJWT_OPENSSL)
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

# external vectors (network): RFC 4231, NIST CAVP, Wycheproof, RFC 7515 + random cases from pyca/cryptography.
# Uses python3's cryptography if importable, else installs it into build/venv.
VECTORS_N ?= 5000
$(B)/pyenv: | $(B)
	@if $(PYTHON) -c "import cryptography" 2>/dev/null; then echo $(PYTHON) > $@; \
	  else $(PYTHON) -m venv $(B)/venv && $(B)/venv/bin/pip -q install cryptography && echo $(B)/venv/bin/python > $@; fi
$(B)/hmac_vectors.txt: tests/make_vectors.py scripts/fetch-vectors.sh $(B)/pyenv
	./scripts/fetch-vectors.sh
	$$(cat $(B)/pyenv) tests/make_vectors.py third_party/vectors $(VECTORS_N) 1 > $@
test-vectors: $(B)/test_jwt $(B)/tokens.json $(B)/hmac_vectors.txt
	JWT_TEST_QUICK=1 ./$(B)/test_jwt $(B)/tokens.json $(B)/hmac_vectors.txt

test: $(B)/test_jwt $(B)/tokens.json example-check
	./$(B)/test_jwt $(B)/tokens.json
test-quick: $(B)/test_jwt $(B)/tokens.json example-check
	JWT_TEST_QUICK=1 ./$(B)/test_jwt $(B)/tokens.json
asan: $(B)/asan_jwt $(B)/tokens.json
	ASAN_OPTIONS=detect_leaks=0 JWT_TEST_QUICK=1 ./$(B)/asan_jwt $(B)/tokens.json
bench: $(B)/bench_jwt $(B)/tokens.json
	./$(B)/bench_jwt $(B)/tokens.json

# comparison vs jwt-cpp (C++) and golang-jwt v5 (Go, if `go` is installed), fetched at pinned commits (network)
CXX ?= c++
compare: $(B)/tokens.json $(SRC) | $(B)
	./scripts/fetch-compare.sh
	$(CC) $(CFLAGS) $(ARCHFLAGS) -w $(INC) bench/compare/e2e.c -o $(B)/compare_e2e
	$(CC) $(CFLAGS) $(ARCHFLAGS) -w $(INC) -DJWT_NO_SHAPE_JSON bench/compare/e2e.c -o $(B)/compare_e2e_strict
	$(CXX) -O3 $(ARCHFLAGS) -std=c++17 -w -Ithird_party/jwt-cpp/include $(SSLINC) bench/compare/jwtcpp_bench.cpp $(SSLLIB) -lcrypto -o $(B)/compare_jwtcpp
	./$(B)/compare_e2e $(B)/tokens.json
	./$(B)/compare_e2e_strict $(B)/tokens.json
	./$(B)/compare_jwtcpp $(B)/tokens.json
	@if command -v go >/dev/null; then (cd bench/compare/go && GOFLAGS=-mod=mod go build -o ../../../$(B)/compare_gojwt .) && ./$(B)/compare_gojwt $(B)/tokens.json; \
	  else echo "golang-jwt: skipped (no go toolchain)"; fi

AVX512 := -march=cascadelake -DJWT_AVX512
avx512: tests/test_jwt.c bench/bench_jwt.c $(SRC) | $(B)
	$(CC) $(CFLAGS) $(AVX512) $(WARN) $(INC) -include stdarg.h $(SSLINC) tests/test_jwt.c $(SSLLIB) -lcrypto -o $(B)/test_jwt_avx512
	$(CC) $(CFLAGS) $(AVX512) $(WARN) $(INC) $(SSLINC) bench/bench_jwt.c $(SSLLIB) -lcrypto -o $(B)/bench_jwt_avx512
	@echo "vprord/vpternlogd in the test binary: $$(objdump -d $(B)/test_jwt_avx512 | grep -c -E 'vprord|vpternlogd')"
licence: bench/licence_probe.c $(SRC) | $(B)
	$(CC) $(CFLAGS) $(AVX512) $(WARN) $(INC) $< -o $(B)/licence_probe && ./$(B)/licence_probe

# RS256 / ES256 prototype (src/jwt_pk.inc, PK.md): needs fiat-crypto's P-256 arithmetic, fetched at a pinned commit
PK := -DJWT_PK -Ithird_party/fiat
PKSRC := $(SRC) src/jwt_pk.inc third_party/fiat/p256_64.c
third_party/fiat/p256_64.c: scripts/fetch-fiat.sh
	./scripts/fetch-fiat.sh
# -DJWT_S2N: AWS s2n-bignum's verified asm for the P-256 field and RSA-2048 Montgomery kernels (fetched pinned)
S2N_ARCH := $(if $(filter x86_64,$(UNAME_M)),x86,arm)
S2N_FILES := p256/bignum_montmul_p256 p256/bignum_montsqr_p256 p256/bignum_add_p256 p256/bignum_sub_p256 \
             fastmul/bignum_kmul_32_64 fastmul/bignum_ksqr_32_64 fastmul/bignum_emontredc_8n
S2N := -DJWT_S2N $(B)/libs2n.a
$(B)/libs2n.a: scripts/fetch-s2n-bignum.sh | $(B)
	./scripts/fetch-s2n-bignum.sh
	mkdir -p $(B)/s2n
	for f in $(S2N_FILES); do $(CC) -c -DS2N_BN_HIDE_SYMBOLS=1 -Ithird_party/s2n-bignum/include \
	  third_party/s2n-bignum/$(S2N_ARCH)/$$f.S -o $(B)/s2n/$${f#*/}.o || exit 1; done
	rm -f $@ && ar rcs $@ $(addprefix $(B)/s2n/,$(addsuffix .o,$(notdir $(S2N_FILES))))
$(B)/test_pk_s2n: tests/test_pk.c $(PKSRC) $(B)/libs2n.a | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(WARN) $(INC) $(PK) $< $(S2N) -o $@
$(B)/test_pk_s2n_screen: tests/test_pk.c $(PKSRC) $(B)/libs2n.a | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(WARN) $(INC) $(PK) -DJWT_RSA_SCREEN $< $(S2N) -o $@
$(B)/bench_pk_s2n: bench/bench_pk.c $(PKSRC) $(B)/libs2n.a | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(WARN) $(INC) $(PK) $(SSLINC) $< $(S2N) $(SSLLIB) -lcrypto -o $@
$(B)/bench_pk_s2n_screen: bench/bench_pk.c $(PKSRC) $(B)/libs2n.a | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(WARN) $(INC) $(PK) -DJWT_RSA_SCREEN $(SSLINC) $< $(S2N) $(SSLLIB) -lcrypto -o $@
# -DJWT_OPENSSL: RSA arithmetic through libcrypto's BN_mod_exp_mont / BN_mod_mul_montgomery (OpenSSL's asm);
# pk-test-fast / pk-bench-fast build the fastest combination: s2n-bignum for P-256, OpenSSL for RSA
FAST := -DJWT_S2N -DJWT_OPENSSL $(SSLINC) $(B)/libs2n.a $(SSLLIB) -lcrypto
$(B)/test_pk_fast: tests/test_pk.c $(PKSRC) $(B)/libs2n.a | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(WARN) $(INC) $(PK) $< $(FAST) -o $@
$(B)/test_pk_fast_screen: tests/test_pk.c $(PKSRC) $(B)/libs2n.a | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(WARN) $(INC) $(PK) -DJWT_RSA_SCREEN $< $(FAST) -o $@
$(B)/bench_pk_fast: bench/bench_pk.c $(PKSRC) $(B)/libs2n.a | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(WARN) $(INC) $(PK) $< $(FAST) -o $@
$(B)/bench_pk_fast_screen: bench/bench_pk.c $(PKSRC) $(B)/libs2n.a | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(WARN) $(INC) $(PK) -DJWT_RSA_SCREEN $< $(FAST) -o $@
pk-test-fast: $(B)/test_pk_fast $(B)/test_pk_fast_screen $(B)/pk_vectors.txt
	./$(B)/test_pk_fast $(B)/pk_vectors.txt
	./$(B)/test_pk_fast_screen $(B)/pk_vectors.txt
pk-bench-fast: $(B)/bench_pk_fast $(B)/bench_pk_fast_screen $(B)/pk_tokens.txt
	./$(B)/bench_pk_fast $(B)/pk_tokens.txt
	./$(B)/bench_pk_fast_screen $(B)/pk_tokens.txt
$(B)/pk_vectors.txt: tests/make_pk_vectors.py scripts/fetch-vectors.sh $(B)/pyenv
	./scripts/fetch-vectors.sh
	$$(cat $(B)/pyenv) -I tests/make_pk_vectors.py third_party/vectors $(VECTORS_N) 1 > $@
$(B)/test_pk: tests/test_pk.c $(PKSRC) | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(WARN) $(INC) $(PK) $< -o $@
$(B)/test_pk_screen: tests/test_pk.c $(PKSRC) | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(WARN) $(INC) $(PK) -DJWT_RSA_SCREEN $< -o $@
$(B)/test_pk_w%: tests/test_pk.c $(PKSRC) | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(WARN) $(INC) $(PK) -DJWT_P256_W=$* $< -o $@
$(B)/asan_pk: tests/test_pk.c $(PKSRC) | $(B)
	$(CC) $(SAN) $(ARCHFLAGS) $(WARN) $(INC) $(PK) -DJWT_RSA_SCREEN $< -o $@
pk-test: $(B)/test_pk $(B)/test_pk_screen $(B)/test_pk_w5 $(B)/test_pk_w7 $(B)/pk_vectors.txt
	./$(B)/test_pk $(B)/pk_vectors.txt
	./$(B)/test_pk_screen $(B)/pk_vectors.txt
	./$(B)/test_pk_w5 $(B)/pk_vectors.txt | tail -1
	./$(B)/test_pk_w7 $(B)/pk_vectors.txt | tail -1
pk-test-s2n: $(B)/test_pk_s2n $(B)/test_pk_s2n_screen $(B)/pk_vectors.txt
	./$(B)/test_pk_s2n $(B)/pk_vectors.txt
	./$(B)/test_pk_s2n_screen $(B)/pk_vectors.txt
$(B)/pk_tokens.txt: bench/gen_pk_tokens.py $(B)/pyenv
	$$(cat $(B)/pyenv) -I bench/gen_pk_tokens.py 64 1 > $@
$(B)/bench_pk: bench/bench_pk.c $(PKSRC) | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(WARN) $(INC) $(PK) $(SSLINC) $< $(SSLLIB) -lcrypto -o $@
$(B)/bench_pk_screen: bench/bench_pk.c $(PKSRC) | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(WARN) $(INC) $(PK) -DJWT_RSA_SCREEN $(SSLINC) $< $(SSLLIB) -lcrypto -o $@
pk-bench: $(B)/bench_pk $(B)/bench_pk_screen $(B)/pk_tokens.txt
	./$(B)/bench_pk $(B)/pk_tokens.txt
	./$(B)/bench_pk_screen $(B)/pk_tokens.txt
pk-bench-s2n: $(B)/bench_pk_s2n $(B)/bench_pk_s2n_screen $(B)/pk_tokens.txt
	./$(B)/bench_pk_s2n $(B)/pk_tokens.txt
	./$(B)/bench_pk_s2n_screen $(B)/pk_tokens.txt
pk-asan: $(B)/asan_pk $(B)/pk_vectors.txt
	ASAN_OPTIONS=detect_leaks=0 ./$(B)/asan_pk $(B)/pk_vectors.txt

clean:
	rm -rf $(B)
.PHONY: pk-test-fast pk-bench-fast pk-test pk-test-s2n pk-asan pk-bench pk-bench-s2n all test test-quick test-vectors compare asan bench avx512 licence example-check clean
