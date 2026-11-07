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
#   make fuzz-smoke   fuzz harnesses replaying their seed/saved corpora under ASan + UBSan (seconds, local)
#   make fuzz         libFuzzer in Docker, 10 s per harness (FUZZ_SECS=600 JOBS=6 for a real campaign)
#   make test-hypothesis  property-based tests vs an independent Python model (Hypothesis; network for the venv)
#   make pk-test      RS256 / ES256 / EdDSA vs Wycheproof, NIST CAVP, RFC 7515/8032/8037, pyca (network)
#   make pk-bench     RS256 / ES256 / EdDSA ns/token vs OpenSSL
#   make pk-test-s2n / pk-bench-s2n   the same with s2n-bignum's verified asm kernels (-DJWT_S2N; fetched pinned)
#   make pk-test-fast / pk-bench-fast s2n-bignum for P-256 + OpenSSL's BN asm for RSA (-DJWT_S2N -DJWT_OPENSSL)
#   make pk-test-ifma / pk-bench-ifma + Intel crypto_mb 8-way AVX-512 IFMA (Linux x86-64; IFMA CPU to exercise it)
#   make mca          static estimates of every SHA-256 engine per CPU model (llvm-mca; + uiCA, scripts/mca/fetch-uica.sh)
#   make mca-validate perf-measured cycles of the same engines on this machine (x86-64 Linux; scripts/mca/validate.sh)
#   make lint         formatting + lint checks (clang-format, shfmt, ruff, shellcheck, cppcheck; Docker)
#   make format       apply the formatters; make hooks installs the pre-commit check (.githooks/)
# Engines are picked at run time from the CPU; ARCHFLAGS only changes the baseline (see README.md, Building).
CC ?= cc
PYTHON ?= python3
B := build
UNAME_M := $(shell uname -m)
# No -march by default: the library is built for the baseline ISA and picks its engines at run time from the CPU
# (CPUID / HWCAP).  ARCHFLAGS=-march=native still works; dispatch checks the CPU either way.
ARCHFLAGS ?=
# x86-64 Linux: batch 1 and leftover lanes use OpenSSL's extracted sha256 block function (src/sha256_x86_64_ossl.S,
# ELF only).  `make OSSL_SHA=` builds without it.
ifeq ($(UNAME_M)-$(shell uname -s),x86_64-Linux)
OSSL_SHA ?= 1
endif
ifeq ($(OSSL_SHA),1)
SHAFLAG := -DJWT_OSSL_SHA256
X86SHA := -DJWT_OSSL_SHA256 $(B)/sha256_x86_64_ossl.o
SHAOBJ := $(B)/sha256_x86_64_ossl.o
endif
SSLDIR := $(shell brew --prefix openssl@3 2>/dev/null)
ifneq ($(SSLDIR),)
SSLINC := -I$(SSLDIR)/include
SSLLIB := -L$(SSLDIR)/lib
endif
CFLAGS ?= -O3
WARN := -Wall -Wextra -Wno-deprecated-declarations -Wno-unused-function
INC := -Iinclude -Isrc -Itests
SRC := src/jwt.c src/jwt_mb.inc include/jwt.h src/jwt_pk.inc src/jwt_pk_ec.inc src/jwt_ed25519.inc $(wildcard src/fiat/*.c) $(SHAOBJ)
SAN := -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
TEST_SECRET := cursed-jwt-test-secret
NTOKENS ?= 20000

all: $(B)/libcursedjwt.a $(B)/verify

$(B):
	mkdir -p $(B)
$(B)/jwt.o: $(SRC) | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(SHAFLAG) $(WARN) -Iinclude -c src/jwt.c -o $@
$(B)/sha256_x86_64_ossl.o: src/sha256_x86_64_ossl.S | $(B)
	$(CC) -c $< -o $@
$(B)/libcursedjwt.a: $(B)/jwt.o $(SHAOBJ)
	rm -f $@ && ar rcs $@ $^
$(B)/verify: examples/verify.c $(B)/libcursedjwt.a
	$(CC) $(CFLAGS) $(WARN) -Iinclude $< $(B)/libcursedjwt.a -o $@

# test tokens: deterministic, generated with Python's hmac module (an independent HS256 implementation)
$(B)/tokens.json: tests/gen_tokens.py | $(B)
	$(PYTHON) tests/gen_tokens.py $(TEST_SECRET) $(NTOKENS) > $@

$(B)/test_jwt: tests/test_jwt.c tests/ossl_min.h $(SRC) | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(WARN) $(INC) -include stdarg.h $(SSLINC) $< $(SSLLIB) -lcrypto $(X86SHA) -o $@
$(B)/asan_jwt: tests/test_jwt.c tests/ossl_min.h $(SRC) | $(B)
	$(CC) $(SAN) $(ARCHFLAGS) $(WARN) $(INC) -include stdarg.h $(SSLINC) $< $(SSLLIB) -lcrypto $(X86SHA) -o $@
$(B)/bench_jwt: bench/bench_jwt.c tests/ossl_min.h $(SRC) | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(WARN) $(INC) $(SSLINC) $< $(SSLLIB) -lcrypto $(X86SHA) -o $@

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
	$(CC) $(CFLAGS) $(ARCHFLAGS) -w $(INC) bench/compare/e2e.c $(X86SHA) -o $(B)/compare_e2e
	$(CC) $(CFLAGS) $(ARCHFLAGS) -w $(INC) -DJWT_NO_SHAPE_JSON bench/compare/e2e.c $(X86SHA) -o $(B)/compare_e2e_strict
	$(CXX) -O3 $(ARCHFLAGS) -std=c++17 -w -Ithird_party/jwt-cpp/include $(SSLINC) bench/compare/jwtcpp_bench.cpp $(SSLLIB) -lcrypto -o $(B)/compare_jwtcpp
	./$(B)/compare_e2e $(B)/tokens.json
	./$(B)/compare_e2e_strict $(B)/tokens.json
	./$(B)/compare_jwtcpp $(B)/tokens.json
	@if command -v go >/dev/null; then (cd bench/compare/go && GOFLAGS=-mod=mod go build -o ../../../$(B)/compare_gojwt .) && ./$(B)/compare_gojwt $(B)/tokens.json; \
	  else echo "golang-jwt: skipped (no go toolchain)"; fi

AVX512 := -march=cascadelake -DJWT_AVX512
avx512: tests/test_jwt.c bench/bench_jwt.c $(SRC) | $(B)
	$(CC) $(CFLAGS) $(AVX512) $(WARN) $(INC) -include stdarg.h $(SSLINC) tests/test_jwt.c $(SSLLIB) -lcrypto $(X86SHA) -o $(B)/test_jwt_avx512
	$(CC) $(CFLAGS) $(AVX512) $(WARN) $(INC) $(SSLINC) bench/bench_jwt.c $(SSLLIB) -lcrypto $(X86SHA) -o $(B)/bench_jwt_avx512
	@echo "vprord/vpternlogd in the test binary: $$(objdump -d $(B)/test_jwt_avx512 | grep -c -E 'vprord|vpternlogd')"
licence: bench/licence_probe.c $(SRC) | $(B)
	$(CC) $(CFLAGS) $(AVX512) $(WARN) $(INC) $< $(X86SHA) -o $(B)/licence_probe && ./$(B)/licence_probe

# RS256 / ES256 / EdDSA (src/jwt_pk.inc, PK.md) are part of the default build; their field arithmetic is fiat-crypto's,
# vendored in src/fiat/ (scripts/fetch-fiat.sh re-checks it).  PK holds extra flags for these targets (none now).
# Defined before any rule that lists $(PKSRC): make expands prerequisites as it reads them
PK :=
PKSRC := $(SRC)
# property-based tests (Hypothesis) against an independent Python model, every engine, HS256 + RS256/ES256
HYP_N ?= 200   # quick dev default; e.g. HYP_N=20000 for a long run
$(B)/pyenv-hyp: | $(B)
	@if $(PYTHON) -c "import cryptography, hypothesis" 2>/dev/null; then echo $(PYTHON) > $@; \
	  else $(PYTHON) -m venv $(B)/venv && $(B)/venv/bin/pip -q install cryptography "hypothesis==6.*" && echo $(B)/venv/bin/python > $@; fi
$(B)/libjwtshim.so: tests/pyshim.c $(PKSRC) | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(WARN) -shared -fPIC $(INC) $(PK) $< $(X86SHA) -o $@
test-hypothesis: $(B)/libjwtshim.so $(B)/pyenv-hyp
	$$(cat $(B)/pyenv-hyp) -I tests/test_hypothesis.py $(B)/libjwtshim.so $(HYP_N)

# fuzz harnesses (fuzz/): fuzz-smoke replays the seed corpora (and any corpus in build/fuzz-*/) under ASan + UBSan,
# locally, in seconds; fuzz runs libFuzzer in Docker, 10 s per harness by default (FUZZ_SECS, JOBS for longer runs)
FUZZ_SAN := -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all $(ARCHFLAGS) $(WARN) $(INC) $(SSLINC)
$(B)/replay_verify: fuzz/fuzz_verify.c fuzz/replay.c $(SRC) | $(B)
	$(CC) $(FUZZ_SAN) fuzz/fuzz_verify.c fuzz/replay.c $(SSLLIB) -lcrypto $(X86SHA) -o $@
$(B)/replay_b64: fuzz/fuzz_b64.c fuzz/replay.c $(SRC) | $(B)
	$(CC) $(FUZZ_SAN) fuzz/fuzz_b64.c fuzz/replay.c $(X86SHA) -o $@
$(B)/replay_pk: fuzz/fuzz_pk.c fuzz/replay.c $(PKSRC) | $(B)
	$(CC) $(FUZZ_SAN) $(PK) -DJWT_RSA_SCREEN fuzz/fuzz_pk.c fuzz/replay.c $(SSLLIB) -lcrypto $(X86SHA) -o $@
fuzz-smoke: $(B)/replay_verify $(B)/replay_b64 $(B)/replay_pk
	@python3 -I fuzz/seeds.py $(B)/fuzz-seeds >/dev/null
	@for h in verify b64 pk; do printf "%-7s " $$h; ASAN_OPTIONS=detect_leaks=0 ./$(B)/replay_$$h $(B)/fuzz-seeds/$$h \
	  $$(ls -d $(B)/fuzz-*/corpus/$$h 2>/dev/null) || exit 1; done
FUZZ_SECS ?= 10
fuzz:
	./scripts/fuzz.sh "" $(FUZZ_SECS)

# RS256 / ES256 / EdDSA: PK and PKSRC are defined above (before the first rule that uses them)
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
# -DJWT_OPENSSL: RSA arithmetic through libcrypto's BN_mod_exp_mont / BN_mod_mul_montgomery (OpenSSL's asm);
# pk-test-fast / pk-bench-fast build the fastest combination: s2n-bignum for P-256, OpenSSL for RSA
FAST := -DJWT_S2N -DJWT_OPENSSL $(SSLINC) $(B)/libs2n.a $(SSLLIB) -lcrypto
# -DJWT_CRYPTO_MB: Intel crypto_mb's 8-way AVX-512 IFMA ES256 / RSA (scripts/build-crypto-mb.sh; Linux x86-64; used only
# on CPUs with IFMA, checked at run time).  pk-test-ifma / pk-bench-ifma = the fast build plus crypto_mb.
CMB := -DJWT_CRYPTO_MB -Ithird_party/crypto-mb/include third_party/crypto-mb/lib/libcrypto_mb.a
third_party/crypto-mb/lib/libcrypto_mb.a:
	./scripts/build-crypto-mb.sh

# Every backend builds test_pk<v>, test_pk<v>_screen, bench_pk<v> and bench_pk<v>_screen from one template:
# $(1) = the suffix ("" for portable C), $(2) = its flags and libraries, $(3) = their prerequisites.
# _screen adds -DJWT_RSA_SCREEN.  pk-test-<v> / pk-bench-<v> run both builds; pk-test also runs the W=5 and W=7 combs.
define PK_BACKEND
$(B)/test_pk$(1) $(B)/test_pk$(1)_screen: tests/test_pk.c $(PKSRC) $(3) | $(B)
	$$(CC) $$(CFLAGS) $$(ARCHFLAGS) $$(WARN) $$(INC) $$(PK) $$(if $$(findstring _screen,$$@),-DJWT_RSA_SCREEN) $$< $(2) -o $$@
$(B)/bench_pk$(1) $(B)/bench_pk$(1)_screen: bench/bench_pk.c $(PKSRC) $(3) | $(B)
	$$(CC) $$(CFLAGS) $$(ARCHFLAGS) $$(WARN) $$(INC) $$(PK) $$(if $$(findstring _screen,$$@),-DJWT_RSA_SCREEN) $$(SSLINC) $$< $(2) $$(SSLLIB) -lcrypto -o $$@
endef
$(eval $(call PK_BACKEND,,,))
$(eval $(call PK_BACKEND,_s2n,$(S2N),$(B)/libs2n.a))
$(eval $(call PK_BACKEND,_fast,$(FAST),$(B)/libs2n.a))
$(eval $(call PK_BACKEND,_ifma,$(CMB) $(FAST),$(B)/libs2n.a third_party/crypto-mb/lib/libcrypto_mb.a))
# -DJWT_RSAZ: RSA-2048 through OpenSSL's 52-bit AVX-512 IFMA almost-Montgomery multiply ($(B)/rsaz-4k-avx512.S,
# generated into build/ by scripts/fetch-ossl-rsaz.sh; x86-64 only, used only on CPUs with IFMA, checked at run time).
# pk-test-rsaz / pk-bench-rsaz = the fast build plus it; test-rsaz checks it against libcrypto's BN_mod_exp.
RSAZ := -DJWT_RSAZ $(B)/rsaz-4k-avx512.S
$(B)/rsaz-4k-avx512.S: scripts/fetch-ossl-rsaz.sh
	./scripts/fetch-ossl-rsaz.sh
$(eval $(call PK_BACKEND,_rsaz,$(RSAZ) $(FAST),$(B)/libs2n.a $(B)/rsaz-4k-avx512.S))
# -DJWT_RSAZ8 (with -DJWT_RSAZ): groups of 8 RS256-2048 tokens through crypto_mb's 8-lane IFMA exponentiation
# (scripts/fetch-crypto-mb-rsa.sh, Apache-2.0: three files built on their own into build/libcmbrsa.a).
CMBRSA_SRC := sources/ippcp/crypto_mb/src/rsa/ifma_exp52x40_65537_mb8.c \
  sources/ippcp/crypto_mb/src/rsa/internal_avx512/ifma_amm52x40_mb8.c \
  sources/ippcp/crypto_mb/src/rsa/internal_avx512/ifma_ams52x40_diagonal_mb8.c
$(B)/libcmbrsa.a: scripts/fetch-crypto-mb-rsa.sh src/cmb_rsa/cmb_rsa_glue.c src/cmb_rsa/internal/rsa/ifma_rsa_arith.h | $(B)
	./scripts/fetch-crypto-mb-rsa.sh
	mkdir -p $(B)/cmbrsa
	for f in $(CMBRSA_SRC); do $(CC) -O3 -D_MBX=2 -mavx512f -mavx512ifma -mavx512vl -mavx512bw -mavx512dq \
	  -Isrc/cmb_rsa -Ithird_party/crypto-mb-rsa/sources/ippcp/crypto_mb/include -c third_party/crypto-mb-rsa/$$f \
	  -o $(B)/cmbrsa/$$(basename $$f .c).o || exit 1; done
	$(CC) -O2 -c src/cmb_rsa/cmb_rsa_glue.c -o $(B)/cmbrsa/cmb_rsa_glue.o
	rm -f $@ && ar rcs $@ $(B)/cmbrsa/*.o
RSAZ8 := -DJWT_RSAZ8 $(B)/libcmbrsa.a
$(eval $(call PK_BACKEND,_rsaz8,$(RSAZ) $(RSAZ8) $(FAST),$(B)/libs2n.a $(B)/rsaz-4k-avx512.S $(B)/libcmbrsa.a))
$(B)/test_rsaz8: tests/test_rsaz.c $(PKSRC) $(B)/libs2n.a $(B)/rsaz-4k-avx512.S $(B)/libcmbrsa.a | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(INC) $(SSLINC) $< $(RSAZ) $(RSAZ8) $(FAST) -o $@
$(B)/test_rsaz: tests/test_rsaz.c $(PKSRC) $(B)/libs2n.a $(B)/rsaz-4k-avx512.S | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(INC) $(SSLINC) $< $(RSAZ) $(FAST) -o $@
test-rsaz: $(B)/test_rsaz
	./$(B)/test_rsaz 8 200
pk-test-rsaz8: $(B)/test_rsaz8 $(B)/test_pk_rsaz8 $(B)/pk_vectors.txt
	./$(B)/test_rsaz8 2 20
	./$(B)/test_pk_rsaz8 $(B)/pk_vectors.txt
pk-test-rsaz: $(B)/test_rsaz $(B)/test_pk_rsaz $(B)/test_pk_rsaz_screen $(B)/pk_vectors.txt
	./$(B)/test_rsaz 2 20
	./$(B)/test_pk_rsaz $(B)/pk_vectors.txt
	./$(B)/test_pk_rsaz_screen $(B)/pk_vectors.txt
pk-test-s2n pk-test-fast pk-test-ifma: pk-test-%: $(B)/test_pk_% $(B)/test_pk_%_screen $(B)/pk_vectors.txt
	./$(B)/test_pk_$* $(B)/pk_vectors.txt
	./$(B)/test_pk_$*_screen $(B)/pk_vectors.txt
pk-bench-s2n pk-bench-fast pk-bench-rsaz: pk-bench-%: $(B)/bench_pk_% $(B)/bench_pk_%_screen $(B)/pk_tokens.txt
	./$(B)/bench_pk_$* $(B)/pk_tokens.txt
	./$(B)/bench_pk_$*_screen $(B)/pk_tokens.txt
pk-bench-ifma: $(B)/bench_pk_ifma $(B)/pk_tokens.txt
	./$(B)/bench_pk_ifma $(B)/pk_tokens.txt
	JWT_CPU_MASK=0xef ./$(B)/bench_pk_ifma $(B)/pk_tokens.txt   # the same binary with IFMA masked off, for comparison
$(B)/pk_vectors.txt: tests/make_pk_vectors.py scripts/fetch-vectors.sh $(B)/pyenv
	./scripts/fetch-vectors.sh
	$$(cat $(B)/pyenv) -I tests/make_pk_vectors.py third_party/vectors $(VECTORS_N) 1 > $@
$(B)/test_pk_w%: tests/test_pk.c $(PKSRC) | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(WARN) $(INC) $(PK) -DJWT_P256_W=$* $< -o $@
$(B)/asan_pk: tests/test_pk.c $(PKSRC) | $(B)
	$(CC) $(SAN) $(ARCHFLAGS) $(WARN) $(INC) $(PK) -DJWT_RSA_SCREEN $< -o $@
pk-test: $(B)/test_pk $(B)/test_pk_screen $(B)/test_pk_w5 $(B)/test_pk_w7 $(B)/pk_vectors.txt
	./$(B)/test_pk $(B)/pk_vectors.txt
	./$(B)/test_pk_screen $(B)/pk_vectors.txt
	./$(B)/test_pk_w5 $(B)/pk_vectors.txt | tail -1
	./$(B)/test_pk_w7 $(B)/pk_vectors.txt | tail -1
$(B)/pk_tokens.txt: bench/gen_pk_tokens.py $(B)/pyenv
	$$(cat $(B)/pyenv) -I bench/gen_pk_tokens.py 64 1 > $@
pk-bench: $(B)/bench_pk $(B)/bench_pk_screen $(B)/pk_tokens.txt
	./$(B)/bench_pk $(B)/pk_tokens.txt
	./$(B)/bench_pk_screen $(B)/pk_tokens.txt
pk-asan: $(B)/asan_pk $(B)/pk_vectors.txt
	ASAN_OPTIONS=detect_leaks=0 ./$(B)/asan_pk $(B)/pk_vectors.txt

# static throughput estimates per engine and CPU model, and the measurement to check them against (README, Benchmarks)
mca:
	./scripts/mca/mca.sh
mca-validate: | $(B)
	./scripts/mca/validate.sh > $(B)/mca-measured.txt
	MEASURED=$(B)/mca-measured.txt ./scripts/mca/mca.sh

# formatting and linting (scripts/lint.sh; pinned tools in ci/lint.Dockerfile, run through Docker)
format:
	./scripts/lint.sh --fix
lint:
	./scripts/lint.sh
hooks:
	git config core.hooksPath .githooks
clean:
	rm -rf $(B)
.PHONY: test-rsaz pk-test-rsaz pk-bench-rsaz pk-test-rsaz8 mca mca-validate pk-test-ifma pk-bench-ifma fuzz fuzz-smoke test-hypothesis pk-test-fast pk-bench-fast pk-test pk-test-s2n pk-asan pk-bench pk-bench-s2n all test test-quick test-vectors compare asan bench avx512 licence example-check format lint hooks clean
