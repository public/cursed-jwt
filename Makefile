# cursed-jwt
#   make              build/libcursedjwt.a + build/libcursedcrypto.a + build/verify (no dependencies; see Libraries)
#   make JCC=1        the same, for Intel Skylake .. Cascade Lake only (JCC-erratum-safe code; see JCC below)
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
#   make sign-test    HS256 / EdDSA signing: RFC 8032 / 8037 / 7515 and pyca exact outputs, round trips, pyca checks
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
comma := ,
PYTHON ?= python3
B := build
UNAME_M := $(shell uname -m)
# No -march by default: the library is built for the baseline ISA and picks its engines at run time from the CPU
# (CPUID / HWCAP).  ARCHFLAGS=-march=native still works; dispatch checks the CPU either way.
ARCHFLAGS ?=
# x86-64 Linux: batch 1 and leftover lanes use OpenSSL's extracted sha256 block function (crypto/src/sha256_x86_64_ossl.S,
# ELF only), SHA-NI batches the generated 3/4-stream kernels (crypto/src/sha256_shani_mb.S) and zmm batches the generated
# 16-lane kernel (crypto/src/sha256_x16_avx512.S), both with -DJWT_SHANI_MB, and RSA uses OpenSSL's extracted bn_mul_mont
# (crypto/src/bn_mont*_x86_64_ossl.S) where s2n-bignum can't run.
# `make OSSL_SHA=` builds without either.
ifeq ($(UNAME_M)-$(shell uname -s),x86_64-Linux)
OSSL_SHA ?= 1
endif
ifeq ($(OSSL_SHA),1)
MONTOBJ := $(B)/bn_mont_x86_64_ossl.o $(B)/bn_mont5_x86_64_ossl.o
SHAFLAG := -DJWT_OSSL_SHA256 -DJWT_SHANI_MB -DJWT_OSSL_MONT
SHAOBJ := $(B)/sha256_x86_64_ossl.o $(B)/sha256_shani_mb.o $(B)/sha256_x16_avx512.o $(MONTOBJ)
X86SHA := $(SHAFLAG) $(SHAOBJ)
X86MONT := -DJWT_OSSL_MONT $(MONTOBJ)
endif
SSLDIR := $(shell brew --prefix openssl@3 2>/dev/null)
ifneq ($(SSLDIR),)
SSLINC := -I$(SSLDIR)/include
SSLLIB := -L$(SSLDIR)/lib
endif
CFLAGS ?= -O3
# JCC=1: keep every branch off 32-byte boundaries (assembler padding), C and assembly alike.  Intel's microcode fix
# for the JCC erratum (Skylake through Cascade Lake / Cooper Lake) stalls branches that cross or end on one; on those
# CPUs this makes full HS256 verify up to 17% faster (Cascade Lake, realistic tokens, batch 16), while on AMD Zen 4 /
# Zen 5 it costs 2-7% there.  The crypto itself doesn't move either way (README.md, Building).  For Intel-only builds.
ifeq ($(JCC),1)
JCCFLAG ?= $(if $(shell $(CC) --version 2>/dev/null | grep -i clang),-mbranches-within-32B-boundaries,-Wa$(comma)-mbranches-within-32B-boundaries)
override CFLAGS += $(JCCFLAG)
ASJCC := $(JCCFLAG)
endif
WARN := -Wall -Wextra -Wno-deprecated-declarations -Wno-unused-function
INC := -Iinclude -Isrc -Itests
SRC := src/jwt.c include/jwt.h crypto/include/cursed_crypto.h $(wildcard crypto/src/*.c crypto/src/*.h crypto/src/*.inc crypto/src/fiat/*.c) $(SHAOBJ)
SAN := -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
TEST_SECRET := cursed-jwt-test-secret
NTOKENS ?= 20000

all: $(B)/libcursedjwt.a $(B)/libcursedcrypto.a $(B)/verify

$(B):
	mkdir -p $(B)
$(B)/jwt.o: $(SRC) | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(SHAFLAG) $(WARN) -Iinclude -c src/jwt.c -o $@
$(B)/sha256_x86_64_ossl.o: crypto/src/sha256_x86_64_ossl.S | $(B)
	$(CC) $(ASJCC) -c $< -o $@
$(B)/sha256_shani_mb.o: crypto/src/sha256_shani_mb.S | $(B)
	$(CC) $(ASJCC) -c $< -o $@
$(B)/sha256_x16_avx512.o: crypto/src/sha256_x16_avx512.S | $(B)
	$(CC) $(ASJCC) -c $< -o $@
$(B)/bn_mont_x86_64_ossl.o: crypto/src/bn_mont_x86_64_ossl.S | $(B)
	$(CC) $(ASJCC) -c $< -o $@
$(B)/bn_mont5_x86_64_ossl.o: crypto/src/bn_mont5_x86_64_ossl.S | $(B)
	$(CC) $(ASJCC) -c $< -o $@
# Libraries: cursed-crypto (crypto/) and the JWT layer (src/jwt.c) are compiled as separate units, no LTO:
#   build/libcursedcrypto.a  cursed-crypto alone (crypto/include/cursed_crypto.h)
#   build/libcursedjwt.a     the JWT layer (-DJWT_EXTERNAL_CRYPTO) plus the same cursed-crypto objects, so linking it
#                            on its own works as before; linking both is fine too (the linker takes each object once)
# build/jwt.o is everything as one unit (src/jwt.c #includes crypto/src/cursed_crypto.c), as the tests and the
# contrib modules build it.
# LIBFLAGS adds build flags to both (e.g. LIBFLAGS="-DJWT_S2N -DJWT_OPENSSL", the fast public-key build; see the
# flags table in README.md).  $(B)/libcursedjwt_all.a is libcursedjwt.a plus, with -DJWT_S2N in LIBFLAGS, s2n-bignum's
# kernels: one archive for builds of their own (contrib/nginx, contrib/haproxy), which then take nothing else from
# this tree but include/ and crypto/include/.
$(B)/cursed_crypto.o: $(SRC) | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(SHAFLAG) $(LIBFLAGS) $(WARN) -c crypto/src/cursed_crypto.c -o $@
$(B)/jwt_layer.o: $(SRC) | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(SHAFLAG) $(LIBFLAGS) $(WARN) -Iinclude -DJWT_EXTERNAL_CRYPTO -c src/jwt.c -o $@
$(B)/libcursedcrypto.a: $(B)/cursed_crypto.o $(SHAOBJ)
	rm -f $@ && ar rcs $@ $^
$(B)/libcursedjwt.a: $(B)/jwt_layer.o $(B)/cursed_crypto.o $(SHAOBJ)
	rm -f $@ && ar rcs $@ $^
LIB_S2N := $(if $(findstring -DJWT_S2N,$(LIBFLAGS))$(findstring -DCC_S2N,$(LIBFLAGS)),$(B)/libs2n.a)
$(B)/libcursedjwt_all.a: $(B)/jwt_layer.o $(B)/cursed_crypto.o $(SHAOBJ) $(LIB_S2N)
	rm -f $@ && ar rcs $@ $(filter %.o,$^) $(if $(LIB_S2N),$(addprefix $(B)/s2n/,$(addsuffix .o,$(notdir $(S2N_FILES)))))
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

test: $(B)/test_jwt $(B)/tokens.json example-check check-symbols
	./$(B)/test_jwt $(B)/tokens.json
# the libraries' exported symbols: libcursedcrypto.a only cc_*, libcursedjwt.a cc_* / jwt_* (scripts/check-symbols.sh)
check-symbols: $(B)/libcursedcrypto.a $(B)/libcursedjwt.a
	./scripts/check-symbols.sh --cc-only $(B)/libcursedcrypto.a
	./scripts/check-symbols.sh $(B)/libcursedjwt.a
# signing (README.md, Signing): exact-output vectors (RFC 8032 7.1, RFC 8037 A.4, RFC 7515 A.1, pyca/cryptography),
# round trips through both verifiers on every HMAC engine, then pyca/cryptography and Python's hmac check emitted tokens
SIGN_N ?= 300
$(B)/test_sign: tests/test_sign.c $(SRC) | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(WARN) $(INC) $< $(X86SHA) -o $@
$(B)/sign_vectors.txt: tests/make_sign_vectors.py scripts/fetch-vectors.sh $(B)/pyenv
	./scripts/fetch-vectors.sh
	$$(cat $(B)/pyenv) -I tests/make_sign_vectors.py third_party/vectors $(SIGN_N) 1 > $@
sign-test: $(B)/test_sign $(B)/sign_vectors.txt $(B)/pyenv
	./$(B)/test_sign $(B)/sign_vectors.txt
	JWT_CPU_MASK=0 ./$(B)/test_sign $(B)/sign_vectors.txt | tail -1   # every CPU feature masked: the portable engines
	./$(B)/test_sign emit $(SIGN_N) > $(B)/sign_emitted.txt
	$$(cat $(B)/pyenv) -I tests/check_sign_pyca.py < $(B)/sign_emitted.txt
# constant-time checks of the HS256 secret-key path (tests/test_ct.c, tests/dudect_hmac.c):
#   make test-ct   valgrind memcheck with the key marked secret: any key-dependent branch or address in jwt_key_init
#                  or an HMAC engine this CPU runs fails it (deterministic; needs valgrind and its memcheck.h); then
#                  the same for signing (`test_ct sign`: the HS256 key, the Ed25519 seed, a, prefix and nonce r)
#   make test-ct-sde SDE=…/sde64   trace equivalence under Intel SDE for the engines valgrind can't run (SHA-NI,
#                  AVX-512): every engine's instruction and address trace must be identical under two keys
#   make test-ct-qemu QEMU=…/qemu-aarch64 EXECLOG=…/libexeclog.so   the same for the AArch64 engines (NEON, SHA2), cross-
#                  built; needs a qemu built with --enable-plugins and its contrib execlog plugin
#   make dudect    statistical timing tests (dudect) for the engines valgrind can't run (SHA-NI, AVX-512): run on a
#                  quiet machine; |t| > 10 is a leak. The first line is a deliberately leaky control and must say LEAK.
$(B)/test_ct: tests/test_ct.c $(SRC) | $(B)
	$(CC) -O2 -g $(ARCHFLAGS) $(WARN) $(INC) -include stdarg.h $< $(X86SHA) -o $@
test-ct: $(B)/test_ct
	valgrind -q --error-exitcode=1 ./$(B)/test_ct key
	valgrind -q --error-exitcode=1 ./$(B)/test_ct sign
	@if valgrind -q --error-exitcode=1 ./$(B)/test_ct sign-control >/dev/null 2>&1; then \
	  echo "test-ct: the sign-control run raised no memcheck error: the method is broken"; exit 1; \
	  else echo "test-ct: sign-control flagged (as it must)"; fi
$(B)/ct_trace: tests/ct_trace.c $(SRC) | $(B)
	$(CC) -O2 $(ARCHFLAGS) $(WARN) $(INC) -include stdarg.h $< $(X86SHA) -o $@
SDE ?= sde64
test-ct-sde: $(B)/ct_trace
	scripts/ct-trace.sh $(SDE) ./$(B)/ct_trace
# the AArch64 engines (NEON, SHA2) from an x86-64 machine: a static cross build, traced by qemu-aarch64's execlog plugin
CROSS ?= aarch64-linux-gnu-
QEMU ?= qemu-aarch64
EXECLOG ?= libexeclog.so
$(B)/ct_trace_arm: tests/ct_trace.c $(SRC) | $(B)
	$(CROSS)gcc -O2 -static $(WARN) $(INC) -include stdarg.h $< -o $@
test-ct-qemu: $(B)/ct_trace_arm
	NM=$(CROSS)nm scripts/ct-trace.sh --qemu $(QEMU) $(EXECLOG) ./$(B)/ct_trace_arm
$(B)/dudect_hmac: tests/dudect_hmac.c $(SRC) | $(B)
	$(CC) -O2 $(ARCHFLAGS) $(WARN) $(INC) -include stdarg.h $< $(X86SHA) -lm -o $@
dudect: $(B)/dudect_hmac
	./$(B)/dudect_hmac control x 1; ./$(B)/dudect_hmac aa ossl 1; ./$(B)/dudect_hmac aa avx2 16
	for b in 3 16; do for e in ossl avx2 avx512 zmm x16 shani_4 shani_4r shani_x16; do ./$(B)/dudect_hmac key $$e $$b; done; done
	./$(B)/dudect_hmac key ossl 1
	./$(B)/dudect_hmac mac x 1; ./$(B)/dudect_hmac mac x 16; ./$(B)/dudect_hmac b64 x 1
test-quick: $(B)/test_jwt $(B)/tokens.json example-check check-symbols
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

# RS256 / ES256 / EdDSA (crypto/src/cc_pk.c, PK.md) are part of the default build; their field arithmetic is fiat-crypto's,
# vendored in crypto/src/fiat/ (scripts/fetch-fiat.sh re-checks it).  PK holds extra flags for these targets (none now).
# Defined before any rule that lists $(PKSRC): make expands prerequisites as it reads them
PK := $(X86MONT)
# (rules that also link $(X86SHA), which carries the same objects, take $(filter-out $(MONTOBJ),$(PK)))
PKSRC := $(SRC)
# property-based tests (Hypothesis) against an independent Python model, every engine, HS256 + RS256/ES256
HYP_N ?= 200   # quick dev default; e.g. HYP_N=20000 for a long run
$(B)/pyenv-hyp: | $(B)
	@if $(PYTHON) -c "import cryptography, hypothesis" 2>/dev/null; then echo $(PYTHON) > $@; \
	  else $(PYTHON) -m venv $(B)/venv && $(B)/venv/bin/pip -q install cryptography "hypothesis==6.*" && echo $(B)/venv/bin/python > $@; fi
$(B)/libjwtshim.so: tests/pyshim.c $(PKSRC) | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(WARN) -shared -fPIC $(INC) $(filter-out $(MONTOBJ),$(PK)) $< $(X86SHA) -o $@
test-hypothesis: $(B)/libjwtshim.so $(B)/pyenv-hyp
	$$(cat $(B)/pyenv-hyp) -I tests/test_hypothesis.py $(B)/libjwtshim.so $(HYP_N)

# fuzz harnesses (fuzz/): fuzz-smoke replays the seed corpora (and any corpus in build/fuzz-*/) under ASan + UBSan,
# locally, in seconds; fuzz runs libFuzzer in Docker, 10 s per harness by default (FUZZ_SECS, JOBS for longer runs)
FUZZ_SAN := -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all $(ARCHFLAGS) $(WARN) $(INC) $(SSLINC)
$(B)/replay_verify: fuzz/fuzz_verify.c fuzz/replay.c $(SRC) | $(B)
	$(CC) $(FUZZ_SAN) fuzz/fuzz_verify.c fuzz/replay.c $(SSLLIB) -lcrypto $(X86SHA) -o $@
$(B)/replay_b64: fuzz/fuzz_b64.c fuzz/replay.c $(SRC) | $(B)
	$(CC) $(FUZZ_SAN) fuzz/fuzz_b64.c fuzz/replay.c $(X86SHA) -o $@
$(B)/replay_sign: fuzz/fuzz_sign.c fuzz/replay.c $(SRC) | $(B)
	$(CC) $(FUZZ_SAN) fuzz/fuzz_sign.c fuzz/replay.c $(X86SHA) -o $@
$(B)/replay_pk: fuzz/fuzz_pk.c fuzz/replay.c $(PKSRC) | $(B)
	$(CC) $(FUZZ_SAN) $(filter-out $(MONTOBJ),$(PK)) -DJWT_RSA_SCREEN fuzz/fuzz_pk.c fuzz/replay.c $(SSLLIB) -lcrypto \
	  $(X86SHA) -o $@
fuzz-smoke: $(B)/replay_verify $(B)/replay_b64 $(B)/replay_sign $(B)/replay_pk
	@python3 -I fuzz/seeds.py $(B)/fuzz-seeds >/dev/null
	@for h in verify b64 sign pk; do printf "%-7s " $$h; ASAN_OPTIONS=detect_leaks=0 ./$(B)/replay_$$h $(B)/fuzz-seeds/$$h \
	  $$(ls -d $(B)/fuzz-*/corpus/$$h 2>/dev/null) || exit 1; done
FUZZ_SECS ?= 10
fuzz:
	./scripts/fuzz.sh "" $(FUZZ_SECS)

# RS256 / ES256 / EdDSA: PK and PKSRC are defined above (before the first rule that uses them)
# -DJWT_S2N: AWS s2n-bignum's verified asm for the P-256 field and RSA-2048 Montgomery kernels (fetched pinned)
S2N_ARCH := $(if $(filter x86_64,$(UNAME_M)),x86,arm)
S2N_FILES := p256/bignum_montmul_p256 p256/bignum_montsqr_p256 p256/bignum_add_p256 p256/bignum_sub_p256 \
             fastmul/bignum_kmul_32_64 fastmul/bignum_ksqr_32_64 fastmul/bignum_emontredc_8n
# x86-64 only: the ADX-free P-256 multiply / square, for CPUs (and VMs) that hide BMI2 / ADX
S2N_FILES += $(if $(filter x86,$(S2N_ARCH)),p256/bignum_montmul_p256_alt p256/bignum_montsqr_p256_alt \
  curve25519/edwards25519_pepadd curve25519/edwards25519_pepadd_alt)
S2N := -DJWT_S2N $(B)/libs2n.a
# each kernel's one global is renamed cc_s2n_<name> as it is assembled (the C side declares those names), so the
# archive links next to AWS-LC or another copy of s2n-bignum, which carry the plain bignum_* / edwards25519_* names
$(B)/libs2n.a: scripts/fetch-s2n-bignum.sh | $(B)
	./scripts/fetch-s2n-bignum.sh
	mkdir -p $(B)/s2n
	for f in $(S2N_FILES); do n=$${f#*/}; $(CC) $(ASJCC) -c -DS2N_BN_HIDE_SYMBOLS=1 -D$$n=cc_s2n_$$n \
	  -Ithird_party/s2n-bignum/include third_party/s2n-bignum/$(S2N_ARCH)/$$f.S -o $(B)/s2n/$$n.o || exit 1; done
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
$(B)/libcmbrsa.a: scripts/fetch-crypto-mb-rsa.sh crypto/src/cmb_rsa/cmb_rsa_glue.c crypto/src/cmb_rsa/internal/rsa/ifma_rsa_arith.h | $(B)
	./scripts/fetch-crypto-mb-rsa.sh
	mkdir -p $(B)/cmbrsa
	for f in $(CMBRSA_SRC); do $(CC) -O3 -D_MBX=2 -mavx512f -mavx512ifma -mavx512vl -mavx512bw -mavx512dq \
	  -Icrypto/src/cmb_rsa -Ithird_party/crypto-mb-rsa/sources/ippcp/crypto_mb/include -c third_party/crypto-mb-rsa/$$f \
	  -o $(B)/cmbrsa/$$(basename $$f .c).o || exit 1; done
	$(CC) -O2 -c crypto/src/cmb_rsa/cmb_rsa_glue.c -o $(B)/cmbrsa/cmb_rsa_glue.o
	ld -r $(B)/cmbrsa/ifma_*.o $(B)/cmbrsa/cmb_rsa_glue.o -o $(B)/cmbrsa/cmbrsa.o
	# one global, renamed so it never clashes with Intel's own libcrypto_mb: everything else local
	objcopy --redefine-sym EXP52x40_pub65537_mb8=cc_cmb_exp52x40_pub65537_mb8 $(B)/cmbrsa/cmbrsa.o
	objcopy -w --keep-global-symbol=cc_cmb_exp52x40_pub65537_mb8 $(B)/cmbrsa/cmbrsa.o
	rm -f $@ && ar rcs $@ $(B)/cmbrsa/cmbrsa.o
RSAZ8 := -DJWT_RSAZ8 $(B)/libcmbrsa.a
$(eval $(call PK_BACKEND,_rsaz8,$(RSAZ) $(RSAZ8) $(FAST),$(B)/libs2n.a $(B)/rsaz-4k-avx512.S $(B)/libcmbrsa.a))
$(B)/test_rsaz8: tests/test_rsaz.c $(PKSRC) $(B)/libs2n.a $(B)/rsaz-4k-avx512.S $(B)/libcmbrsa.a | $(B)
	$(CC) $(CFLAGS) $(ARCHFLAGS) $(INC) $(SSLINC) $< $(RSAZ) $(RSAZ8) $(FAST) -o $@
# -DJWT_ES8: ES256 batches 8 tokens at a time through crypto_mb's 8-lane P-256 field arithmetic under our comb tables
# (crypto/src/cmb_ec/es8.c #includes the two fetched files; every symbol but cc_es8_* is made local).  Used only where zmm
# costs no clock speed (FAST_ZMM: AMD Zen 4 / 5) and the CPU has IFMA.  pk-test-es8 / pk-bench-es8 = rsaz8 plus it.
CMB_INC := -Ithird_party/crypto-mb-rsa -Ithird_party/crypto-mb-rsa/sources/ippcp/crypto_mb/include
$(B)/libcmbec.a: scripts/fetch-crypto-mb-rsa.sh crypto/src/cmb_ec/es8.c | $(B)
	./scripts/fetch-crypto-mb-rsa.sh
	mkdir -p $(B)/cmbec
	$(CC) -O3 -D_MBX=2 -mavx512f -mavx512ifma -mavx512vl -mavx512bw -mavx512dq $(CMB_INC) -c crypto/src/cmb_ec/es8.c \
	  -o $(B)/cmbec/es8.o
	objcopy -w --keep-global-symbol='cc_es8_*' $(B)/cmbec/es8.o
	rm -f $@ && ar rcs $@ $(B)/cmbec/es8.o
ES8 := -DJWT_ES8 $(B)/libcmbec.a
$(eval $(call PK_BACKEND,_es8,$(RSAZ) $(RSAZ8) $(ES8) $(FAST),$(B)/libs2n.a $(B)/rsaz-4k-avx512.S $(B)/libcmbrsa.a $(B)/libcmbec.a))
pk-test-es8: $(B)/test_pk_es8 $(B)/pk_vectors.txt
	./$(B)/test_pk_es8 $(B)/pk_vectors.txt
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
	JWT_CPU_MASK=0xfffffffb ./$(B)/test_pk_$* $(B)/pk_vectors.txt   # BMI2/ADX masked: the ADX-free kernels (x86-64)
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
.PHONY: sign-test check-symbols test-ct test-ct-sde test-ct-qemu dudect mca mca-validate pk-test-ifma pk-bench-ifma fuzz fuzz-smoke test-hypothesis pk-test-fast pk-bench-fast pk-test pk-test-s2n pk-asan pk-bench pk-bench-s2n all test test-quick test-vectors compare asan bench avx512 licence example-check format lint hooks clean test-rsaz pk-test-rsaz pk-bench-rsaz pk-test-rsaz8 pk-test-es8
