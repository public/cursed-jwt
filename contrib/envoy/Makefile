# contrib/envoy: cjwt_authn, an Envoy HTTP filter (dynamic module) that verifies JWTs with cursed-jwt.  Linux only
# (Envoy loads a .so); build in the Dockerfile here or any Linux with clang 18 / gcc 13.  ./fetch.sh first.
#
#   make              build/<arch>/libcjwt_authn.so (needs only ./fetch.sh envoy: the ABI header)
#   make tokens       build/tokens: keys, JWKS and signed tokens (pyca/cryptography)
#   make configs      build/configs: Envoy bootstrap configs (jwt_authn, cjwt_authn, ...) over build/tokens-e2e
#   make functional   jwt_authn and cjwt_authn side by side in the stock Envoy v1.40.2 image; same answers (Docker)
#   make deps         abseil, protobuf and BoringSSL as Envoy v1.40.2 pins them (./fetch.sh deps; cmake + ninja)
#   make test         after deps: differential mutation test against Envoy's own JWT library (test/diff.cpp)
#   make asan         after deps: the differential test with the claims layer under ASan + UBSan
#   make bench        after deps: ns per token, Envoy's JWT library vs this filter's, split by stage
ARCH := $(shell uname -m)
B := build/$(ARCH)
P := $(B)/prefix
ROOT := ../..
CC ?= cc
CXX ?= c++
PYTHON ?= python3
# cursed-jwt with s2n-bignum's verified asm for P-256 and RSA (the root Makefile fetches and builds it, pinned)
RB := build/envoy-$(ARCH)
CJFLAGS := -O3 -DJWT_S2N -I$(ROOT)/include -Wall -Wextra -Wno-unused-function
CJOBJS := $(ROOT)/$(RB)/libs2n.a
ifeq ($(ARCH),x86_64)
CJFLAGS += -DJWT_OSSL_SHA256
CJOBJS += $(ROOT)/$(RB)/sha256_x86_64_ossl.o
endif
CJSRC := cjwt_envoy.c cjwt_envoy.h $(wildcard $(ROOT)/src/*.c $(ROOT)/src/*.inc $(ROOT)/include/*.h)
ABI := third_party/envoy/source/extensions/dynamic_modules/abi/abi.h
ENVOY_SRC := $(addprefix third_party/envoy/source/common/jwt/,check_audience.cc jwks.cc jwt.cc status.cc struct_utils.cc verify.cc)
ENVOY_INC := -I. -Ibench/shim -Ithird_party/envoy -I$(P)/include -I$(P)/bssl/include
ENVOY_LIB := -Wl,--start-group $(P)/lib/*.a $(P)/bssl/lib/libcrypto.a -Wl,--end-group -lpthread

all: $(B)/libcjwt_authn.so

$(B):
	mkdir -p $(B)
$(CJOBJS):
	$(MAKE) -C $(ROOT) B=$(RB) CC=$(CC) $(patsubst $(ROOT)/%,%,$(CJOBJS))
$(ABI):
	./fetch.sh envoy

# one self-contained .so: cjwt_authn.c includes cjwt_envoy.c, which includes cursed-jwt's src/jwt.c (one translation
# unit).  Only the ABI hooks are exported; s2n-bignum stays hidden, so nothing clashes with Envoy's BoringSSL.
$(B)/libcjwt_authn.so: cjwt_authn.c $(CJSRC) $(ABI) $(CJOBJS) | $(B)
	$(CC) $(CJFLAGS) -shared -fPIC -fvisibility=hidden -Ithird_party/envoy $< $(CJOBJS) -Wl,--exclude-libs,ALL -o $@

$(B)/cjwt_envoy.o: $(CJSRC) | $(B)
	$(CC) $(CJFLAGS) -fPIC -c $< -o $@

build/tokens/jwks.json: test/gen_tokens.py
	$(PYTHON) -I test/gen_tokens.py build/tokens 64
tokens: build/tokens/jwks.json
build/tokens-e2e/jwks.json: test/gen_tokens.py
	$(PYTHON) -I test/gen_tokens.py build/tokens-e2e 16 7

build/configs/cjwt.json: test/make_configs.py build/tokens-e2e/jwks.json
	$(PYTHON) -I test/make_configs.py build/tokens-e2e/jwks.json build/configs
configs: build/configs/cjwt.json
functional: $(B)/libcjwt_authn.so configs
	./test/functional.sh

$(P)/.boringssl:
	./fetch.sh deps
	./build-deps.sh
deps: $(P)/.boringssl

# Envoy's library at -O2 (Envoy's release builds are -c opt), against the deps Envoy pins
$(B)/diff: test/diff.cpp $(ENVOY_SRC) $(B)/cjwt_envoy.o $(CJOBJS) $(P)/.boringssl
	$(CXX) -O2 -std=c++20 -DNDEBUG $(ENVOY_INC) $< $(ENVOY_SRC) $(B)/cjwt_envoy.o $(CJOBJS) $(ENVOY_LIB) -o $@
$(B)/bench: bench/bench.cpp $(ENVOY_SRC) $(B)/cjwt_envoy.o $(CJOBJS) $(P)/.boringssl
	$(CXX) -O2 -std=c++20 -DNDEBUG -I$(ROOT)/include $(ENVOY_INC) $< $(ENVOY_SRC) $(B)/cjwt_envoy.o $(CJOBJS) $(ENVOY_LIB) -o $@

# the bench's agreement check (same verdicts and claims on every token) runs before any timing
test: $(B)/diff $(B)/bench build/tokens/jwks.json
	$(B)/bench build/tokens 0.02 >/dev/null && echo "bench agreement: ok"
	$(B)/diff build/tokens $${DIFF_N:-3000} 1
	$(B)/diff build/tokens $${DIFF_N:-3000} 2
# the claims layer (it parses untrusted tokens and JWKS) under ASan + UBSan.  Only the C side is instrumented: abseil
# changes its container layout under ASan, so Envoy's side must match the uninstrumented deps it links.
SAN := -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
$(B)/asan_cjwt_envoy.o: $(CJSRC) | $(B)
	$(CC) $(filter-out -O3,$(CJFLAGS)) $(SAN) -fPIC -c $< -o $@
$(B)/ej/%.o: third_party/envoy/source/common/jwt/%.cc $(P)/.boringssl
	@mkdir -p $(@D)
	$(CXX) -O2 -std=c++20 -DNDEBUG $(ENVOY_INC) -c $< -o $@
$(B)/ej/diff.o: test/diff.cpp $(P)/.boringssl
	@mkdir -p $(@D)
	$(CXX) -O2 -std=c++20 -DNDEBUG $(ENVOY_INC) -c $< -o $@
EJOBJS := $(addprefix $(B)/ej/,$(notdir $(ENVOY_SRC:.cc=.o)))
$(B)/asan_diff: $(B)/ej/diff.o $(EJOBJS) $(B)/asan_cjwt_envoy.o $(CJOBJS)
	$(CXX) -fsanitize=address,undefined $^ $(ENVOY_LIB) -o $@
asan: $(B)/asan_diff build/tokens/jwks.json
	ASAN_OPTIONS=detect_leaks=0 $(B)/asan_diff build/tokens $${DIFF_N:-3000} 3
bench: $(B)/bench build/tokens/jwks.json
	$(B)/bench build/tokens

clean:
	rm -rf build
.PHONY: all tokens configs functional deps test asan bench clean
