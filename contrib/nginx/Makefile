# build/libcursedjwt_nginx.a: cursed-jwt compiled -fPIC for a dynamic nginx module, in the fast public-key build
# (s2n-bignum's P-256 / RSA-2048 assembly, libcrypto BN for other RSA sizes; PK.md).  The module's config links it.
#   make                  then: ./configure --with-compat --add-dynamic-module=<this dir> (see README.md)
#   make test             builds nginx at a pinned release with the module and runs test.sh (tested on Linux)
#   make SCREEN=1         adds -DJWT_RSA_SCREEN (opt-in; PK.md)
JWT ?= ../..
OUT ?= build
CC ?= cc
CFLAGS ?= -O3
SCREEN ?= 0
UNAME_M := $(shell uname -m)
S2N_ARCH := $(if $(filter x86_64,$(UNAME_M)),x86,arm)
S2N_FILES := p256/bignum_montmul_p256 p256/bignum_montsqr_p256 p256/bignum_add_p256 p256/bignum_sub_p256 \
             fastmul/bignum_kmul_32_64 fastmul/bignum_ksqr_32_64 fastmul/bignum_emontredc_8n
# x86-64: the ADX-free P-256 multiply / square, which jwt_pk.inc calls on CPUs (and VMs) that hide BMI2 / ADX, and the
# Ed25519 comb addition (both variants), which jwt_ed25519.inc calls
S2N_FILES += $(if $(filter x86,$(S2N_ARCH)),p256/bignum_montmul_p256_alt p256/bignum_montsqr_p256_alt \
             curve25519/edwards25519_pepadd curve25519/edwards25519_pepadd_alt)
SSLDIR := $(shell brew --prefix openssl@3 2>/dev/null)
DEFS := -DJWT_S2N -DJWT_OPENSSL $(if $(SSLDIR),-I$(SSLDIR)/include) $(if $(filter 1,$(SCREEN)),-DJWT_RSA_SCREEN)
OBJS := $(OUT)/jwt.o $(addprefix $(OUT)/,$(addsuffix .o,$(notdir $(S2N_FILES))))
ifeq ($(UNAME_M)-$(shell uname -s),x86_64-Linux)
DEFS += -DJWT_OSSL_SHA256
OBJS += $(OUT)/sha256_x86_64_ossl.o
endif
S2N_STAMP := $(JWT)/third_party/s2n-bignum/LICENSE

$(OUT)/libcursedjwt_nginx.a: $(OBJS)
	rm -f $@ && ar rcs $@ $^
$(OUT)/jwt.o: $(JWT)/src/jwt.c $(wildcard $(JWT)/src/*.inc) $(JWT)/include/jwt.h | $(OUT)
	$(CC) $(CFLAGS) -fPIC $(DEFS) -Wall -Wno-unused-function -I$(JWT)/include -c $< -o $@
$(OUT)/sha256_x86_64_ossl.o: $(JWT)/src/sha256_x86_64_ossl.S | $(OUT)
	$(CC) -fPIC -c $< -o $@
$(S2N_STAMP):
	$(JWT)/scripts/fetch-s2n-bignum.sh
$(OUT)/%.o: $(S2N_STAMP) | $(OUT)
	$(CC) -fPIC -c -DS2N_BN_HIDE_SYMBOLS=1 -I$(JWT)/third_party/s2n-bignum/include \
	  $$(ls $(JWT)/third_party/s2n-bignum/$(S2N_ARCH)/*/$*.S) -o $@
$(OUT):
	mkdir -p $(OUT)
test: $(OUT)/libcursedjwt_nginx.a
	./test.sh
clean:
	rm -rf $(OUT)
.PHONY: test clean
