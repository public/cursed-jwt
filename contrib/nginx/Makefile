# build/libcursedjwt_nginx.a: cursed-jwt compiled -fPIC for a dynamic nginx module, in the fast public-key build
# (s2n-bignum's P-256 / RSA-2048 assembly, libcrypto BN for other RSA sizes; PK.md).  The module's config links it.
# The root Makefile builds it (its libcursedjwt_all.a: the JWT layer, cursed-crypto and the s2n-bignum kernels), so
# no source list lives here.
#   make                  then: ./configure --with-compat --add-dynamic-module=<this dir> (see README.md)
#   make test             builds nginx at a pinned release with the module and runs test.sh (tested on Linux)
#   make SCREEN=1         adds -DJWT_RSA_SCREEN (opt-in; PK.md)
JWT ?= ../..
OUT ?= build
CC ?= cc
CFLAGS ?= -O3
SCREEN ?= 0
UNAME_M := $(shell uname -m)
SSLDIR := $(shell brew --prefix openssl@3 2>/dev/null)
DEFS := -DJWT_S2N -DJWT_OPENSSL $(if $(SSLDIR),-I$(SSLDIR)/include) $(if $(filter 1,$(SCREEN)),-DJWT_RSA_SCREEN)
ROOTB := $(abspath $(OUT))/root
# x86-64 Linux: OpenSSL's extracted SHA-256 block function for single tokens, as before (and none of the root
# build's other kernels)
ifeq ($(UNAME_M)-$(shell uname -s),x86_64-Linux)
SHA := SHAFLAG=-DJWT_OSSL_SHA256 SHAOBJ=$(ROOTB)/sha256_x86_64_ossl.o
else
SHA := SHAFLAG= SHAOBJ=
endif

# always asks the root Makefile, which rebuilds only what changed
$(OUT)/libcursedjwt_nginx.a: | $(OUT)
	$(MAKE) -C $(JWT) B=$(ROOTB) CC="$(CC)" CFLAGS="$(CFLAGS) -fPIC" $(SHA) LIBFLAGS="$(DEFS)" $(ROOTB)/libcursedjwt_all.a
	cmp -s $(ROOTB)/libcursedjwt_all.a $@ || cp $(ROOTB)/libcursedjwt_all.a $@
	$(JWT)/scripts/check-symbols.sh $@
$(OUT):
	mkdir -p $(OUT)
test: $(OUT)/libcursedjwt_nginx.a
	./test.sh
clean:
	rm -rf $(OUT)
.PHONY: test clean $(OUT)/libcursedjwt_nginx.a
