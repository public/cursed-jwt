# cursed_crypto (Python): batch verification for pyca/cryptography key objects, backed by cursed-crypto.
#   make              build the extension in place (src/cursed_crypto/_native*.so)
#   make test         the differential suite vs pyca/cryptography (Wycheproof, RFC 4231 / 8032, edge cases, random
#                     keys, Hypothesis), then the batch tests again under CC_CPU_MASK for each engine this CPU has
#   make test-quick   the suite once, default engine, fewer Hypothesis examples
#   make asan         the suite against an ASan + UBSan build of the extension (LD_PRELOAD; Linux, gcc or clang)
#   make dist         sdist + wheel (built from the sdist) into build/dist; checks both carry the licence texts
#   make venv         build/venv with cryptography, pytest, hypothesis, setuptools, build (network);
#                     then make PYTHON=build/venv/bin/python test
#   make bench        the benchmark (bench/bench.py) on this machine
# Needs a Python with cryptography, pytest and hypothesis.  The vectors come from ../../scripts/fetch-vectors.sh
# (network, pinned SHA-256s).  Not part of the root `make test`.
PYTHON ?= python3
B := build
CC ?= cc
EX ?= 300
PYTEST := -m pytest -q -p no:cacheprovider
SAN := -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
SRC := setup.py src/cursed_crypto/_native.c $(wildcard ../../crypto/src/*.c ../../crypto/src/*.h ../../crypto/src/*.inc \
         ../../crypto/src/*.S ../../crypto/src/fiat/*.c ../../crypto/include/*.h)

all: $(B)/.inplace

$(B)/.inplace: $(SRC)
	CC=$(CC) $(PYTHON) setup.py -q build_ext --inplace --build-temp $(B)/tmp
	@mkdir -p $(B) && touch $@

vectors:
	../../scripts/fetch-vectors.sh >/dev/null

test: $(B)/.inplace vectors
	HYPOTHESIS_EXAMPLES=$(EX) PYTHONPATH=src $(PYTHON) $(PYTEST) tests
	HYPOTHESIS_EXAMPLES=100 PYTHONPATH=src $(PYTHON) tests/run_engines.py -q -p no:cacheprovider \
	  tests/test_differential.py tests/test_props.py tests/test_vectors.py tests/test_sign.py

test-quick: $(B)/.inplace vectors
	HYPOTHESIS_EXAMPLES=50 PYTHONPATH=src $(PYTHON) $(PYTEST) tests

# ASan + UBSan: the extension built with the sanitizers into build/asan, the interpreter run with their runtimes
# preloaded (CPython itself isn't instrumented; PYTHONMALLOC=malloc puts its allocations under ASan too)
asan: vectors
	rm -rf $(B)/asan $(B)/asan-tmp
	mkdir -p $(B)/asan/cursed_crypto
	CC=$(CC) CURSED_CRYPTO_CFLAGS="$(SAN)" CURSED_CRYPTO_LDFLAGS="-fsanitize=address,undefined" \
	  $(PYTHON) setup.py -q build_ext --build-lib $(B)/asan --build-temp $(B)/asan-tmp
	cp src/cursed_crypto/__init__.py src/cursed_crypto/py.typed $(B)/asan/cursed_crypto/
	LD_PRELOAD="$$($(CC) -print-file-name=libasan.so) $$($(CC) -print-file-name=libubsan.so)" \
	  ASAN_OPTIONS=detect_leaks=0 PYTHONMALLOC=malloc HYPOTHESIS_EXAMPLES=100 PYTHONPATH=$(B)/asan \
	  $(PYTHON) $(PYTEST) tests

dist:
	rm -rf $(B)/dist
	$(PYTHON) -m build --no-isolation -o $(B)/dist .
	$(PYTHON) tests/check_dist.py $(B)/dist

venv:
	$(PYTHON) -m venv $(B)/venv
	$(B)/venv/bin/pip -q install cryptography pytest hypothesis setuptools build

bench: $(B)/.inplace
	PYTHONPATH=src $(PYTHON) bench/bench.py

clean:
	rm -rf $(B) vendor dist src/*.egg-info .hypothesis
	rm -f src/cursed_crypto/*.so

.PHONY: all vectors test test-quick asan dist venv bench clean
