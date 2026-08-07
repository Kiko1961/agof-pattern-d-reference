# AGOF(TM) Pattern D - public self-verification reference
# Targets: make lib (build io_uring primitive), make test (run the 14 tests)
PY ?= python3

.PHONY: all lib test clean
all: lib test

lib: libiouring_bypass.so
libiouring_bypass.so: iouring_bypass.c
	gcc -O2 -fPIC -shared -o $@ $<

test: lib
	$(PY) -m pytest test_pattern_d_conformance.py -v

clean:
	rm -f libiouring_bypass.so
	rm -rf .pytest_cache __pycache__
