# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2021 ETH Zurich

PKGCONF ?= pkg-config
LDFLAGS += $(shell $(PKGCONF) --static --libs libdpdk)
CFLAGS += $(shell $(PKGCONF) --cflags libdpdk)

build/asdict_test: asdict_test.c ../asdict.c | build
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(DEBUG)

build:
	@mkdir -p $@

.PHONY: asdict_test_debug
asdict_test_debug: DEBUG := -g
asdict_test_debug: build/asdict_test

.PHONY: test_asdict
test_asdict: build/asdict_test
	./build/asdict_test --no-huge

.PHONY: test_all
test_all: test_asdict

.PHONY: clean
clean:
	rm -f -r build