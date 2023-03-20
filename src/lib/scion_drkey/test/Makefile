# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2021 ETH Zurich

LDFLAGS += -L ../ -ldrkey -lpthread

build/sdrkey_fetcher_test: sdrkey_test.c | build
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -f -r build