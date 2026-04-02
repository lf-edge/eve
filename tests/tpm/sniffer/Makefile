# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

.PHONY: all clean

BINARY = sniffer

all: $(BINARY)

$(BINARY): main.go go.mod go.sum
	go build -o $(BINARY) .

clean:
	rm -f $(BINARY)
