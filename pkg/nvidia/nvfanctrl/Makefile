# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
SOURCES=go.mod main.go
BINARY=nvfanctrl

.PHONY: clean

all: $(BINARY)

$(BINARY):$(SOURCES)
	go build -o $@ .

clean:
	rm -f $(BINARY)
