# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

SOURCES=main.go
MODULES=go.mod go.sum
EXECUTABLE=gen-hash-deps

.PHONY: clean

all: $(EXECUTABLE)

$(EXECUTABLE): $(SOURCES) $(MODULES)
	CGO_ENABLED=0 go build -mod=vendor -o $(EXECUTABLE) $(SOURCES)

clean:
	rm -f $(EXECUTABLE)
