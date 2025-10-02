# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

.PHONY: clean test all

all: cmd/git-exec/git-exec cmd/gc/gc cmd/ge/ge

cmd/git-exec/git-exec: pkg/*.go cmd/git-exec/*.go
	go build -C cmd/git-exec/

cmd/gc/gc: pkg/*.go cmd/gc/*.go
	go build -C cmd/gc/

cmd/ge/ge: pkg/*.go cmd/ge/*.go
	go build -C cmd/ge/


clean:
	rm -fv ./cmd/git-exec/git-exec ./cmd/gc/gc ./cmd/ge/ge

test:
	go test -C pkg/ -v -race
	go test -C pkg -fuzz=^FuzzLCSDiff$$ -v -fuzztime=1m
	go test -C pkg -fuzz=^FuzzLCS$$ -v -fuzztime=1m
