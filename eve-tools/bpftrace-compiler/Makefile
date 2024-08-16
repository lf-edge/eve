# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

bpftrace-compiler: *.go
	go build

.PHONY: test

test:
	go test -test.timeout 30m -v -race .
