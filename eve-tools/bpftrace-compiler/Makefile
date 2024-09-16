# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

bpftrace-compiler: *.go
	go build

.PHONY: test docker-test

bare-test:
	go test -test.timeout 30m -v -race .

test:
	docker run --cap-add=SYS_PTRACE --cap-add=SYS_ADMIN --privileged --security-opt seccomp=unconfined -v $(shell pwd):/src $(shell docker build -q .) make bare-test
