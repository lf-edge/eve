# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

bpftrace-compiler: *.go
	go build

.PHONY: test bare-test docker-test

bare-test:
	go test -coverprofile=coverage.txt -covermode=atomic -test.timeout 1h -v -race .

show-coverage:
	go tool cover -html=coverage.txt

test: bare-test

kernel-commits.mk: ../../kernel-commits.mk
	cp ../../kernel-commits.mk .

docker-test: kernel-commits.mk
	docker run --cap-add=SYS_PTRACE --cap-add=SYS_ADMIN --privileged --security-opt seccomp=unconfined -v $(shell pwd):/src $(shell docker build -q .) make bare-test
