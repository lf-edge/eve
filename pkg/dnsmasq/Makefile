# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

HOSTARCH        := $(subst aarch64,arm64,$(subst x86_64,amd64,$(shell uname -m)))
ZARCH           ?= $(HOSTARCH)
DOCKER_LIKE_LKT := ../../build-tools/bin/linuxkit pkg build --network --platforms linux/$(ZARCH) --dry-run --force ./ | tail -n1 | perl -pe 's/ buildx / /g'

.PHONY: test

build-docker-test-dependencies:
	make -C ../../ dnsmasq-cache-export-docker-load
build-docker-test-build: build-docker-test-dependencies
	$(shell $(DOCKER_LIKE_LKT)) --load --target test

test: build-docker-test-build
	docker run --privileged $(shell $(shell $(DOCKER_LIKE_LKT)) --load -q --target test) go test -v
