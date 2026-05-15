# Copyright (c) 2018-2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#

IMAGE_NAME ?= dnstest

build:
	docker build -t eve-alpine-dnstest ..
	docker build --network=none -t $(IMAGE_NAME) .

test: build
	docker run --rm --privileged $(IMAGE_NAME)

clean:
	docker rmi $(IMAGE_NAME) 2>/dev/null || true

.PHONY: build test clean
