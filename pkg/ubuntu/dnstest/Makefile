# Copyright (c) 2018-2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Runs the dnsmasq test against the lfedge/eve-ubuntu image of this checkout,
# the one the other packages install dnsmasq from.

IMAGE_NAME ?= dnstest

build:
	$(MAKE) -C ../../.. ubuntu-cache-export-docker-load
	docker tag "$$(cd ../../.. && build-tools/bin/linuxkit pkg show-tag pkg/ubuntu)" eve-ubuntu-dnstest
	docker build --network=none -t $(IMAGE_NAME) .

test: build
	docker run --rm --privileged $(IMAGE_NAME)

clean:
	docker rmi $(IMAGE_NAME) 2>/dev/null || true

.PHONY: build test clean
