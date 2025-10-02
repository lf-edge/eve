# Copyright (c) 2025  Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

.PHONY: test-collect-info test-openssh debug-docker-image-build

debug-docker-image-build: Dockerfile
	make -C ../../ debug-cache-export-docker-load
	docker build --target build .

test-collect-info: debug-docker-image-build
	docker run -w /collect-info-test -v $(realpath collect-info-test):/collect-info-test  -it $(shell docker build --target build -q .) go test
test-ssh: debug-docker-image-build
	docker run -w /usr/src/openssh -it $(shell docker build --target build -q .) make tests


test: test-collect-info test-ssh
