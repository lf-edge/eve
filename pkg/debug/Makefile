# Copyright (c) 2025  Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

.PHONY: test
test:
	make -C ../../ debug-cache-export-docker-load
	docker build --rm --target test .
