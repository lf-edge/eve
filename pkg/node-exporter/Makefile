# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

.PHONY: test
test:
	make -C ../../ node-exporter-cache-export-docker-load
	docker build --no-cache --rm --target test .
