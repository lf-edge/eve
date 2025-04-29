# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

.PHONY: test

test:
	docker run --privileged $(shell docker build --target=test -q .) go test -v
