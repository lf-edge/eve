# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

.PHONY: test

test:
	make -C ../../ vtpm-cache-export-docker-load
	# swtpm daemonizes; without an init as PID 1 its exited instances stay zombies
	# and every health check waits for the full pid timeout
	docker run --rm --init \
		-v $$(pwd):/output \
		$$(docker build --target=test -q .) \
		env CGO_ENABLED=1 go test -v -race -timeout 30m \
		-coverprofile="/output/vtpm.coverage.txt" \
		-covermode=atomic
