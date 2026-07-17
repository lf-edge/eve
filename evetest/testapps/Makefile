# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# Builds (and, with DOCKER_TARGET=push, pushes) every test app under this
# directory by invoking each subdirectory's own "build" target. Adding a new
# test app is picked up here -- and by .github/workflows/publish-evetest.yml,
# which just calls this Makefile -- automatically, with no changes needed in
# either place. See README.md in this directory for how to add one.

build:
	@for dir in */; do \
		app=$${dir%/}; \
		[ -f "$$app/Makefile" ] || continue; \
		echo "Building $$app..."; \
		$(MAKE) -C "$$app" build || exit 1; \
	done
