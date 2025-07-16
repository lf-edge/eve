# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# TODO: temporary, change to lfedge
EVETEST_ORG ?= milan4zededa
IMAGE = $(EVETEST_ORG)/evetest-ubuntu-ctr
# Update VERSION whenever there is a change made to this app.
VERSION ?= 1.0

DOCKER_TARGET ?= load
DOCKER_PLATFORM ?= $(shell uname -s | tr '[A-Z]' '[a-z]')/$(subst aarch64,arm64,$(subst x86_64,amd64,$(shell uname -m)))

build:
	docker buildx build \
		--$(DOCKER_TARGET) \
		--platform $(DOCKER_PLATFORM) \
		-t $(IMAGE):$(VERSION) .
