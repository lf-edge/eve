# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

DOCKER_TARGET ?= load
DOCKER_PLATFORM ?= $(shell uname -s | tr '[A-Z]' '[a-z]')/$(subst aarch64,arm64,$(subst x86_64,amd64,$(shell uname -m)))

# Split comma-separated DOCKER_PLATFORM list into space-separated
COMMA := ,
EMPTY :=
SPACE := $(EMPTY) $(EMPTY)
DOCKER_PLATFORM_LIST := $(subst $(COMMA),$(SPACE),$(DOCKER_PLATFORM))

# Generate target names like build-vm-img-linux-arm64 from DOCKER_PLATFORM_LIST
DOCKER_PLATFORM_TARGETS := $(foreach platform,$(DOCKER_PLATFORM_LIST),build-vm-img-$(subst /,-,$(platform)))

EVETEST_ORG ?= lfedge
LINUXKIT ?= linuxkit
SDN_REPO ?= $(EVETEST_ORG)/evetest-sdn
SDN_DIR := $(CURDIR)
SDN_VM_DIR := $(SDN_DIR)/vm
SDN_VERSION := $(shell grep -v '^\#' VERSION | head -n1)

build-vm-img-%:
	PLATFORM=$(subst -,/,$*); \
	ARCH=$$(echo $$PLATFORM | cut -d/ -f2); \
	SDN_SVC_CONT_TAG=`$(LINUXKIT) pkg show-tag $(SDN_VM_DIR)`-$$ARCH; \
	$(LINUXKIT) pkg build --platforms $$PLATFORM --build-yml build.yml $(SDN_VM_DIR); \
	sed 's|SDN_SERVICE_CONTAINER|'"$$SDN_SVC_CONT_TAG"'|g' $(SDN_VM_DIR)/sdn-vm.yml.in | \
		$(LINUXKIT) build --docker --arch $$ARCH --name sdn-$$ARCH --format raw-bios --dir $(SDN_VM_DIR) -

build: $(DOCKER_PLATFORM_TARGETS)
	docker buildx build --$(DOCKER_TARGET) --platform $(DOCKER_PLATFORM) \
		-f $(SDN_VM_DIR)/Dockerfile.vm \
		--build-arg SDN_VERSION=$(SDN_VERSION) \
		--tag $(SDN_REPO):$(SDN_VERSION) \
		$(SDN_VM_DIR)
