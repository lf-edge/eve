# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

EVETEST_VERSION := $(shell grep -v '^\#' VERSION | head -n1)
EVETEST_ORG ?= lfedge

EVETEST_ADAM_VERSION ?= 0.0.75
EVETEST_ADAM_REPO ?= lfedge/adam

EVETEST_IMAGE := $(EVETEST_ORG)/evetest:$(EVETEST_VERSION)-adam-$(EVETEST_ADAM_VERSION)
EVETEST_API_PORT ?= 50021

PROTOC_VERSION ?= 31.1
PROTOC_GEN_GO_VERSION ?= 1.36.6
PROTOC_GEN_GO_GRPC_VERSION ?= 1.5.1

PROTO_SRC_DIR := $(CURDIR)/grpcapi/proto
EVE_API_DIR ?= $(CURDIR)/grpcapi/eve-api
GEN_GO_DIR := $(CURDIR)/grpcapi/go
PROTOC_OUT_OPTS = paths=source_relative

REPO_ROOT := $(abspath $(CURDIR)/..)

GOBIN ?= $(shell go env GOBIN)
ifeq ($(GOBIN),)
GOBIN := $(HOME)/go/bin
endif

DOCKER_TARGET ?= load
DOCKER_PLATFORM ?= $(shell uname -s | tr '[A-Z]' '[a-z]')/$(subst aarch64,arm64,$(subst x86_64,amd64,$(shell uname -m)))

# Allocate a pseudo-TTY only when stdout is a terminal (i.e. interactive use).
DOCKER_IT := $(shell [ -t 1 ] && echo '-it' || echo '-i')

.PHONY: evetest list-tests _run_protoc proto clone-eve-api _install-broker

list-tests: ensure-evetest-image
	@docker run --rm $(DOCKER_IT) \
		-v $(REPO_ROOT)/evetest/tests:/evetest/tests \
		$(EVETEST_IMAGE)

evetest: ensure-evetest-image
ifndef EVETEST_NAME
ifndef NAME
	$(error EVETEST_NAME or NAME must be set. Run 'make list-tests' to see available tests)
endif
	$(eval EVETEST_NAME := $(NAME))
endif
	$(eval EVE_VERSION_ENV :=)
ifndef EVETEST_EVE_VERSION
	$(eval EVETEST_EVE_VERSION := $(strip $(shell \
		$(MAKE) -s -C $(REPO_ROOT) version 2>/dev/null \
	)))
	$(eval EVE_VERSION_ENV := -e EVETEST_EVE_VERSION=$(EVETEST_EVE_VERSION))
endif
	@echo "Running evetest $(EVETEST_NAME) for EVE $(EVETEST_EVE_VERSION) with evetest image version $(EVETEST_VERSION)-adam-$(EVETEST_ADAM_VERSION)..."
	$(eval ENV_VARS := $(shell env | grep '^EVETEST_' | grep -v '^EVETEST_NAME=' | sed 's/^/-e /'))
	$(eval ARTIFACTS_MOUNT :=)
ifneq ($(EVETEST_COLLECT_ARTIFACTS),)
	$(eval ARTIFACTS_MOUNT := -v $(EVETEST_COLLECT_ARTIFACTS):/artifacts)
endif
	$(eval BROKER_IMAGE_MOUNT :=)
	$(eval BROKER_IMAGE_ENV :=)
	$(eval BROKER_PROXY_CA_MOUNT :=)
ifndef EVETEST_BROKER_ADDRESS
	@# Broker runs inside the container; it stores per-VM disk images on the
	@# host. Default to <home-dir>/.evetest because /tmp is usually on the small
	@# root partition (or tmpfs) and quickly fills up with three-node clusters.
	$(eval IMAGE_DIR := $(or $(EVETEST_BROKER_IMAGE_DIR),$(HOME)/.evetest))
	$(eval BROKER_IMAGE_MOUNT := -v $(IMAGE_DIR):$(IMAGE_DIR))
	$(eval BROKER_IMAGE_ENV := -e EVETEST_BROKER_IMAGE_DIR=$(IMAGE_DIR))
ifneq ($(EVETEST_BROKER_PROXY_CA_CHAIN),)
	$(eval BROKER_PROXY_CA_MOUNT := -v $(EVETEST_BROKER_PROXY_CA_CHAIN):/etc/evetest/proxy/ca-chain.pem:ro)
endif
	@mkdir -p $(IMAGE_DIR)
endif
	@# Detect host Go build cache (optional, used to speed up the test build)
	$(eval HOST_GOCACHE := $(strip $(shell \
		if command -v go >/dev/null 2>&1; then \
			go env GOCACHE 2>/dev/null; \
		fi \
	)))
	$(eval GO_CACHE_MOUNT :=)
	$(eval GO_CACHE_ENV :=)
	$(if $(HOST_GOCACHE), \
		$(eval GO_CACHE_MOUNT := -v $(HOST_GOCACHE):/go-build-cache) \
		$(eval GO_CACHE_ENV := -e GOCACHE=/go-build-cache) \
	)
	$(eval DOCKER_CONFIG_MOUNT :=)
	$(if $(wildcard $(HOME)/.docker/config.json), \
		$(eval DOCKER_CONFIG_MOUNT := -v $(HOME)/.docker/config.json:/root/.docker/config.json:ro) \
	)
	$(eval EVETEST_HOST_UID := $(shell id -u))
	$(eval EVETEST_HOST_GID := $(shell id -g))
	@# On Linux, only pass /dev/kvm if it exists on the host. On macOS, Docker
	@# Desktop's Linux VM does not support nested virtualization, so /dev/kvm is
	@# never available; omit the flag so the container starts and QEMU falls back
	@# to TCG software emulation.
	$(eval KVM_DEVICE := $(shell [ -e /dev/kvm ] && echo '--device=/dev/kvm'))
	@if docker inspect --type container evetest-$(EVETEST_API_PORT) >/dev/null 2>&1; then \
		echo ""; \
		echo "Error: evetest instance 'evetest-$(EVETEST_API_PORT)' is already running."; \
		echo ""; \
		echo "To run multiple instances in parallel, set a different EVETEST_API_PORT for"; \
		echo "each one (default is 50021):"; \
		echo ""; \
		echo "  EVETEST_API_PORT=50022 make evetest NAME=<test-name>"; \
		echo ""; \
		echo "When using the evetest CLI against a non-default port, set the same variable:"; \
		echo ""; \
		echo "  EVETEST_API_PORT=50022 evetest status"; \
		echo ""; \
		exit 1; \
	fi >&2
	docker run --rm $(DOCKER_IT) \
		--name evetest-$(EVETEST_API_PORT) \
		-p $(EVETEST_API_PORT):$(EVETEST_API_PORT) \
		-v $(REPO_ROOT)/evetest/tests:/evetest/tests \
		-v $(REPO_ROOT)/evetest/netmodels:/evetest/netmodels \
		-v $(REPO_ROOT)/evetest/matchers:/evetest/matchers \
		-v /var/run/docker.sock:/var/run/docker.sock \
		--cap-add=NET_ADMIN \
		--sysctl net.ipv6.conf.all.disable_ipv6=0 \
		--sysctl net.ipv6.conf.default.disable_ipv6=0 \
		--sysctl net.ipv6.conf.all.forwarding=1 \
		--sysctl net.ipv6.conf.default.forwarding=1 \
		--device=/dev/net/tun \
		$(KVM_DEVICE) \
		$(ARTIFACTS_MOUNT) \
		$(BROKER_IMAGE_MOUNT) \
		$(BROKER_PROXY_CA_MOUNT) \
		$(GO_CACHE_MOUNT) \
		$(DOCKER_CONFIG_MOUNT) \
		$(ENV_VARS) \
		$(EVE_VERSION_ENV) \
		$(BROKER_IMAGE_ENV) \
		$(GO_CACHE_ENV) \
		-e EVETEST_NAME=$(EVETEST_NAME) \
		-e EVETEST_HOST_UID=$(EVETEST_HOST_UID) \
		-e EVETEST_HOST_GID=$(EVETEST_HOST_GID) \
		$(EVETEST_ORG)/evetest:$(EVETEST_VERSION)-adam-$(EVETEST_ADAM_VERSION)

ensure-evetest-image:
	@if ! docker image inspect $(EVETEST_IMAGE) >/dev/null 2>&1; then \
		echo "Docker image $(EVETEST_IMAGE) not found locally, trying to pull..."; \
		if ! docker pull $(EVETEST_IMAGE); then \
			echo "Pull failed, building image locally..."; \
			$(MAKE) build-container; \
		fi; \
	fi

# Internal target: invoked by proto inside the builder container.
# Run make proto instead.
_run_protoc:
	mkdir -p $(GEN_GO_DIR)
	protoc -I$(PROTO_SRC_DIR) -I$(EVE_API_DIR)/proto \
		--go_out=$(PROTOC_OUT_OPTS):$(GEN_GO_DIR) \
		--go-grpc_out=$(PROTOC_OUT_OPTS):$(GEN_GO_DIR) \
		$(PROTO_SRC_DIR)/*.proto

proto: clone-eve-api clean-proto-go
	docker build \
		--build-arg PROTOC_VERSION=$(PROTOC_VERSION) \
		--build-arg PROTOC_GEN_GO_VERSION=$(PROTOC_GEN_GO_VERSION) \
		--build-arg PROTOC_GEN_GO_GRPC_VERSION=$(PROTOC_GEN_GO_GRPC_VERSION) \
		-t evetest-api-builder -f protobuilder/Dockerfile .
	docker run --rm \
		--env HOME=/src \
		-v $(CURDIR):/src \
		-w /src \
		-u $$(id -u):$$(id -g) \
		evetest-api-builder make _run_protoc

clone-eve-api:
	git -C $(REPO_ROOT) submodule update --init evetest/grpcapi/eve-api

clean-proto-go:
	rm -rf $(GEN_GO_DIR)/*.pb.go

build-container:
	docker buildx build \
		--$(DOCKER_TARGET) \
		--platform $(DOCKER_PLATFORM) \
		--build-arg EVETEST_VERSION=$(EVETEST_VERSION) \
		--build-arg EVETEST_ADAM_REPO=$(EVETEST_ADAM_REPO) \
		--build-arg EVETEST_ADAM_VERSION=$(EVETEST_ADAM_VERSION) \
		-t $(EVETEST_ORG)/evetest:$(EVETEST_VERSION)-adam-$(EVETEST_ADAM_VERSION) \
		-f Dockerfile.evetest .

build-test-apps:
	@for app in testapps/*/; do \
		echo "Building $$app..."; \
		$(MAKE) -C $$app build || exit 1; \
	done

build-broker-container:
	@echo "Building Docker image $(EVETEST_ORG)/evetest-broker:$(EVETEST_VERSION)"
	docker buildx build \
		--$(DOCKER_TARGET) \
		--platform $(DOCKER_PLATFORM) \
		--build-arg EVETEST_VERSION=$(EVETEST_VERSION) \
		-t $(EVETEST_ORG)/evetest-broker:$(EVETEST_VERSION) \
		-f Dockerfile.broker .

# Create the eve-broker user/group for the libvirt provider, and prepare the
# image directory so libvirt-qemu can read/write VM disks there.
# Pass EVETEST_BROKER_IMAGE_DIR=/some/path to use a custom image directory
# (default: /home/eve-broker/images, which lives on /home - usually a larger
# partition than /var). Note: sudo strips environment variables, so set it
# on the make command line, e.g.:
#     sudo make setup-broker-user EVETEST_BROKER_IMAGE_DIR=/data/evetest
setup-broker-user:
	@echo "Setting up eve-broker user and groups..."
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "Error: This target must be run as root."; \
		echo "       Please rerun with: sudo make setup-broker-user"; \
		exit 1; \
	fi
	@if ! id -u eve-broker >/dev/null 2>&1; then \
		echo "Creating eve-broker user and group..."; \
		groupadd -f eve-broker; \
		useradd -r -g eve-broker -m -s /bin/bash eve-broker; \
	else \
		echo "eve-broker user already exists"; \
	fi
	@echo "Adding eve-broker to docker and libvirt groups (for socket access)..."
	usermod -aG docker eve-broker || true
	usermod -aG libvirt eve-broker || true
	@echo "Allowing libvirt-qemu to access eve-broker-owned images..."
	usermod -aG eve-broker libvirt-qemu || true
	$(eval IMAGE_DIR := $(or $(EVETEST_BROKER_IMAGE_DIR),/home/eve-broker/images))
	@echo "Configuring image directory $(IMAGE_DIR) ownership and permissions..."
	mkdir -p $(IMAGE_DIR)
	chgrp libvirt $(IMAGE_DIR)
	chmod 771 $(IMAGE_DIR)
	@echo "Image directory $(IMAGE_DIR) is now writable by libvirt group (eve-broker is a member)."
	@# Verify libvirt-qemu can actually reach the image directory.
	@if id -u libvirt-qemu >/dev/null 2>&1; then \
		if ! sudo -u libvirt-qemu test -x $(IMAGE_DIR); then \
			echo "Warning: libvirt-qemu cannot traverse $(IMAGE_DIR)."; \
			echo "         Check parent directory permissions or pick a different EVETEST_BROKER_IMAGE_DIR."; \
		fi; \
	fi
	@echo "setup-broker-user complete. You can now run the container safely as eve-broker."

# Run broker container for the libvirt provider.
run-broker-container:
	@echo "Running Evetest Broker version $(EVETEST_VERSION)..."
	# Capture EVETEST_* and DOCKER_* environment variables
	$(eval EV_VARS := $(shell env | grep -E '^(EVETEST|DOCKER)_' | sed 's/^/-e /'))
	$(eval IMAGE_DIR := $(or $(EVETEST_BROKER_IMAGE_DIR),/home/eve-broker/images))
	# Optionally mount (docker registry and/or app image datastore) proxy CA chain if provided.
ifneq ($(EVETEST_BROKER_PROXY_CA_CHAIN),)
	$(eval PROXY_CA_MOUNT := -v $(EVETEST_BROKER_PROXY_CA_CHAIN):/etc/evetest/proxy/ca-chain.pem:ro)
endif
	# Determine group IDs dynamically
	$(eval LIBVIRT_GID := $(shell getent group libvirt | cut -d: -f3))
	$(eval DOCKER_GID := $(shell getent group docker | cut -d: -f3))
	# Determine user for container (if eve-broker exists)
	$(eval EVE_BROKER_UID := $(shell getent passwd eve-broker | cut -d: -f3))
	$(eval EVE_BROKER_GID := $(shell getent passwd eve-broker | cut -d: -f4))
	@if [ -n "$(EVE_BROKER_UID)" ]; then \
		echo "Running container as eve-broker user ($(EVE_BROKER_UID):$(EVE_BROKER_GID))..."; \
		USER_OPT="-u $(EVE_BROKER_UID):$(EVE_BROKER_GID)"; \
	else \
		echo "Warning: eve-broker user not found. Running as root."; \
		echo "         To improve security, run: sudo make setup-broker-user"; \
		USER_OPT=""; \
	fi; \
	# Run the broker container in privileged mode to allow enabling
	# forwarding of link-local protocols (EAPOL, LLDP) on the xconnect bridges.
	docker run --rm -it \
		$$USER_OPT \
		--group-add $(LIBVIRT_GID) \
		--group-add $(DOCKER_GID) \
		$(EV_VARS) \
		$(PROXY_CA_MOUNT) \
		--network host \
		--privileged \
		-v /tmp:/tmp \
		-v /var/run/libvirt/:/var/run/libvirt/ \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v ~/.docker:/root/.docker:ro \
		-v $(IMAGE_DIR):$(IMAGE_DIR) \
		$(EVETEST_ORG)/evetest-broker:$(EVETEST_VERSION)

# Internal target: invoked by Dockerfile.broker inside the builder container.
# Run build-broker-container instead.
_install-broker:
	@echo "Installing evetest Broker version $(EVETEST_VERSION)..."
	cd ./broker && go build -ldflags "-X main.version=$(EVETEST_VERSION)" -o $(GOBIN)/evetest-broker
	@echo "Installed evetest Broker to $(GOBIN)/evetest-broker"

install-cli:
	@echo "Installing evetest CLI version $(EVETEST_VERSION)..."
	cd ./cli && go build -ldflags "-X main.version=$(EVETEST_VERSION)" -o $(GOBIN)/evetest
	@echo "Installed evetest CLI to $(GOBIN)/evetest"

build-sdn-container:
	@$(MAKE) -C sdn build
