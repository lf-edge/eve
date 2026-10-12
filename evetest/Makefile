# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

EVETEST_ORG ?= lfedge

# Image tags are content hashes (see content-hash.sh), so they change exactly
# when the sources baked into the image change. EVETEST_VERSION tags both the
# evetest and the evetest-broker image, SDN_VERSION the evetest-sdn image.
# Skipped when already set, e.g. inside the image builds, which have no git.
ifndef EVETEST_VERSION
EVETEST_VERSION := $(shell ./content-hash.sh framework)
endif
ifndef SDN_VERSION
SDN_VERSION := $(shell ./content-hash.sh sdn)
endif

EVETEST_ADAM_VERSION ?= 0.0.85
EVETEST_ADAM_REPO ?= lfedge/adam

# Repository holding built EVE images (mirrors constants.DefaultEVERepo).
EVETEST_EVE_REPO ?= lfedge/eve

# linuxkit comes from the EVE repo's build tools (see ../Makefile and
# ../mk/linuxkit.mk); it is built on demand via the root's "linuxkit" target
# and handed to the sdn sub-make through LINUXKIT, so it does not have to be
# on PATH.
BUILDTOOLS_BIN := $(abspath $(CURDIR)/../build-tools/bin)
LINUXKIT := $(BUILDTOOLS_BIN)/linuxkit

# Authenticate Dockerfile `ADD <github git url>` fetches, as ../Makefile does.
# linuxkit only supports --secret when built from the pinned LINUXKIT_GIT_REF,
# not from LINUXKIT_SRC or as a release (LINUXKIT_GIT_URL=); see ../mk/linuxkit.mk.
COMMA := ,
BUILD_SECRET_OPTS := $(if $(GITHUB_TOKEN),--secret id=GIT_AUTH_TOKEN.github.com$(COMMA)env=GITHUB_TOKEN)
LINUXKIT_PINNED := $(if $(LINUXKIT_SRC),,$(if $(filter undefined,$(origin LINUXKIT_GIT_URL)),y,$(LINUXKIT_GIT_URL)))
LINUXKIT_SECRET_OPTS := $(if $(LINUXKIT_PINNED),$(BUILD_SECRET_OPTS))

EVETEST_IMAGE := $(EVETEST_ORG)/evetest:$(EVETEST_VERSION)
EVETEST_API_PORT ?= 50021
SDN_IMAGE := $(EVETEST_ORG)/evetest-sdn:$(SDN_VERSION)

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

.PHONY: version sdn-version evetest list-tests list-test-suites _run_protoc proto clone-eve-api _install-broker proxmox-broker-installer

# Image tags of the current sources.
version:
	@echo $(EVETEST_VERSION)

sdn-version:
	@echo $(SDN_VERSION)

list-tests: ensure-evetest-image
	@docker run --rm $(DOCKER_IT) \
		-v $(REPO_ROOT)/evetest/tests:/evetest/tests \
		$(EVETEST_IMAGE)

# Plain list of test suite names, one per line -- e.g. for a CI job matrix.
list-test-suites: ensure-evetest-image
	@docker run --rm $(DOCKER_IT) \
		-v $(REPO_ROOT)/evetest/tests:/evetest/tests \
		-e EVETEST_LIST_SUITES_ONLY=true \
		$(EVETEST_IMAGE)

evetest: ensure-evetest-image ensure-sdn-image
ifndef EVETEST_NAME
ifndef NAME
	$(error EVETEST_NAME or NAME must be set. Run 'make list-tests' to see available tests)
endif
	$(eval EVETEST_NAME := $(NAME))
endif
	@# Default the EVE version to this checkout's, which is what the container
	@# transport needs to name an image. Deliberately NOT defaulted under
	@# EVETEST_EVE_LIVE_IMAGE: the live transport looks the version up among the
	@# local builds under dist/, and `make version` reports the working tree as it
	@# is *now* -- including a "-dirty-<timestamp>" suffix -- which is a directory
	@# that generally does not exist. Left empty, the newest build (dist/<arch>/
	@# current) is used and reports its own version. An EVETEST_EVE_VERSION the
	@# operator sets explicitly is always honoured, by both transports.
	$(eval EVE_VERSION_ENV :=)
ifndef EVETEST_EVE_VERSION
ifeq ($(strip $(filter-out false False FALSE 0 f F,$(EVETEST_EVE_LIVE_IMAGE))),)
	@# Resolve which EVE version to test. On a dirty tree 'make version' embeds
	@# the wall-clock minute of *this* invocation, so it almost never matches
	@# the timestamp baked into the image tag by an earlier 'make eve' run.
	@# In that case fall back to the version recorded by the last completed
	@# build (dist/<arch>/current, read via 'make currentversion'), provided it
	@# is a dirty build of the same commit and its EVE Docker image exists
	@# locally. 'make currentversion' reports the full version including the
	@# hypervisor/arch suffix; strip it by anchoring on the dirty timestamp.
	$(eval EVETEST_EVE_VERSION := $(strip $(shell \
		v="$$($(MAKE) -s -C $(REPO_ROOT) version 2>/dev/null)"; \
		if echo "$$v" | grep -q -e '-dirty-' && \
			! docker images --format '{{.Tag}}' "$(EVETEST_EVE_REPO)" 2>/dev/null \
				| grep -q "^$$v-"; then \
			base="$${v%%-dirty-*}-dirty-"; \
			cur="$$($(MAKE) -s -C $(REPO_ROOT) currentversion 2>/dev/null \
				| sed -E 's/(-dirty-[0-9]{4}-[0-9]{2}-[0-9]{2}\.[0-9]{2}\.[0-9]{2}).*/\1/')"; \
			if [ -n "$$cur" ] && [ "$${cur#"$$base"}" != "$$cur" ] && \
				docker images --format '{{.Tag}}' "$(EVETEST_EVE_REPO)" 2>/dev/null \
					| grep -q "^$$cur-"; then \
				echo "NOTE: no local EVE image for dirty version $$v;" \
					"falling back to last built version $$cur (from dist/current)." >&2; \
				echo "NOTE: run 'make eve' first if EVE sources changed since that build." >&2; \
				v="$$cur"; \
			fi; \
		fi; \
		echo "$$v" \
	)))
	$(eval EVE_VERSION_ENV := -e EVETEST_EVE_VERSION=$(EVETEST_EVE_VERSION))
endif
endif
	@echo "Running evetest $(EVETEST_NAME) for EVE $(or $(EVETEST_EVE_VERSION),the newest local build) with evetest image version $(EVETEST_VERSION), SDN image version $(SDN_VERSION) (adam $(EVETEST_ADAM_VERSION))..."
	$(eval ENV_VARS := $(shell env | grep '^EVETEST_' | grep -v '^EVETEST_NAME=' | sed 's/^/-e /'))
	@# Tell the harness which SDN image matches this checkout, unless overridden.
ifndef EVETEST_SDN_VERSION
	$(eval ENV_VARS += -e EVETEST_SDN_VERSION=$(SDN_VERSION))
endif
	$(eval ARTIFACTS_MOUNT :=)
ifneq ($(EVETEST_COLLECT_ARTIFACTS),)
	$(eval ARTIFACTS_MOUNT := -v $(EVETEST_COLLECT_ARTIFACTS):/artifacts)
endif
	$(eval BROKER_IMAGE_MOUNT :=)
	$(eval BROKER_IMAGE_ENV :=)
	$(eval BROKER_PROXY_CA_MOUNT :=)
	@# Always mount the evetest data directory so that Docker bind-mounts issued
	@# from inside the container (e.g. rootfs extraction for upgrades) resolve
	@# correctly on the host.
	$(eval EVETEST_HOME_DIR := $(HOME)/.evetest)
	$(eval EVETEST_HOME_MOUNT := -v $(EVETEST_HOME_DIR):$(EVETEST_HOME_DIR))
	@# The instances directory is created here, as the host user, so that the
	@# registry records the (root) container writes into it can be removed by
	@# the evetest CLI.
	@mkdir -p $(EVETEST_HOME_DIR)/instances
	@# Tests that compile a bpftrace script for the device's kernel (see
	@# tests/apps/pciaccess_helpers_test.go) run eve-tools/bpftrace-compiler
	@# from the checkout, mounted at the same position relative to /evetest/tests
	@# as in the repository. The compiler keeps the pulled kernel images in the
	@# linuxkit cache and the compiled scripts in its own cache, which it uses
	@# only when the directory exists; mounting both from the evetest home makes
	@# them survive runs.
	$(eval BPFTRACE_COMPILER_MOUNTS := \
		-v $(REPO_ROOT)/eve-tools/bpftrace-compiler:/eve-tools/bpftrace-compiler:ro \
		-v $(EVETEST_HOME_DIR)/linuxkit-cache:/root/.linuxkit/cache \
		-v $(EVETEST_HOME_DIR)/bpftrace-compiler-cache:/root/.bpftrace-compiler/cache)
	@mkdir -p $(EVETEST_HOME_DIR)/linuxkit-cache $(EVETEST_HOME_DIR)/bpftrace-compiler-cache
ifndef EVETEST_BROKER_ADDRESS
	@# Broker runs inside the container; it stores per-VM disk images on the
	@# host. Default to <home-dir>/.evetest because /tmp is usually on the small
	@# root partition (or tmpfs) and quickly fills up with three-node clusters.
	$(eval IMAGE_DIR := $(or $(EVETEST_BROKER_IMAGE_DIR),$(EVETEST_HOME_DIR)))
	@# Only add a broker image mount when the image dir differs from EVETEST_HOME_DIR
	@# to avoid a duplicate bind-mount error.
	$(eval BROKER_IMAGE_MOUNT := $(if $(filter-out $(EVETEST_HOME_DIR),$(IMAGE_DIR)),-v $(IMAGE_DIR):$(IMAGE_DIR),))
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
	@# Mount the EVE build output directory so a locally built live.qcow2 is
	@# visible inside the container. Same absolute path on both sides so that
	@# EVETEST_EVE_DIST_DIR is valid both inside the container and in any error
	@# message a developer sees on the host. Read-write: the harness caches the
	@# image's sha256 in a sidecar file next to it. Only added when a local
	@# build exists, so nothing breaks without one.
	$(eval EVETEST_DIST_DIR := $(or $(EVETEST_EVE_DIST_DIR),$(REPO_ROOT)/dist))
	$(eval DIST_DIR_MOUNT :=)
	$(eval DIST_DIR_ENV :=)
	$(if $(wildcard $(EVETEST_DIST_DIR)), \
		$(eval DIST_DIR_MOUNT := -v $(EVETEST_DIST_DIR):$(EVETEST_DIST_DIR)) \
		$(eval DIST_DIR_ENV := -e EVETEST_EVE_DIST_DIR=$(EVETEST_DIST_DIR)) \
	)
	@if docker inspect --type container evetest-$(EVETEST_API_PORT) >/dev/null 2>&1; then \
		echo ""; \
		echo "Error: evetest instance 'evetest-$(EVETEST_API_PORT)' is already running."; \
		echo ""; \
		echo "To run multiple instances in parallel, set a different EVETEST_API_PORT for"; \
		echo "each one (default is 50021):"; \
		echo ""; \
		echo "  EVETEST_API_PORT=50022 make evetest NAME=<test-name>"; \
		echo ""; \
		echo "The evetest CLI finds running instances on its own. With several running,"; \
		echo "choose one for the current terminal, or per command:"; \
		echo ""; \
		echo "  evetest instances"; \
		echo "  evetest use <name>"; \
		echo "  evetest -i <name> status"; \
		echo ""; \
		exit 1; \
	fi >&2
	@# Colorize framework log output only when stdout is a terminal. The test
	@# runs inside the container where stdout is never a TTY (go test pipes it),
	@# so the detection must happen here. It also cannot use $(shell [ -t 1 ])
	@# because within $(shell) stdout is make's capture pipe, never a terminal;
	@# only a recipe shell sees make's real stdout.
	[ -t 1 ] && COLOR=true || COLOR=false; \
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
		$(EVETEST_HOME_MOUNT) \
		$(BPFTRACE_COMPILER_MOUNTS) \
		$(BROKER_IMAGE_MOUNT) \
		$(BROKER_PROXY_CA_MOUNT) \
		$(DIST_DIR_MOUNT) \
		$(GO_CACHE_MOUNT) \
		$(DOCKER_CONFIG_MOUNT) \
		-e EVETEST_COLOR_OUTPUT=$$COLOR \
		$(ENV_VARS) \
		$(EVE_VERSION_ENV) \
		$(BROKER_IMAGE_ENV) \
		$(DIST_DIR_ENV) \
		$(GO_CACHE_ENV) \
		-e EVETEST_NAME=$(EVETEST_NAME) \
		-e EVETEST_API_PORT=$(EVETEST_API_PORT) \
		-e EVETEST_CONTAINER_NAME=evetest-$(EVETEST_API_PORT) \
		-e EVETEST_HOME=$(EVETEST_HOME_DIR) \
		-e EVETEST_HOST_UID=$(EVETEST_HOST_UID) \
		-e EVETEST_HOST_GID=$(EVETEST_HOST_GID) \
		$(EVETEST_IMAGE)

# Ensure the evetest image for the current sources exists locally: pull it, or
# build it if it is not published (the tag is a content hash, so an existing
# image is always up to date).
ensure-evetest-image:
	@if ! docker image inspect $(EVETEST_IMAGE) >/dev/null 2>&1; then \
		echo "Docker image $(EVETEST_IMAGE) not found locally, trying to pull..."; \
		if ! docker pull $(EVETEST_IMAGE); then \
			echo "Pull failed, building image locally..."; \
			$(MAKE) build-container; \
		fi; \
	fi

# Same for the SDN image, which the broker needs. Skipped with a remote broker,
# which pulls the image itself (and cannot use one built here).
ensure-sdn-image:
ifndef EVETEST_BROKER_ADDRESS
ifndef EVETEST_SDN_VERSION
	@if ! docker image inspect $(SDN_IMAGE) >/dev/null 2>&1; then \
		echo "Docker image $(SDN_IMAGE) not found locally, trying to pull..."; \
		if ! docker pull $(SDN_IMAGE); then \
			echo "Pull failed, building image locally (requires linuxkit)..."; \
			$(MAKE) build-sdn-container; \
		fi; \
	fi
endif
endif

# Internal target: invoked by proto inside the builder container.
# Run make proto instead.
_run_protoc:
	mkdir -p $(GEN_GO_DIR)
	protoc -I$(PROTO_SRC_DIR) -I$(EVE_API_DIR)/proto \
		--go_out=$(PROTOC_OUT_OPTS):$(GEN_GO_DIR) \
		--go-grpc_out=$(PROTOC_OUT_OPTS):$(GEN_GO_DIR) \
		$(PROTO_SRC_DIR)/*.proto

proto: clone-eve-api clean-proto-go
	docker build $(BUILD_SECRET_OPTS) \
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
		-t $(EVETEST_IMAGE) \
		-f Dockerfile.evetest .

build-test-apps:
	@$(MAKE) -C testapps build

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
#     sudo make libvirt-setup-broker-user EVETEST_BROKER_IMAGE_DIR=/data/evetest
libvirt-setup-broker-user:
	@echo "Setting up eve-broker user and groups..."
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "Error: This target must be run as root."; \
		echo "       Please rerun with: sudo make libvirt-setup-broker-user"; \
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
	@echo "libvirt-setup-broker-user complete. You can now run the container safely as eve-broker."

# Run broker container for the libvirt provider.
libvirt-run-broker-container:
	@echo "Running Evetest Broker version $(EVETEST_VERSION)..."
	# Capture EVETEST_* and DOCKER_* environment variables
	$(eval EV_VARS := $(shell env | grep -E '^(EVETEST|DOCKER)_' | sed 's/^/-e /'))
	$(eval IMAGE_DIR := $(or $(EVETEST_BROKER_IMAGE_DIR),/home/eve-broker/images))
	# Bind-mount the host's actual Docker storage directory into the container at
	# the same path, so the broker's periodic image-cleanup routine (which asks
	# the Docker daemon for its own DockerRootDir rather than assuming a fixed
	# path like /var/lib/docker) can statfs it from inside the container too.
	$(eval DOCKER_ROOT := $(shell docker info -f '{{.DockerRootDir}}'))
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
		echo "         To improve security, run: sudo make libvirt-setup-broker-user"; \
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
		-v $(DOCKER_ROOT):$(DOCKER_ROOT):ro \
		$(EVETEST_ORG)/evetest-broker:$(EVETEST_VERSION)

# Internal target: invoked by Dockerfile.broker inside the builder container.
# Run build-broker-container instead.
_install-broker:
	@echo "Installing evetest Broker version $(EVETEST_VERSION)..."
	cd ./broker && go build -ldflags "-X main.version=$(EVETEST_VERSION)" -o $(GOBIN)/evetest-broker
	@echo "Installed evetest Broker to $(GOBIN)/evetest-broker"

# Assemble the self-contained Proxmox broker installer by embedding the
# hookscript and cloud-init user-data into the installer template. The resulting
# single script is what users download and run on the Proxmox host.
PROXMOX_DEPLOY := deploy/proxmox
PROXMOX_INSTALLER := $(PROXMOX_DEPLOY)/evetest-broker-proxmox-installer.sh
proxmox-broker-installer:
	@awk '\
	  /@@TEMPLATE_NOTE_BEGIN@@/ { skip=1; next } \
	  /@@TEMPLATE_NOTE_END@@/   { skip=0; next } \
	  skip { next } \
	  /^@@HOOKSCRIPT@@$$/     { f="$(PROXMOX_DEPLOY)/evetest-hook.pl";             while ((getline l < f) > 0) print l; close(f); next } \
	  /^@@CLOUDINIT@@$$/      { f="$(PROXMOX_DEPLOY)/broker-cloudinit.yaml";       while ((getline l < f) > 0) print l; close(f); next } \
	  /^@@MIRRORS_SCRIPT@@$$/ { f="$(PROXMOX_DEPLOY)/broker-registry-mirrors.sh";  while ((getline l < f) > 0) print l; close(f); next } \
	  { print }' $(PROXMOX_DEPLOY)/installer.sh.tmpl \
	  | sed 's|@@VERSION@@|$(EVETEST_VERSION)|g' > $(PROXMOX_INSTALLER)
	@chmod +x $(PROXMOX_INSTALLER)
	@echo "Assembled $(PROXMOX_INSTALLER) (broker image tag: $(EVETEST_VERSION))"

install-cli:
	@echo "Installing evetest CLI version $(EVETEST_VERSION)..."
	cd ./cli && go build -ldflags "-X main.version=$(EVETEST_VERSION)" -o $(GOBIN)/evetest
	@echo "Installed evetest CLI to $(GOBIN)/evetest"

# Always go through the root Makefile (a no-op when up to date), so a linuxkit
# left over from an older pin is rebuilt rather than reused.
.PHONY: linuxkit
linuxkit:
	@$(MAKE) -C $(CURDIR)/.. linuxkit

build-sdn-container: linuxkit
	@$(MAKE) -C sdn SDN_VERSION=$(SDN_VERSION) LINUXKIT=$(LINUXKIT) LINUXKIT_SECRET_OPTS="$(LINUXKIT_SECRET_OPTS)" build
