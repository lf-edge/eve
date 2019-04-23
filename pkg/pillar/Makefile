# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# Goals
# 1. Build go provision binaries for arm64 and amd64
# 2. Build on Linux as well on Mac

ARCH         ?= amd64
#ARCH        ?= arm64


USER         = $(shell id -u -n)
GROUP	     = $(shell id -g -n)
UID          = $(shell id -u)
GID	     = $(shell id -g)
BUILD_VERSION=$(shell scripts/getversion.sh)

# Go parameters and builder
GOVER ?= 1.9.1
GOMODULE=github.com/zededa/eve/pkg/pillar
DOCKER_GO = mkdir -p .go/src/$(GOMODULE) ;\
    docker run -it --rm -u $(USER) -w /go/src/$(GOMODULE) \
    -v $(CURDIR)/.go:/go -v $(CURDIR):/go/src/$(GOMODULE) -v $(DISTDIR):/go/bin -v $${HOME}:/home/$(USER) \
    -e GOOS=linux -e GOARCH=$(ARCH) -e CGO_ENABLED=1 -e BUILD=local $(GOBUILDER)

# by default, build in docker container, unless override with BUILD=local
GOBUILD=$(DOCKER_GO) go install
ifeq ($(BUILD),local)
GOBUILD=GOOS=linux GOARCH=$(ARCH) CGO_ENABLED=0 go build -o $(DISTDIR)/$@
endif

OBJDIR      := $(PWD)/dist/$(ARCH)
DISTDIR	    := $(OBJDIR)

DOCKER_ARGS=$${GOARCH:+--build-arg GOARCH=}$(GOARCH)
DOCKER_TAG=zededa/ztools:local$${GOARCH:+-}$(GOARCH)
GOBUILDER ?= eve-build-$(USER)


APPS = zedbox
APPS1 = logmanager ledmanager downloader verifier client zedrouter domainmgr identitymgr zedmanager zedagent hardwaremodel ipcmonitor nim diag baseosmgr wstunnelclient conntrack

SHELL_CMD=bash

.PHONY: all clean vendor $(GOBUILDER) builder-image build build-docker

all: obj build

obj:
	@rm -rf $(DISTDIR)
	@mkdir -p $(DISTDIR)

$(DISTDIR): 
	mkdir -p $(DISTDIR)

build: $(APPS) $(APPS1)

$(APPS): $(DISTDIR) builder-image
	@echo "Building $@"
	@$(GOBUILD) -ldflags -X=main.Version=$(BUILD_VERSION) $(GOMODULE)/$@

$(APPS1): $(DISTDIR)
	@echo $@
	@rm -f $(DISTDIR)/$@
	@ln -s $(APPS) $(DISTDIR)/$@

shell: builder-image
	@$(DOCKER_GO) $(SHELL_CMD) 

build-docker:
	docker build $(DOCKER_ARGS) -t $(DOCKER_TAG) .

build-docker-git:
	git archive HEAD | docker build $(DOCKER_ARGS) -t $(DOCKER_TAG) -

builder-image: $(GOBUILDER)
$(GOBUILDER):
ifneq ($(BUILD),local)
	@echo "Creating go builder image for user $(USER)"
	@docker build --build-arg GOVER=$(GOVER) --build-arg USER=$(USER) --build-arg GROUP=$(GROUP) --build-arg UID=$(UID) --build-arg GID=$(GID) -t $@ dev-support >/dev/null
endif

test: SHELL_CMD=go test github.com/zededa/go-provision/...
test: shell
	@echo Done testing

Gopkg.lock: SHELL_CMD=bash --norc --noprofile -c "go get github.com/golang/dep/cmd/dep ; cd /go/src/$(GOMODULE) ; dep ensure -update $(GODEP_NAME)"
Gopkg.lock: Gopkg.toml shell
	@echo Done updating vendor

vendor: Gopkg.lock
	touch Gopkg.toml

clean:
	@rm -rf dist
