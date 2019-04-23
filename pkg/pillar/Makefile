# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# Goals
# 1. Build go provision binaries for arm64 and amd64
# 2. Build on Linux as well on Mac

ARCH        ?= amd64
#ARCH        ?= arm64


USER        := $(shell id -u -n)
GROUP	    := $(shell id -g -n)
UID         := $(shell id -u)
GID	    := $(shell id -g)
GIT_TAG     := $(shell git tag | tail -1)
BUILD_DATE  := $(shell date -u +"%Y-%m-%d-%H:%M")
GIT_VERSION := $(shell git describe --match v --abbrev=8 --always --dirty)
BRANCH_NAME := $(shell git rev-parse --abbrev-ref HEAD)
VERSION     := $(GIT_TAG)
# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOMODULE=github.com/zededa/eve/pkg/pillar

BUILD_VERSION=$(shell scripts/getversion.sh)

OBJDIR      := $(PWD)/bin/$(ARCH)
BINDIR	    := $(OBJDIR)

DOCKER_ARGS=$${GOARCH:+--build-arg GOARCH=}$(GOARCH)
DOCKER_TAG=zededa/ztools:local$${GOARCH:+-}$(GOARCH)

APPS = zedbox
APPS1 = logmanager ledmanager downloader verifier client zedrouter domainmgr identitymgr zedmanager zedagent hardwaremodel ipcmonitor nim diag baseosmgr wstunnelclient conntrack

SHELL_CMD=bash
define BUILD_CONTAINER
FROM golang:1.9.1-alpine
RUN apk add --no-cache openssh-client git gcc linux-headers libc-dev util-linux libpcap-dev bash vim make
RUN deluser $(USER) ; delgroup $(GROUP) || :
RUN sed -ie /:$(UID):/d /etc/passwd /etc/shadow ; sed -ie /:$(GID):/d /etc/group || :
RUN addgroup -g $(GID) $(GROUP) && adduser -h /home/$(USER) -G $(GROUP) -D -H -u $(UID) $(USER)
ENV HOME /home/$(USER)
endef

SHELL_CMD=bash
define BUILD_CONTAINER
FROM golang:1.9.1-alpine
RUN apk add --no-cache openssh-client git gcc linux-headers libc-dev util-linux libpcap-dev bash vim make
RUN deluser $(USER) ; delgroup $(GROUP) || :
RUN sed -ie /:$(UID):/d /etc/passwd /etc/shadow ; sed -ie /:$(GID):/d /etc/group || :
RUN addgroup -g $(GID) $(GROUP) && adduser -h /home/$(USER) -G $(GROUP) -D -H -u $(UID) $(USER)
ENV HOME /home/$(USER)
endef

.PHONY: all clean vendor

all: obj build

obj:
	@rm -rf $(BINDIR)
	@mkdir -p $(BINDIR)

build:
	@echo Building version $(BUILD_VERSION)
	@mkdir -p var/tmp/zededa
	@for app in $(APPS); do \
		echo $$app; \
		CGO_ENABLED=0 \
		GOOS=linux \
		GOARCH=$(ARCH) $(GOBUILD) \
			-ldflags -X=main.Version=$(BUILD_VERSION) \
			-o $(BINDIR)/$$app github.com/zededa/eve/$$app || exit 1; \
	done
	@for app in $(APPS1); do \
		echo $$app; \
		rm -f $(BINDIR)/$$app; \
		ln -s $(APPS) $(BINDIR)/$$app; \
	done

build-docker:
	docker build $(DOCKER_ARGS) -t $(DOCKER_TAG) .

build-docker-git:
	git archive HEAD | docker build $(DOCKER_ARGS) -t $(DOCKER_TAG) -

export BUILD_CONTAINER
eve-build-$(USER):
	@echo "$$BUILD_CONTAINER" | docker build -t $@ - >/dev/null

shell: eve-build-$(USER)
	@mkdir -p .go/src/$(GOMODULE)
	@docker run -it --rm -u $(USER) -w /home/$(USER) \
	  -v $(CURDIR)/.go:/go -v $(CURDIR):/go/src/$(GOMODULE) -v $${HOME}:/home/$(USER) \
	$< $(SHELL_CMD)

test: SHELL_CMD=go test github.com/zededa/eve/...
test: shell
	@echo Done testing

Gopkg.lock: SHELL_CMD=bash --norc --noprofile -c "go get github.com/golang/dep/cmd/dep ; cd /go/src/$(GOMODULE) ; dep ensure -update $(GODEP_NAME)"
Gopkg.lock: Gopkg.toml shell
	@echo Done updating vendor

vendor: Gopkg.lock
	touch Gopkg.toml

clean:
	@rm -rf bin
