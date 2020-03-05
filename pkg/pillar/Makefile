# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# Goals
# 1. Build go provision binaries for arm64 and amd64
# 2. Build on Linux as well on Mac

ARCH         ?= amd64
#ARCH        ?= arm64
DISTDIR      := dist/$(ARCH)
BUILD_VERSION=$(shell scripts/getversion.sh 2>/dev/null)

DOCKER_ARGS=
DOCKER_TAG=lfedge/eve-pillar:local
ifneq ($(GOARCH),)
DOCKER_ARGS:=--build-arg GOARCH=$(GOARCH)
DOCKER_TAG:=$(DOCKER_TAG)-$(GOARCH)
endif

APPS = zedbox
APPS1 = logmanager ledmanager downloader verifier client zedrouter domainmgr \
        identitymgr zedmanager zedagent hardwaremodel ipcmonitor nim diag    \
        baseosmgr wstunnelclient conntrack waitforaddr tpmmgr vaultmgr nodeagent \
        eveadm

.PHONY: all clean build test build-docker build-docker-git shell

all: build

$(DISTDIR): 
	mkdir -p $(DISTDIR)

build: $(APPS) $(APPS1)

$(APPS): $(DISTDIR)/$(APPS)
$(DISTDIR)/$(APPS): $(DISTDIR)
	@echo "Building $@"
	GO111MODULE=on GOOS=linux CGO_ENABLED=1 go build -mod=vendor -ldflags -X=main.Version=$(BUILD_VERSION) -o $@ ./$(@F)

$(APPS1): $(DISTDIR)
	@echo $@
	@rm -f $(DISTDIR)/$@
	@ln -s $(APPS) $(DISTDIR)/$@

shell:
	make -C ../.. shell

build-docker-$(APPS): $(DISTDIR)
	docker build -f Dockerfile.in --target=build -t $(APPS)-builder .
	# all of this goes away when we switch to full buildkit-based docker builds
	docker container create --name $(APPS)-extract $(APPS)-builder
	docker container cp $(APPS)-extract:/dist/$(APPS) $(DISTDIR)/$(APPS)
	docker container rm -f $(APPS)-extract


build-docker:
	docker build $(DOCKER_ARGS) -t $(DOCKER_TAG) .

build-docker-git:
	git archive HEAD | docker build $(DOCKER_ARGS) -t $(DOCKER_TAG) -

test:
	go test -mod=vendor ./...

clean:
	@rm -rf $(DISTDIR)
