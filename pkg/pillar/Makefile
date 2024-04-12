# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# Goals
# 1. Build go provision binaries for arm64 and amd64
# 2. Build on Linux as well on Mac

HOSTARCH      := $(subst aarch64,arm64,$(subst x86_64,amd64,$(shell uname -m)))
ZARCH         ?= $(HOSTARCH)
DISTDIR       := dist/$(ZARCH)
BUILD_VERSION ?=

DOCKER_ARCH_ARGS:=--platform linux/$(ZARCH)
DOCKER_ARGS:=$(DOCKER_ARCH_ARGS) --build-arg ZARCH=$(ZARCH)
DOCKER_TAG:=lfedge/eve-pillar:local-$(ZARCH)

APPS = zedbox
APPS1 = $(notdir $(wildcard cmd/*))

# find all GOFILES
GOFILES = $(shell find . -path ./vendor -prune -o -name '*go' -print)

.PHONY: all clean build test build-docker build-docker-git shell

all: build

$(DISTDIR):
	mkdir -p $(DISTDIR)

build: $(APPS) $(APPS1)

TAGS=
ifeq ($(RSTATS),y)
	TAGS+=rstats
endif
ifneq ($(HV),)
	TAGS+=$(HV)
endif
ifneq ($(TAGS),)
	TAGS:=-tags "$(TAGS)"
endif

LDFLAGS=-X=main.Version=$(BUILD_VERSION)
ifneq ($(DEV),y)
	LDFLAGS+=-s -w
endif
ifeq ($(RSTATS),y)
	LDFLAGS+=-X=github.com/lf-edge/eve/pkg/pillar/rstats.Endpoint=$(RSTATS_ENDPOINT)
	LDFLAGS+=-X=github.com/lf-edge/eve/pkg/pillar/rstats.Tag=$(RSTATS_TAG)
endif
LDFLAGS:=-ldflags "$(LDFLAGS)"

GCFLAGS=
ifeq ($(DEV),y)
	GCFLAGS:=-gcflags=all="-N -l"
endif

$(APPS): $(DISTDIR)/$(APPS)
$(DISTDIR)/$(APPS): $(DISTDIR)
	@echo "Building $@"
	GO111MODULE=on GOOS=linux GOARCH=$(ZARCH) go build -mod=vendor $(TAGS) $(GCFLAGS) $(LDFLAGS) -o $@ ./$(@F)

$(APPS1): $(DISTDIR)
	@echo $@
	@rm -f $(DISTDIR)/$@
	@ln -s $(APPS) $(DISTDIR)/$@

shell:
	make -C ../.. shell

build-docker:
	docker build $(DOCKER_ARGS) -t $(DOCKER_TAG) .

build-docker-dev:
	docker build $(DOCKER_ARGS) -t $(DOCKER_TAG) . --target build

enter-docker-dev: build-docker-dev
	docker run --platform linux/$(ZARCH) -it --rm --entrypoint /bin/sh $(DOCKER_TAG)

build-docker-git:
	git archive HEAD | docker build $(DOCKER_ARGS) -t $(DOCKER_TAG) -

build-docker-test:
	docker build $(DOCKER_ARGS) --build-arg TEST_TOOLS=y -t $(DOCKER_TAG) . --target build

test: build-docker-test
	rm -f results.json
	rm -f results.xml
	touch results.json
	touch results.xml
	docker run --platform linux/$(ZARCH) -w /pillar \
		--mount type=bind,source=./results.json,target=/pillar/results.json \
		--mount type=bind,source=./results.xml,target=/pillar/results.xml \
		--entrypoint /final/opt/gotestsum $(DOCKER_TAG) \
		--jsonfile /pillar/results.json \
		--junitfile /pillar/results.xml \
		--raw-command -- go test -tags kubevirt -coverprofile=coverage.txt -covermode=atomic -race -json \
		./...
	docker run --platform linux/$(ZARCH) -w /pillar \
		--entrypoint /bin/sh $(DOCKER_TAG) \
		/pillar/build-scripts/fuzz_test.sh

test-profiling-create: build-docker-test
	docker run --memory=800m --platform linux/$(ZARCH) -w /pillar \
                --mount type=bind,source=./,target=/pillar/ \
                --entrypoint /bin/sh $(DOCKER_TAG) \
                /pillar/build-scripts/memprof_test.sh

test-profiling: test-profiling-create
	for i in *.profile; \
                do go tool pprof -output "$${i}.png" -png "$${i}" ;\
        done

clean:
	@rm -rf $(DISTDIR)

fmt:
	@gofmt -w -s $(GOFILES)

fmt-check:
	@gofmt -l $(GOFILES)

fmt-check-details:
	@gofmt -d $(GOFILES)

vet:
	go vet $(TAGS) ./...
