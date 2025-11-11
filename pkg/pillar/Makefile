# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# Goals
# 1. Build go provision binaries for arm64 and amd64
# 2. Build on Linux as well on Mac

HOSTARCH      := $(subst aarch64,arm64,$(subst x86_64,amd64,$(shell uname -m)))
ZARCH         ?= $(HOSTARCH)
DISTDIR       := dist/$(ZARCH)
BUILD_VERSION ?=

DOCKER_LIKE_LKT:= ../../build-tools/bin/linuxkit pkg build --network --platforms linux/$(ZARCH) --dry-run --force ./ | tail -n1 | perl -pe 's/ buildx / /g'
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
ifeq ($(IMM_PROFILING),y)
	TAGS+=immprofiling
endif
ifeq ($(ARTIFICIAL_LEAK),y)
	TAGS+=artificialleak
endif
ifneq ($(HV),)
	TAGS+=$(HV)
endif
ifneq ($(TAGS),)
	TAGS:=-tags "$(TAGS)"
endif

ifneq ($(HV),)
       LDFLAGS=-extldflags '-fuse-ld=bfd -no-pie'
else
       LDFLAGS=-extldflags=-fuse-ld=bfd
endif

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
	$(shell $(DOCKER_LIKE_LKT)) -t $(DOCKER_TAG)

enter-docker-dev: build-docker-test
	docker run --platform linux/$(ZARCH) -it --rm --entrypoint /bin/sh $(DOCKER_TAG)

build-docker-test-dependencies:
	make -C ../../ pillar-cache-export-docker-load
build-docker-test-build: build-docker-test-dependencies
	$(shell $(DOCKER_LIKE_LKT)) --build-arg TEST_TOOLS=y --load --target build
build-docker-test: build-docker-test-build
	docker image tag $(shell $(shell $(DOCKER_LIKE_LKT)) --build-arg TEST_TOOLS=y --load -q --target build) $(DOCKER_TAG)

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
	docker run --platform linux/$(ZARCH) -w /pillar \
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
