#
# Makefile for zededa-provision
#

# Goals
# 1. Build go provision binaries for arm64 and amd64
# 2. Build on Linux as well on Mac

ARCH        ?= amd64
#ARCH        ?= arm64

GIT_TAG     := $(shell git tag | tail -1)
BUILD_DATE  := $(shell date -u +"%Y-%m-%d-%H:%M")
GIT_VERSION := $(shell git describe --match v --abbrev=8 --always --dirty)
BRANCH_NAME := $(shell git rev-parse --abbrev-ref HEAD)
VERSION     := $(GIT_TAG)
# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build

BUILD_VERSION=$(shell scripts/getversion.sh)

OBJDIR      := $(PWD)/bin/$(ARCH)
BINDIR	    := $(OBJDIR)

APPS = zedbox
APPS1 = logmanager ledmanager downloader verifier client zedrouter domainmgr identitymgr zedmanager zedagent hardwaremodel

SCRIPTS = \
	device-steps.sh \
	find-uplink.sh \
	generate-device.sh \
	generate-onboard.sh \
	generate-self-signed.sh \
	run-ocsp.sh

.PHONY: all clean vendor

all: obj build

obj:
	@rm -rf $(BINDIR)
	@mkdir -p $(BINDIR)

build:
	@echo Building version $(BUILD_VERSION)
	@mkdir -p var/tmp/zededa
	@echo $(BUILD_VERSION) >$(BINDIR)/versioninfo
	@for app in $(APPS); do \
		echo $$app; \
		CGO_ENABLED=0 \
		GOOS=linux \
		GOARCH=$(ARCH) $(GOBUILD) \
			-ldflags -X=main.Version=$(BUILD_VERSION) \
			-o $(BINDIR)/$$app github.com/zededa/go-provision/$$app || exit 1; \
	done
	@for app in $(APPS1); do \
		echo $$app; \
		rm -f $(BINDIR)/$$app; \
		ln -s $(APPS) $(BINDIR)/$$app; \
	done

build-docker:
	docker build -t zededa/ztools:local .

build-docker-git:
	git archive HEAD | docker build -t zededa/ztools:local -

Gopkg.lock: Gopkg.toml
	mkdir -p .go/src/github.com/zededa && ln -s ../../../.. .go/src/github.com/zededa/go-provision || :
	GOPATH=$(CURDIR)/.go go get github.com/golang/dep/cmd/dep
	rm vendor
	mv src/vendor vendor
	(cd .go/src/github.com/zededa/go-provision ; GOPATH=$(CURDIR)/.go dep ensure -update $(GODEP_NAME)) 
	mv vendor src/vendor
	ln -s src/vendor vendor	

vendor: Gopkg.lock
	touch Gopkg.toml

clean:
	@rm -rf bin
