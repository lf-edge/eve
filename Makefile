#
# Makefile for zededa-provision
#

# Goals
# 1. Build go provision binaries for arm64 and amd64
# 2. Build on Linux as well on Mac
# 3. If build host is Linux, build a Debian package ...
# 4. .. else build a tarball(?)
# 5. Option to build and install on a given device(s).
#    If this is done well, then we can forget about 3 and 4.

PKGNAME   := zededa-provision
ARCH        ?= amd64
#ARCH        ?= arm64

GIT_TAG     := $(shell git tag)
BUILD_DATE  := $(shell date -u +"%Y-%m-%d-%H:%M")
GIT_VERSION := $(shell git describe --match v --abbrev=8 --always --dirty)
BRANCH_NAME := $(shell git rev-parse --abbrev-ref HEAD)
VERSION     := $(GIT_TAG)
LISPURL     := https://www.dropbox.com/s/8wwdihdxm6pomqu/lispers.net-x86-release-0.434.tgz

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOINSTALL=$(GOCMD) install
GOGENERATE=$(GOCMD) generate
GOGET=$(GOCMD) get
GOFMT=gofmt -w

ifeq ($(PROD), 1)
EXTRA_VERSION :=
else
EXTRA_VERSION := -$(GIT_VERSION)-$(BUILD_DATE)
endif

ifeq ($(BRANCH_NAME), master)
PKG         := $(PKGNAME)_$(VERSION)_$(ARCH)
BUILD_VERSION := $(VERSION)$(EXTRA_VERSION)
else
PKG         := $(PKGNAME)_$(VERSION)-$(BRANCH_NAME)_$(ARCH)
BUILD_VERSION := $(VERSION)-$(GIT_BRANCH)$(EXTRA_VERSION)
endif

OBJDIR      := $(PWD)/bin/$(ARCH)
PKGDIR      := $(OBJDIR)/$(PKG)/opt/zededa
BINDIR      := $(PKGDIR)/bin
ETCDIR      := $(PKGDIR)/etc
LISPDIR     := $(PKGDIR)/lisp

APPS = \
	downloader 	\
	verifier 	\
	client 		\
	server 		\
	register 	\
	zedrouter 	\
	domainmgr 	\
	identitymgr	\
	zedmanager 	\
	eidregister	\
	zedagent	\
	ledmanager	\
	hardwaremodel

SCRIPTS = \
	device-steps.sh \
	find-uplink.sh \
	generate-device.sh \
	generate-onboard.sh \
	generate-self-signed.sh \
	run-ocsp.sh \
	zupgrade.sh

include install-device-list.mk
INSTALL_DEVICE_SCRIPT = install-zeddevice.sh
INSTALL_SERVER := $(shell pgrep -f SimpleHTTPServer)

ifndef INSTALL_SERVER
	SERVER_CMD := @cd /opt/zededa/debian && python -m SimpleHTTPServer &
else
	SERVER_CMD := @echo "HTTP server already running"
endif
.PHONY: all clean pkg obj install

all: pkg

init:
	$(GOGET) ./...

install: pkg
	@echo "***"
	@echo "*** Pushing zededa-provision debian package to device list"
	@for deviceIP in $(INSTALL_DEVICE_LIST); do \
		echo $$deviceIP; \
		scp $(OBJDIR)/$(PKG).deb $$deviceIP:/tmp/.; \
		scp scripts/$(INSTALL_DEVICE_SCRIPT) $$deviceIP:/tmp/.; \
		ssh -t $$deviceIP 'sudo /tmp/$(INSTALL_DEVICE_SCRIPT) /tmp/$(PKG).deb; rm /tmp/$(PKG).deb; rm /tmp/$(INSTALL_DEVICE_SCRIPT)'; \
	done
	@echo "***"
	@echo "*** Making zededa-provision debian package available for wget"
	@sudo mkdir -p /opt/zededa/debian && sudo cp -p $(OBJDIR)/$(PKG).deb /opt/zededa/debian/.
	$(SERVER_CMD)
	@echo "***"
	@echo "*** Run wget http://<ip>:8000/$(PKG).deb && sudo gdebi -n $(PKG).deb"
	@echo "*** OR run zupgrade http://<ip>:8000/$(PKG).deb"
	@echo "***"

pkg: obj build
	@cp -p README $(ETCDIR)
	@cp -p etc/* $(ETCDIR)
	@for script in $(SCRIPTS); do \
		cp -p scripts/$$script $(BINDIR); done
	@echo "lisp"
	@cd $(LISPDIR) && wget -q -O - $(LISPURL) | tar -zxf -
	@mkdir -p $(OBJDIR)/$(PKG)/DEBIAN
	@sed "s/__VERSION__/$(VERSION)/;s/__ARCH__/$(ARCH)/" package/control > $(OBJDIR)/$(PKG)/DEBIAN/control
	@cp -p package/postinst package/prerm $(OBJDIR)/$(PKG)/DEBIAN/
	@cd $(OBJDIR) && dpkg-deb --build $(PKG)

obj:
	@rm -rf $(BINDIR) $(ETCDIR) $(LISPDIR)
	@mkdir -p $(BINDIR) $(ETCDIR) $(LISPDIR)

build:
	@echo Building version $(BUILD_VERSION)
	@mkdir -p var/tmp/zededa
	@echo "all: $(BUILD_VERSION)" >var/tmp/zededa/version_tag
	@for app in $(APPS); do \
		echo $$app; \
		CGO_ENABLED=0 \
		GOOS=linux \
		GOARCH=$(ARCH) go build \
			-ldflags -X=main.Version=$(BUILD_VERSION) \
			-o $(BINDIR)/$$app github.com/zededa/go-provision/$$app || exit 1; \
	done

clean:
	@rm -rf obj
