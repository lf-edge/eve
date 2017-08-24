#
# Makefile for go-provision
#

PKGNAME   := zededa-provision
MAJOR_VER := 1
MINOR_VER := 0
ARCH        ?= amd64

BUILD_DATE  := $(shell date +"%Y-%m-%d %H:%M %Z")
GIT_VERSION := $(shell git describe --match v --abbrev=8 --always --dirty)
BRANCH_NAME := $(shell git rev-parse --abbrev-ref HEAD)
VERSION     := $(MAJOR_VER).$(MINOR_VER)-$(GIT_VERSION)
LISPURL     := "https://www.dropbox.com/s/j5jnr3r7ba6x6wb/lispers.net-x86-release-0.394.tgz"

# For future use
#LDFLAGS     := -ldflags "-X=main.Version=$(VERSION) -X=main.Build=$(BUILD_DATE)"

ifeq ($(BRANCH_NAME), master)
PKG         := $(PKGNAME)_$(VERSION)_$(ARCH)
else
PKG         := $(PKGNAME)_$(VERSION)-$(BRANCH_NAME)_$(ARCH)
endif

OBJDIR      := $(PWD)/obj/$(ARCH)
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
	eidregister

SCRIPTS = \
	device-steps.sh \
	find-uplink.sh \
	generate-device.sh \
	generate-onboard.sh \
	generate-self-signed.sh \
	run-ocsp.sh \
	zupgrade.sh

INSTALL_DEVICE_FILE = install-device-list.mk
INSTALL_DEVICE_LIST := $(shell cat $(INSTALL_DEVICE_FILE))
INSTALL_DEVICE_SCRIPT = install-zeddevice.sh

.PHONY: all clean pkg obj install

all: pkg

install: pkg
	@for deviceIP in $(INSTALL_DEVICE_LIST); do \
		scp $(OBJDIR)/$(PKG).deb $$deviceIP:~/.; \
		scp scripts/$(INSTALL_DEVICE_SCRIPT) $$deviceIP:~/.; \
		ssh -t $$deviceIP 'sudo chmod +x ~/$(INSTALL_DEVICE_SCRIPT); sudo ~/$(INSTALL_DEVICE_SCRIPT) $(PKG).deb; rm $(PKG).deb; rm $(INSTALL_DEVICE_SCRIPT)'; \
	done
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
	@mkdir -p $(BINDIR) $(ETCDIR) $(LISPDIR)

build:
	@for app in $(APPS); do \
		echo $$app; \
		CGO_ENABLED=0 \
		GOOS=linux \
		GOARCH=$(ARCH) go build \
			-o $(BINDIR)/$$app github.com/zededa/go-provision/$$app; \
	done

clean:
	@rm -rf obj
