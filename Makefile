# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Run make (with no arguments) to see help on what targets are available

GOVER ?= 1.12.4
PKGBASE=github.com/lf-edge/eve
GOMODULE=$(PKGBASE)/pkg/pillar
GOTREE=$(CURDIR)/pkg/pillar
PATH:=$(CURDIR)/build-tools/bin:$(PATH)

export CGO_ENABLED GOOS GOARCH PATH

# A set of tweakable knobs for our build needs (tweak at your risk!)
# which language bindings to generate for EVE API
PROTO_LANGS=go python
# The default hypervisor is Xen. Use 'make HV=acrn' to build ACRN images (AMD64 only) or 'make HV=kvm'
HV=xen
# How large to we want the disk to be in Mb
MEDIA_SIZE=8192
# Image type for final disk images
IMG_FORMAT=qcow2
# Filesystem type for rootfs image
ROOTFS_FORMAT=squash
# SSH port to use for running images live
SSH_PORT=2222
# Use QEMU H/W accelearation (any non-empty value will trigger using it)
ACCEL=
# Location of the EVE configuration folder to be used in builds
CONF_DIR=conf

UNAME_S := $(shell uname -s)

USER         = $(shell id -u -n)
GROUP        = $(shell id -g -n)
UID          = $(shell id -u)
GID          = $(shell id -g)

#for MacOS - use predefined user and group IDs
ifeq ($(UNAME_S),Darwin)
	USER         = eve
	GROUP        = eve
	UID          = 1001
	GID          = 1001
endif

EVE_TREE_TAG = $(shell git describe --abbrev=8 --always --dirty)
APIDIRS = $(shell find ./api/* -maxdepth 1 -type d -exec basename {} \;)

HOSTARCH:=$(subst aarch64,arm64,$(subst x86_64,amd64,$(shell uname -m)))
# by default, take the host architecture as the target architecture, but can override with `make ZARCH=foo`
#    assuming that the toolchain supports it, of course...
ZARCH ?= $(HOSTARCH)
export ZARCH
# warn if we are cross-compiling and track it
CROSS ?=
ifneq ($(HOSTARCH),$(ZARCH))
CROSS = 1
$(warning "WARNING: We are assembling an $(ZARCH) image on $(HOSTARCH). Things may break.")
endif

DOCKER_ARCH_TAG=$(ZARCH)

# EVE rootfs image manifest
ROOTFS_YML=images/rootfs-$(HV).yml

# where we store outputs
DIST=$(CURDIR)/dist/$(ZARCH)
DOCKER_DIST=/eve/dist/$(ZARCH)

BIOS_IMG=$(DIST)/OVMF.fd
LIVE_IMG=$(DIST)/live
TARGET_IMG=$(DIST)/target.img
INSTALLER=$(DIST)/installer

ROOTFS_IMG=$(INSTALLER)/rootfs-$(HV).img
CONFIG_IMG=$(INSTALLER)/config.img
INITRD_IMG=$(INSTALLER)/initrd.img
EFI_PART=$(INSTALLER)/EFI

DEVICETREE_DTB_amd64=
DEVICETREE_DTB_arm64=$(DIST)/dtb/eve.dtb
DEVICETREE_DTB=$(DEVICETREE_DTB_$(ZARCH))

CONF_PART=$(CURDIR)/../adam/run/config

# qemu settings
QEMU_SYSTEM_arm64=qemu-system-aarch64
QEMU_SYSTEM_amd64=qemu-system-x86_64
QEMU_SYSTEM=$(QEMU_SYSTEM_$(ZARCH))

QEMU_ACCEL_Y_Darwin=-M accel=hvf --cpu host
QEMU_ACCEL_Y_Linux=-enable-kvm
QEMU_ACCEL:=$(QEMU_ACCEL_$(ACCEL:%=Y)_$(shell uname -s))

QEMU_OPTS_arm64= -machine virt,gic_version=3 -machine virtualization=true -cpu cortex-a57 -machine type=virt -drive file=fat:rw:$(dir $(DEVICETREE_DTB)),label=QEMU_DTB,format=vvfat
# -drive file=./bios/flash0.img,format=raw,if=pflash -drive file=./bios/flash1.img,format=raw,if=pflash
# [ -f bios/flash1.img ] || dd if=/dev/zero of=bios/flash1.img bs=1048576 count=64
QEMU_OPTS_amd64= -cpu SandyBridge $(QEMU_ACCEL)
QEMU_OPTS_COMMON= -smbios type=1,serial=31415926 -m 4096 -smp 4 -display none -serial mon:stdio -bios $(BIOS_IMG) \
        -rtc base=utc,clock=rt \
        -netdev user,id=eth0,net=192.168.1.0/24,dhcpstart=192.168.1.10,hostfwd=tcp::$(SSH_PORT)-:22 -device virtio-net-pci,netdev=eth0 \
        -netdev user,id=eth1,net=192.168.2.0/24,dhcpstart=192.168.2.10 -device virtio-net-pci,netdev=eth1
QEMU_OPTS_CONF_PART=$(shell [ -d $(CONF_PART) ] && echo '-drive file=fat:rw:$(CONF_PART),format=raw')
QEMU_OPTS=$(QEMU_OPTS_COMMON) $(QEMU_OPTS_$(ZARCH)) $(QEMU_OPTS_CONF_PART)

GOOS=linux
CGO_ENABLED=1
GOBUILDER=eve-build-$(shell echo $(USER) | tr A-Z a-z)

# if proxy is set, use it when building docker builder
ifneq ($(HTTP_PROXY),)
DOCKER_HTTP_PROXY:=--build-arg http_proxy=$(HTTP_PROXY)
endif
ifneq ($(HTTPS_PROXY),)
DOCKER_HTTPS_PROXY:=--build-arg https_proxy=$(HTTPS_PROXY)
endif
ifneq ($(NO_PROXY),)
DOCKER_NO_PROXY:=--build-arg no_proxy=$(NO_PROXY)
endif
ifneq ($(ALL_PROXY),)
DOCKER_ALL_PROXY:=--build-arg all_proxy=$(ALL_PROXY)
endif

DOCKER_UNPACK= _() { C=`docker create $$1 fake` ; shift ; docker export $$C | tar -xf - "$$@" ; docker rm $$C ; } ; _
DOCKER_GO = _() { mkdir -p $(CURDIR)/.go/src/$${3:-dummy} ; mkdir -p $(CURDIR)/.go/bin ; \
    docker run $$DOCKER_GO_ARGS -i --rm -u $(USER) -w /go/src/$${3:-dummy} \
    -v $(CURDIR)/.go:/go -v $$2:/go/src/$${3:-dummy} -v $${4:-$(CURDIR)/.go/bin}:/go/bin -v $(CURDIR)/:/eve -v $${HOME}:/home/$(USER) \
    -e GOOS -e GOARCH -e CGO_ENABLED -e BUILD=local $(GOBUILDER) bash --noprofile --norc -c "$$1" ; } ; _

PARSE_PKGS=$(if $(strip $(EVE_HASH)),EVE_HASH=)$(EVE_HASH) DOCKER_ARCH_TAG=$(DOCKER_ARCH_TAG) ./tools/parse-pkgs.sh
LINUXKIT=$(CURDIR)/build-tools/bin/linuxkit
LINUXKIT_OPTS=--disable-content-trust $(if $(strip $(EVE_HASH)),--hash) $(EVE_HASH) $(if $(strip $(EVE_REL)),--release) $(EVE_REL) $(FORCE_BUILD)
LINUXKIT_PKG_TARGET=build
RESCAN_DEPS=FORCE
FORCE_BUILD=--force

ifeq ($(LINUXKIT_PKG_TARGET),push)
  EVE_REL:=$(shell git describe --always | grep -E '[0-9]*\.[0-9]*\.[0-9]*' || echo snapshot)
  ifneq ($(EVE_REL),snapshot)
    EVE_HASH:=$(EVE_REL)
    EVE_REL:=$(shell [ "`git tag | grep -E '[0-9]*\.[0-9]*\.[0-9]*' | sort -t. -n -k1,1 -k2,2 -k3,3 | tail -1`" = $(EVE_HASH) ] && echo latest)
  endif
endif

# We are currently filtering out a few packages from bulk builds
# since they are not getting published in Docker HUB
PKGS=$(shell ls -d pkg/* | grep -Ev "eve|test-microsvcs")

# Top-level targets

all: help

test: $(GOBUILDER) | $(DIST)
	@echo Running tests on $(GOMODULE)
	@$(DOCKER_GO) "gotestsum --junitfile $(DOCKER_DIST)/results.xml" $(GOTREE) $(GOMODULE)

clean:
	rm -rf $(DIST) $(ROOTFS_YML_xen_$(ZARCH)) $(ROOTFS_YML_acrn_$(ZARCH)) \
               pkg/pillar/Dockerfile pkg/qrexec-lib/Dockerfile pkg/qrexec-dom0/Dockerfile

yetus:
	@echo Running yetus
	build-tools/src/yetus/test-patch.sh

build-tools: $(LINUXKIT)
	@echo Done building $<

$(BIOS_IMG): $(LINUXKIT) | $(DIST)
	cd $| ; $(DOCKER_UNPACK) $(shell $(LINUXKIT) pkg show-tag pkg/uefi)-$(DOCKER_ARCH_TAG) $(notdir $@)

$(DEVICETREE_DTB): $(BIOS_IMG) | $(DIST)
	mkdir $(dir $@) 2>/dev/null || :
	$(QEMU_SYSTEM) $(QEMU_OPTS) -machine dumpdtb=$@

$(EFI_PART): $(LINUXKIT) | $(INSTALLER)
	cd $| ; $(DOCKER_UNPACK) $(shell $(LINUXKIT) pkg show-tag pkg/grub)-$(DOCKER_ARCH_TAG) $(notdir $@)

$(INITRD_IMG): $(LINUXKIT) | $(INSTALLER)
	cd $| ; $(DOCKER_UNPACK) $(shell $(LINUXKIT) pkg show-tag pkg/mkimage-raw-efi)-$(DOCKER_ARCH_TAG) $(notdir $@ $(EFI_PART))

# run-installer
#
# This creates an image equivalent to live.img (called target.img)
# through the installer. It's the long road to live.img. Good for
# testing.
#
run-installer-iso: $(BIOS_IMG) $(DEVICETREE_DTB)
	qemu-img create -f ${IMG_FORMAT} $(TARGET_IMG) ${MEDIA_SIZE}M
	$(QEMU_SYSTEM) -drive file=$(TARGET_IMG),format=$(IMG_FORMAT) -cdrom $(INSTALLER).iso -boot d $(QEMU_OPTS)

run-installer-raw: $(BIOS_IMG) $(DEVICETREE_DTB)
	qemu-img create -f ${IMG_FORMAT} $(TARGET_IMG) ${MEDIA_SIZE}M
	$(QEMU_SYSTEM) -drive file=$(TARGET_IMG),format=$(IMG_FORMAT) -drive file=$(INSTALLER).raw,format=raw $(QEMU_OPTS)

run-live run: $(BIOS_IMG) $(DEVICETREE_DTB)
	$(QEMU_SYSTEM) $(QEMU_OPTS) -drive file=$(LIVE_IMG).img,format=$(IMG_FORMAT)

run-target: $(BIOS_IMG) $(DEVICETREE_DTB)
	$(QEMU_SYSTEM) $(QEMU_OPTS) -drive file=$(TARGET_IMG),format=$(IMG_FORMAT)

run-rootfs: $(BIOS_IMG) $(EFI_PART) $(DEVICETREE_DTB)
	(echo 'set devicetree="(hd0,msdos1)/eve.dtb"' ; echo 'set rootfs_root=/dev/vdb' ; echo 'set root=hd1' ; echo 'export rootfs_root' ; echo 'export devicetree' ; echo 'configfile /EFI/BOOT/grub.cfg' ) > $(EFI_PART)/BOOT/grub.cfg
	$(QEMU_SYSTEM) $(QEMU_OPTS) -drive file=$(ROOTFS_IMG),format=raw -drive file=fat:rw:$(EFI_PART)/..,label=CONFIG,format=vvfat

run-grub: $(BIOS_IMG) $(EFI_PART) $(DEVICETREE_DTB)
	[ -f $(EFI_PART)/BOOT/grub.cfg ] && mv $(EFI_PART)/BOOT/grub.cfg $(EFI_PART)/BOOT/grub.cfg.$(notdir $(shell mktemp))
	$(QEMU_SYSTEM) $(QEMU_OPTS) -drive format=vvfat,label=EVE,file=fat:rw:$(EFI_PART)/..

run-compose: images/docker-compose.yml images/version.yml
	docker-compose -f $< run storage-init sh -c 'rm -rf /run/* /config/* ; cp -Lr /conf/* /config/ ; echo IMGA > /run/eve.id'
	docker-compose -f $< up

# ensure the dist directory exists
$(DIST) $(INSTALLER):
	mkdir -p $@

# convenience targets - so you can do `make config` instead of `make dist/config.img`, and `make installer` instead of `make dist/amd64/installer.img
initrd: $(INITRD_IMG)
config: $(CONFIG_IMG)
rootfs: $(ROOTFS_IMG)
live: $(LIVE_IMG).img
installer: $(INSTALLER).raw
installer-iso: $(INSTALLER).iso

$(CONFIG_IMG): $(CONF_DIR) $(shell ls -d $(CONF_DIR)/*) | $(INSTALLER)
	./tools/makeconfig.sh $< $@

$(ROOTFS_IMG): $(ROOTFS_YML) | $(INSTALLER)
	./tools/makerootfs.sh $< $@ $(ROOTFS_FORMAT)
	@[ $$(wc -c < "$@") -gt $$(( 250 * 1024 * 1024 )) ] && \
          echo "ERROR: size of $@ is greater than 250MB (bigger than allocated partition)" && exit 1 || :
	@rm -f $(dir $@)/rootfs.img ; ln -s $(notdir $@) $(dir $@)/rootfs.img

$(LIVE_IMG).img: $(LIVE_IMG).$(IMG_FORMAT) | $(DIST)
	@rm -f $@ >/dev/null 2>&1 || :
	ln -s $(notdir $<) $@

$(LIVE_IMG).qcow2: $(LIVE_IMG).raw | $(DIST)
	qemu-img convert -c -f raw -O qcow2 $< $@
	rm $<

$(LIVE_IMG).raw: $(EFI_PART) $(ROOTFS_IMG) $(INITRD_IMG) $(CONFIG_IMG) | $(INSTALLER)
	./tools/makeflash.sh -C ${MEDIA_SIZE} $| $@

$(INSTALLER).raw: $(EFI_PART) $(ROOTFS_IMG) $(INITRD_IMG) $(CONFIG_IMG) | $(INSTALLER)
	./tools/makeflash.sh -C 350 $| $@ "conf_win installer inventory_win"

$(INSTALLER).iso: $(EFI_PART) $(ROOTFS_IMG) $(INITRD_IMG) $(CONFIG_IMG) | $(INSTALLER)
	./tools/makeiso.sh $| $@

# top-level linuxkit packages targets, note the one enforcing ordering between packages
pkgs: RESCAN_DEPS=
pkgs: FORCE_BUILD=
pkgs: build-tools $(PKGS)
	@echo Done building packages

pkg/pillar: pkg/dnsmasq pkg/strongswan pkg/gpt-tools pkg/fscrypt eve-pillar
	@true
pkg/xen-tools: pkg/uefi eve-xen-tools
	@true
pkg/qrexec-dom0: pkg/qrexec-lib pkg/xen-tools eve-qrexec-dom0
	@true
pkg/qrexec-lib: pkg/xen-tools eve-qrexec-lib
	@true
pkg/kernel: pkg/kernel/Dockerfile build-tools $(RESCAN_DEPS)
	@D=`date '+%s'` ; $(LINUXKIT) pkg $(LINUXKIT_PKG_TARGET) $(LINUXKIT_OPTS) $@               &&\
	if [ $$(( `date '+%s'` - $$D )) -lt 60 ]; then exit 0; fi                                  &&\
	TAG=`echo NEW_KERNEL_TAG | $(PARSE_PKGS)` && V=$${TAG%-*} && V=$${V##*-}                   &&\
	if echo $$TAG | grep -q -v -- -dirty && ! docker pull $$TAG ; then                           \
		docker build --build-arg KERNEL_VERSION_`uname -m`=$$V -t $$TAG $@                 &&\
		if [ "$(LINUXKIT_PKG_TARGET)" = push ]; then docker push $$TAG ;fi                  ;\
	fi
pkg/%: eve-% FORCE
	@true

eve: Makefile $(BIOS_IMG) $(CONFIG_IMG) $(INSTALLER).iso $(INSTALLER).raw $(ROOTFS_IMG) $(LIVE_IMG).img $(ROOTFS_YML)
	make HV=kvm rootfs
	cp pkg/eve/* Makefile $(ROOTFS_YML) $(DIST)
	$(LINUXKIT) pkg $(LINUXKIT_PKG_TARGET) --hash-path $(CURDIR) $(LINUXKIT_OPTS) $(DIST)

proto-vendor:
	@$(DOCKER_GO) "cd pkg/pillar ; go mod vendor" $(CURDIR) proto

proto: $(addprefix api/go/,$(shell ls api/proto)) $(addprefix api/python/,$(shell ls api/proto))
	@echo Done building protobuf, you may want to vendor it into pillar by running proto-vendor

api/%: $(GOBUILDER)
	rm -rf api/$* ; mkdir api/$* # building $*
	@$(DOCKER_GO) "protoc -I./proto/$(@F) --$(notdir $(@D))_out=paths=source_relative:./$* proto/$(@F)/*.proto" $(CURDIR)/api api

release:
	@bail() { echo "ERROR: $$@" ; exit 1 ; } ;\
	 X=`echo $(VERSION) | cut -s -d. -f1` ; Y=`echo $(VERSION) | cut -s -d. -f2` ; Z=`echo $(VERSION) | cut -s -d. -f3` ;\
	 [ -z "$$X" -o -z "$$Y" -o -z "$$Z" ] && bail "VERSION missing (or incorrect). Re-run as: make VERSION=x.y.z $@" ;\
	 (git fetch && [ `git diff origin/master..master | wc -l` -eq 0 ]) || bail "origin/master is different from master" ;\
	 if git checkout $$X.$$Y 2>/dev/null ; then \
	    git merge origin/master ;\
	 else \
	    git checkout master -b $$X.$$Y && echo zedcloud.zededa.net > conf/server &&\
	    git commit -m"Setting default server to prod" conf/server ;\
	 fi || bail "Can't create $$X.$$Y branch" ;\
	 git tag -a -m"Release $$X.$$Y.$$Z" $$X.$$Y.$$Z &&\
	 echo "Done tagging $$X.$$Y.$$Z release. Check the branch with git log and then run" &&\
	 echo "  git push origin $$X.$$Y $$X.$$Y.$$Z"

shell: $(GOBUILDER)
	@DOCKER_GO_ARGS=-t ; $(DOCKER_GO) bash $(GOTREE) $(GOMODULE)

#
# Utility targets in support of our Dockerized build infrastrucutre
#
$(LINUXKIT): CGO_ENABLED=0
$(LINUXKIT): GOOS=$(shell uname -s | tr '[A-Z]' '[a-z]')
$(LINUXKIT): $(CURDIR)/build-tools/src/linuxkit/Gopkg.lock $(CURDIR)/build-tools/bin/manifest-tool | $(GOBUILDER)
	@$(DOCKER_GO) "unset GOFLAGS ; unset GO111MODULE ; go build -ldflags '-X version.GitCommit=$(EVE_TREE_TAG)' -o /go/bin/linuxkit \
                          vendor/github.com/linuxkit/linuxkit/src/cmd/linuxkit" $(dir $<) / $(dir $@)
$(CURDIR)/build-tools/bin/manifest-tool: $(CURDIR)/build-tools/src/manifest-tool/Gopkg.lock | $(GOBUILDER)
	@$(DOCKER_GO) "unset GOFLAGS ; unset GO111MODULE ; go build -ldflags '-X main.gitCommit=$(EVE_TREE_TAG)' -o /go/bin/manifest-tool \
                          vendor/github.com/estesp/manifest-tool" $(dir $<) / $(dir $@)

$(GOBUILDER):
ifneq ($(BUILD),local)
	@echo "Creating go builder image for user $(USER)"
	@docker build --build-arg GOVER=$(GOVER) --build-arg USER=$(USER) --build-arg GROUP=$(GROUP) \
                      --build-arg UID=$(UID) --build-arg GID=$(GID) \
                      $(DOCKER_HTTP_PROXY) $(DOCKER_HTTPS_PROXY) $(DOCKER_NO_PROXY) $(DOCKER_ALL_PROXY) \
                      -t $@ build-tools/src/scripts > /dev/null
	@echo "$@ docker container is ready to use"
endif

#
# Common, generalized rules
#
%.yml: %.yml.in build-tools $(RESCAN_DEPS)
	@$(PARSE_PKGS) $< > $@

%/Dockerfile: %/Dockerfile.in build-tools $(RESCAN_DEPS)
	@$(PARSE_PKGS) $< > $@

eve-%: pkg/%/Dockerfile build-tools $(RESCAN_DEPS)
	@$(LINUXKIT) pkg $(LINUXKIT_PKG_TARGET) $(LINUXKIT_OPTS) pkg/$*

%-show-tag:
	@$(LINUXKIT) pkg show-tag pkg/$*

%Gopkg.lock: %Gopkg.toml | $(GOBUILDER)
	@$(DOCKER_GO) "dep ensure -update $(GODEP_NAME)" $(dir $@)
	@echo Done updating $@

docker-old-images:
	./tools/oldimages.sh

docker-image-clean:
	docker rmi -f $(shell ./tools/oldimages.sh)

.PHONY: all clean test run pkgs help build-tools live rootfs config installer live FORCE $(DIST) HOSTARCH
FORCE:

help:
	@echo "EVE is Edge Virtualization Engine"
	@echo
	@echo "This Makefile automates commons tasks of building and running"
	@echo "  * EVE"
	@echo "  * Installer of EVE"
	@echo "  * linuxkit command line tools"
	@echo "We currently support two platforms: x86_64 and aarch64. There is"
	@echo "even rudimentary support for cross-compiling that can be triggered"
	@echo "by forcing a particular architecture via adding ZARCH=[x86_64|aarch64]"
	@echo "to the make's command line. You can also run in a cross- way since"
	@echo "all the execution is done via qemu."
	@echo
	@echo "Commonly used maintenance and development targets:"
	@echo "   test           run EVE tests"
	@echo "   clean          clean build artifacts in a current directory (doesn't clean Docker)"
	@echo "   release        prepare branch for a release (VERSION=x.y.z required)"
	@echo "   proto          generates Go and Python source from protobuf API definitions"
	@echo "   proto-vendor   update vendored API in packages that require it (e.g. pkg/pillar)"
	@echo "   shell          drop into docker container setup for Go development"
	@echo "   yetus          run Apache Yetus to check the quality of the source tree"
	@echo
	@echo "Commonly used build targets:"
	@echo "   build-tools    builds linuxkit and manifest-tool utilities under build-tools/bin"
	@echo "   config         builds a bundle with initial EVE configs"
	@echo "   pkgs           builds all EVE packages"
	@echo "   pkg/XXX        builds XXX EVE package"
	@echo "   rootfs         builds EVE rootfs image (upload it to the cloud as BaseImage)"
	@echo "   live           builds a full disk image of EVE which can be function as a virtual device"
	@echo "   installer      builds raw disk installer image (to be installed on bootable media)"
	@echo "   installer-iso  builds an ISO installers image (to be installed on bootable media)"
	@echo
	@echo "Commonly used run targets (note they don't automatically rebuild images they run):"
	@echo "   run-compose       runs all EVE microservices via docker-compose deployment"
	@echo "   run-live          runs a full fledged virtual device on qemu (as close as it gets to actual h/w)"
	@echo "   run-rootfs        runs a rootfs.img (limited usefulness e.g. quick test before cloud upload)"
	@echo "   run-grub          runs our copy of GRUB bootloader and nothing else (very limited usefulness)"
	@echo "   run-installer-iso runs installer.iso (via qemu) and 'installs' EVE into (initially blank) target.img"
	@echo "   run-installer-raw runs installer.raw (via qemu) and 'installs' EVE into (initially blank) target.img"
	@echo "   run-target        runs a full fledged virtual device on qemu from target.img (similar to run-live)"
	@echo
	@echo "make run is currently an alias for make run-live"
	@echo
