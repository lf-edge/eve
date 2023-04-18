
# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Run make (with no arguments) to see help on what targets are available

# universal constants and functions
null  :=
space := $(null) #
comma := ,
uniq = $(if $1,$(firstword $1) $(call uniq,$(filter-out $(firstword $1),$1)))

# you are not supposed to tweak these variables -- they are effectively R/O
HV_DEFAULT=kvm
GOVER ?= 1.20.1
PKGBASE=github.com/lf-edge/eve
GOMODULE=$(PKGBASE)/pkg/pillar
GOTREE=$(CURDIR)/pkg/pillar
BUILDTOOLS_BIN=$(CURDIR)/build-tools/bin
PATH:=$(BUILDTOOLS_BIN):$(PATH)

export CGO_ENABLED GOOS GOARCH PATH

ifeq ($(BUILDKIT_PROGRESS),)
export BUILDKIT_PROGRESS := plain
endif

# A set of tweakable knobs for our build needs (tweak at your risk!)
# Which version to assign to snapshot builds (0.0.0 if built locally, 0.0.0-snapshot if on CI/CD)
EVE_SNAPSHOT_VERSION=0.0.0
# which language bindings to generate for EVE API
PROTO_LANGS=go python
# Use 'make HV=acrn|xen|kvm' to build ACRN images (AMD64 only), Xen or KVM
HV=$(HV_DEFAULT)
# Enable development build (disabled by default)
DEV=n
# How large to we want the disk to be in Mb
MEDIA_SIZE=32768
# Image type for final disk images
IMG_FORMAT=qcow2
# Filesystem type for rootfs image
ROOTFS_FORMAT=squash
# Image type for installer image
INSTALLER_IMG_FORMAT=raw
# Image type for verification image
VERIFICATION_IMG_FORMAT=raw
# SSH port to use for running images live
SSH_PORT=2222
# ports to proxy into a running EVE instance (in ssh notation with -L)
SSH_PROXY=-L6000:localhost:6000
# ssh key to be used for getting into an EVE instance
SSH_KEY=$(CONF_DIR)/ssh.key
# Disable QEMU H/W acceleration (any non-empty value will trigger using it)
NOACCEL=
# Use TPM device (any non-empty value will trigger using it), i.e. 'make TPM=y run'
TPM=
# Prune dangling images after build of package to reduce disk usage (any non-empty value will trigger using it)
# Be aware that with this flag we will clean all dangling images in system, not only EVE-OS related
PRUNE=
# Location of the EVE configuration folder to be used in builds
CONF_DIR=conf
# Source of the cloud-init enabled qcow2 Linux VM for all architectures
BUILD_VM_SRC_arm64=https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-arm64.img
BUILD_VM_SRC_amd64=https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img
BUILD_VM_SRC=$(BUILD_VM_SRC_$(ZARCH))

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

REPO_BRANCH=$(shell git rev-parse --abbrev-ref HEAD | tr / _)
REPO_SHA=$(shell git describe --match '$$^' --abbrev=8 --always --dirty)
REPO_TAG=$(shell git describe --always --tags | grep -E '[0-9]*\.[0-9]*\.[0-9]*' || echo snapshot)
REPO_DIRTY_TAG=$(if $(findstring -dirty,$(REPO_SHA)),-$(shell date -u +"%Y-%m-%d.%H.%M"))
EVE_TREE_TAG = $(shell git describe --abbrev=8 --always --dirty --tags)

ifeq ($(DEV),y)
	DEV_TAG:=-dev
endif

# ROOTFS_VERSION used to construct the installer directory
ROOTFS_VERSION:=$(if $(findstring snapshot,$(REPO_TAG)),$(EVE_SNAPSHOT_VERSION)-$(REPO_BRANCH)-$(REPO_SHA)$(REPO_DIRTY_TAG)$(DEV_TAG),$(REPO_TAG))

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

FULL_VERSION:=$(ROOTFS_VERSION)-$(HV)-$(ZARCH)

# where we store outputs
DIST=$(CURDIR)/dist/$(ZARCH)
DOCKER_DIST=/eve/dist/$(ZARCH)

LIVE=$(BUILD_DIR)/live
LIVE_IMG=$(BUILD_DIR)/live.$(IMG_FORMAT)
TARGET_IMG=$(BUILD_DIR)/target.img
INSTALLER=$(BUILD_DIR)/installer
VERIFICATION=$(BUILD_DIR)/verification
BUILD_DIR=$(DIST)/$(ROOTFS_VERSION)
CURRENT_DIR=$(DIST)/current
CURRENT_IMG=$(CURRENT_DIR)/live.$(IMG_FORMAT)
CURRENT_SWTPM=$(CURRENT_DIR)/swtpm
CURRENT_INSTALLER=$(CURRENT_DIR)/installer
INSTALLER_IMG=$(INSTALLER).$(INSTALLER_IMG_FORMAT)
VERIFICATION_IMG=$(VERIFICATION).$(VERIFICATION_IMG_FORMAT)
INSTALLER_FIRMWARE_DIR=$(INSTALLER)/firmware
CURRENT_FIRMWARE_DIR=$(CURRENT_INSTALLER)/firmware
UBOOT_IMG=$(INSTALLER_FIRMWARE_DIR)/boot

# not every firmware file is used on every architecture
BIOS_IMG_amd64=$(INSTALLER_FIRMWARE_DIR)/OVMF.fd $(INSTALLER_FIRMWARE_DIR)/OVMF_CODE.fd $(INSTALLER_FIRMWARE_DIR)/OVMF_VARS.fd
BIOS_IMG_arm64=$(INSTALLER_FIRMWARE_DIR)/OVMF.fd $(INSTALLER_FIRMWARE_DIR)/OVMF_VARS.fd
BIOS_IMG_riscv64=$(INSTALLER_FIRMWARE_DIR)/OVMF.fd $(INSTALLER_FIRMWARE_DIR)/OVMF_CODE.fd $(INSTALLER_FIRMWARE_DIR)/OVMF_VARS.fd
BIOS_IMG=$(BIOS_IMG_$(ZARCH))

RUNME=$(BUILD_DIR)/runme.sh
BUILD_YML=$(BUILD_DIR)/build.yml

BUILD_VM=$(DIST)/build-vm.qcow2
BUILD_VM_CLOUD_INIT=$(DIST)/build-vm-ci.qcow2

ROOTFS=$(INSTALLER)/rootfs
ROOTFS_FULL_NAME=$(INSTALLER)/rootfs-$(ROOTFS_VERSION)
ROOTFS_COMPLETE=$(ROOTFS_FULL_NAME)-%-$(ZARCH).$(ROOTFS_FORMAT)
ROOTFS_IMG=$(ROOTFS).img
# ROOTFS_TAR is in BUILD_DIR, not installer, so it does not get installed
ROOTFS_TAR=$(BUILD_DIR)/rootfs.tar
CONFIG_IMG=$(INSTALLER)/config.img
INITRD_IMG=$(INSTALLER)/initrd.img
INSTALLER_IMG=$(INSTALLER)/installer.img
VERIFICATION_IMG=$(INSTALLER)/verification.img
PERSIST_IMG=$(INSTALLER)/persist.img
KERNEL_IMG=$(INSTALLER)/kernel
IPXE_IMG=$(INSTALLER)/ipxe.efi
EFI_PART=$(INSTALLER)/EFI
BOOT_PART=$(INSTALLER)/boot
BSP_IMX_PART=$(INSTALLER)/bsp-imx

SBOM?=$(ROOTFS).spdx.json
COLLECTED_SOURCES=$(BUILD_DIR)/collected_sources.tar.gz
DEVICETREE_DTB_amd64=
DEVICETREE_DTB_arm64=$(DIST)/dtb/eve.dtb
DEVICETREE_DTB=$(DEVICETREE_DTB_$(ZARCH))

CONF_FILES=$(shell ls -d $(CONF_DIR)/*)
PART_SPEC=efi conf imga

# parallels settings
# https://github.com/qemu/qemu/blob/595123df1d54ed8fbab9e1a73d5a58c5bb71058f/docs/interop/prl-xml.txt
# predefined GUID according link ^
PARALLELS_UUID={5fbaabe3-6958-40ff-92a7-860e329aab41}
PARALLELS_VM_NAME=EVE_Live
PARALLELS_CPUS=2 #num
PARALLELS_MEMORY=2048 #in megabytes

# VirtualBox settings
VB_VM_NAME=EVE_Live
VB_CPUS=2 #num
VB_MEMORY=2048 #in megabytes

# public cloud settings (only GCP is supported for now)
# note how GCP doesn't like dots so we replace them with -
CLOUD_IMG_NAME=$(subst .,-,live-$(FULL_VERSION))
CLOUD_PROJECT=-project lf-edge-eve
CLOUD_BUCKET=-bucket eve-live
CLOUD_INSTANCE=-zone us-west1-a -machine n1-standard-1

# qemu settings
QEMU_SYSTEM_arm64=qemu-system-aarch64
QEMU_SYSTEM_amd64=qemu-system-x86_64
QEMU_SYSTEM_riscv64=qemu-system-riscv64
QEMU_SYSTEM=$(QEMU_SYSTEM_$(ZARCH))

ifeq ($(NOACCEL),)
ACCEL=1
else
ACCEL=
endif
QEMU_ACCEL_Y_Darwin_amd64=-machine q35,accel=hvf,usb=off -cpu kvm64,kvmclock=off
QEMU_ACCEL_Y_Linux_amd64=-machine q35,accel=kvm,usb=off,dump-guest-core=off -cpu host,invtsc=on,kvmclock=off -machine kernel-irqchip=split -device intel-iommu,intremap=on,caching-mode=on,aw-bits=48
# -machine virt,gic_version=3
QEMU_ACCEL_Y_Linux_arm64=-machine virt,accel=kvm,usb=off,dump-guest-core=off -cpu host
QEMU_ACCEL__$(shell uname -s)_arm64=-machine virt,virtualization=true -cpu cortex-a57
QEMU_ACCEL__$(shell uname -s)_amd64=-machine q35 -cpu SandyBridge
QEMU_ACCEL__$(shell uname -s)_riscv64=-machine virt -cpu rv64
QEMU_ACCEL:=$(QEMU_ACCEL_$(ACCEL:%=Y)_$(shell uname -s)_$(ZARCH))

QEMU_OPTS_NET1=192.168.1.0/24
QEMU_OPTS_NET1_FIRST_IP=192.168.1.10
QEMU_OPTS_NET2=192.168.2.0/24
QEMU_OPTS_NET2_FIRST_IP=192.168.2.10

QEMU_MEMORY:=4096

PFLASH_amd64=y
PFLASH=$(PFLASH_$(ZARCH))
QEMU_OPTS_BIOS_y=-drive if=pflash,format=raw,unit=0,readonly,file=$(CURRENT_FIRMWARE_DIR)/OVMF_CODE.fd -drive if=pflash,format=raw,unit=1,file=$(CURRENT_FIRMWARE_DIR)/OVMF_VARS.fd
QEMU_OPTS_BIOS_=-bios $(CURRENT_FIRMWARE_DIR)/OVMF.fd
QEMU_OPTS_BIOS=$(QEMU_OPTS_BIOS_$(PFLASH))

QEMU_TPM_DEVICE_amd64=tpm-tis
QEMU_TPM_DEVICE_arm64=tpm-tis-device
QEMU_TPM_DEVICE_riscv64=tpm-tis
QEMU_OPTS_TPM_Y_$(ZARCH)=-chardev socket,id=chrtpm,path=$(CURRENT_SWTPM)/swtpm-sock -tpmdev emulator,id=tpm0,chardev=chrtpm -device $(QEMU_TPM_DEVICE_$(ZARCH)),tpmdev=tpm0
QEMU_OPTS_TPM=$(QEMU_OPTS_TPM_$(TPM:%=Y)_$(ZARCH))

QEMU_OPTS_amd64=-smbios type=1,serial=31415926
QEMU_OPTS_arm64=-smbios type=1,serial=31415926 -drive file=fat:rw:$(dir $(DEVICETREE_DTB)),label=QEMU_DTB,format=vvfat
QEMU_OPTS_riscv64=-kernel $(UBOOT_IMG)/u-boot.bin -device virtio-blk,drive=uefi-disk
QEMU_OPTS_COMMON= -m $(QEMU_MEMORY) -smp 4 -display none $(QEMU_OPTS_BIOS) \
        -serial mon:stdio      \
	-global ICH9-LPC.noreboot=false -watchdog-action reset \
        -rtc base=utc,clock=rt \
        -netdev user,id=eth0,net=$(QEMU_OPTS_NET1),dhcpstart=$(QEMU_OPTS_NET1_FIRST_IP),hostfwd=tcp::$(SSH_PORT)-:22$(QEMU_TFTP_OPTS) -device virtio-net-pci,netdev=eth0,romfile="" \
        -netdev user,id=eth1,net=$(QEMU_OPTS_NET2),dhcpstart=$(QEMU_OPTS_NET2_FIRST_IP) -device virtio-net-pci,netdev=eth1,romfile="" \
        -device nec-usb-xhci,id=xhci \
        -qmp unix:$(CURDIR)/qmp.sock,server,wait=off
QEMU_OPTS_CONF_PART=$(shell [ -d "$(CONF_PART)" ] && echo '-drive file=fat:rw:$(CONF_PART),format=raw')
QEMU_OPTS=$(QEMU_OPTS_COMMON) $(QEMU_ACCEL) $(QEMU_OPTS_$(ZARCH)) $(QEMU_OPTS_CONF_PART) $(QEMU_OPTS_TPM)
# -device virtio-blk-device,drive=image -drive if=none,id=image,file=X
# -device virtio-net-device,netdev=user0 -netdev user,id=user0,hostfwd=tcp::1234-:22

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

# use "make V=1" for verbose logging
DASH_V :=
QUIET := @
SET_X := :
ifeq ($(V),1)
  DASH_V := -v
  QUIET :=
  SET_X := set -x
endif

DOCKER_GO = _() { $(SET_X); mkdir -p $(CURDIR)/.go/src/$${3:-dummy} ; mkdir -p $(CURDIR)/.go/bin ; \
    docker_go_line="docker run $$DOCKER_GO_ARGS -i --rm -u $(USER) -w /go/src/$${3:-dummy} \
    -v $(CURDIR)/.go:/go:z -v $$2:/go/src/$${3:-dummy}:z -v $${4:-$(CURDIR)/.go/bin}:/go/bin:z -v $(CURDIR)/:/eve:z -v $${HOME}:/home/$(USER):z \
    -e GOOS -e GOARCH -e CGO_ENABLED -e BUILD=local $(GOBUILDER) bash --noprofile --norc -c" ; \
    verbose=$(V) ;\
    verbose=$${verbose:-0} ;\
    [ $$verbose -ge 1 ] && echo $$docker_go_line "\"$$1\""; \
    $$docker_go_line "$$1" ; } ; _

PARSE_PKGS=$(if $(strip $(EVE_HASH)),EVE_HASH=)$(EVE_HASH) DOCKER_ARCH_TAG=$(DOCKER_ARCH_TAG) ./tools/parse-pkgs.sh
LINUXKIT=$(BUILDTOOLS_BIN)/linuxkit
LINUXKIT_VERSION=8b04a8c92affacb13584c164161d7253d4b7ba4b
LINUXKIT_SOURCE=https://github.com/linuxkit/linuxkit.git
LINUXKIT_OPTS=$(if $(strip $(EVE_HASH)),--hash) $(EVE_HASH) $(if $(strip $(EVE_REL)),--release) $(EVE_REL)
LINUXKIT_PKG_TARGET=build
LINUXKIT_PATCHES_DIR=tools/linuxkit/patches
RESCAN_DEPS=FORCE
# set FORCE_BUILD to --force to enforce rebuild
FORCE_BUILD=

# for the go build sources
GOSOURCES=$(BUILDTOOLS_BIN)/go-sources-and-licenses
GOSOURCES_VERSION=c73009667f4871c084c1f2164063321c81d053a2
GOSOURCES_SOURCE=github.com/deitch/go-sources-and-licenses


SYFT_VERSION:=v0.78.0
SYFT_IMAGE:=docker.io/anchore/syft:$(SYFT_VERSION)

# we use the following block to assign correct tag to the Docker registry artifact
ifeq ($(LINUXKIT_PKG_TARGET),push)
  # only builds from master branch are allowed to be called snapshots
  # everything else gets tagged with a branch name itself UNLESS
  # we're building off of a annotated tag
  EVE_REL_$(REPO_BRANCH)_$(REPO_TAG):=$(REPO_TAG)
  EVE_REL_$(REPO_BRANCH)_snapshot:=$(REPO_BRANCH)
  EVE_REL_master_snapshot:=snapshot
  EVE_REL:=$(EVE_REL_$(REPO_BRANCH)_$(REPO_TAG))

  # the only time we rebuild everything from scratch is when we're building 'latest' release
  # in order to achieve that we have to force EVE_HASH to be the release version
  ifeq ($(shell [ "`git tag | grep -E '[0-9]*\.[0-9]*\.[0-9]*' | sort -t. -n -k1,1 -k2,2 -k3,3 | tail -1`" = $(REPO_TAG) ] && echo latest),latest)
    EVE_HASH:=$(REPO_TAG)
    EVE_REL:=latest
  endif
endif

# We are currently filtering out a few packages from bulk builds
# since they are not getting published in Docker HUB
PKGS_$(ZARCH)=$(shell ls -d pkg/* | grep -Ev "eve|test-microsvcs|alpine")
PKGS_riscv64=pkg/ipxe pkg/mkconf pkg/mkimage-iso-efi pkg/grub     \
             pkg/mkimage-raw-efi pkg/uefi pkg/u-boot pkg/cross-compilers pkg/new-kernel \
	     pkg/debug pkg/dom0-ztools pkg/gpt-tools pkg/storage-init pkg/mkrootfs-squash \
		 pkg/bsp-imx
# alpine-base and alpine must be the first packages to build
PKGS=pkg/alpine $(PKGS_$(ZARCH))
# eve-alpine-base is bootstrap image for eve-alpine
# to update please see https://github.com/lf-edge/eve/blob/master/docs/BUILD.md#how-to-update-eve-alpine-package
# if you want to bootstrap eve-alpine again, uncomment the line below
# PKGS:=pkg/alpine-base $(PKGS)

# these are the packages that, when built, also need to be loaded into docker
# if you need a pkg to be loaded into docker, in addition to the lkt cache, add it here
PKGS_DOCKER_LOAD=mkconf mkimage-iso-efi mkimage-raw-efi mkverification-raw-efi mkrootfs-ext4 mkrootfs-squash
# these packages should exists for HOSTARCH as well as for ZARCH
# alpine-base, alpine and cross-compilers are dependencies for others
PKGS_HOSTARCH=alpine-base alpine cross-compilers $(PKGS_DOCKER_LOAD)
# Top-level targets

all: help
	$(QUIET): $@: Succeeded

# just reports the version, without appending qualifies like HVM or such
version:
	@echo $(ROOTFS_VERSION)

# makes a link to current
current: $(CURRENT_DIR)
$(CURRENT_DIR): $(BUILD_DIR)
	@rm -f $@ && ln -s $(BUILD_DIR) $@

# reports the image version that current points to
# we explicitly do *not* use $(BUILD_DIR), because that is recalculated each time, and it might have changed
# since we last built. We just want to know what current is pointing to *now*, not what it might point to
# if we ran a new build.
currentversion:
	#echo $(shell readlink $(CURRENT) | sed -E 's/rootfs-(.*)\.[^.]*$/\1/')
	@cat $(CURRENT_DIR)/installer/eve_version


kernel-yml:
	$(QUIET)if [ ! -f "pkg/kernel/build.yml" ] || [ ! -f "pkg/new-kernel/build.yml" ]; then tools/kernel-build-yml.sh; fi


.PHONY: currentversion linuxkit kernel-yml

test: $(LINUXKIT) test-images-patches | $(DIST)
	@echo Running tests on $(GOMODULE)
	$(QUIET)$(DOCKER_GO) "gotestsum --jsonfile $(DOCKER_DIST)/results.json --junitfile $(DOCKER_DIST)/results.xml" $(GOTREE) $(GOMODULE)
	$(QUIET): $@: Succeeded

# wrap command into DOCKER_GO and propagate it to the pillar's Makefile
# for example make pillar-fmt will run docker container based on
# build-tools/src/scripts/Dockerfile
# mount pkg/pillar into it
# and will run make fmt
pillar-%: $(GOBUILDER) | $(DIST)
	@echo Running make $* on pillar
	$(QUIET)$(DOCKER_GO) "make $*" $(GOTREE)
	$(QUIET): $@: Succeeded

clean:
	rm -rf $(DIST) images/*.yml

yetus:
	@echo Running yetus
	mkdir -p yetus-output
	docker run -it --rm -v $(CURDIR):/src:delegated,z ghcr.io/apache/yetus:0.14.1 \
		--basedir=/src \
		--dirty-workspace \
		--empty-patch \
		--plugins=all \
		--patch-dir=/src/yetus-output

build-tools: $(LINUXKIT)
	@echo Done building $<

$(BUILD_VM_CLOUD_INIT): build-tools/src/scripts/cloud-init.in | $(DIST)
	@if [ -z "$(BUILD_VM_SSH_PUB_KEY)" ] || [ -z "$(BUILD_VM_GH_TOKEN)" ]; then                  \
	    echo "Must be run as: make BUILD_VM_SSH_PUB_KEY=XXX BUILD_VM_GH_TOKEN=YYY $@" && exit 1 ;\
	fi
	$(QUIET)sed -e 's#@ZARCH@#$(subst amd64,x64,$(ZARCH))#' -e 's#@SSH_PUB_KEY@#$(BUILD_VM_SSH_PUB_KEY)#g'  \
	     -e 's#@GH_TOKEN@#$(BUILD_VM_GH_TOKEN)#g' < $< | docker run -i alpine:edge sh -c             \
	          'apk add cloud-utils > /dev/null 2>&1 && cloud-localds --disk-format qcow2 _ - && cat _' > $@

$(BUILD_VM).orig: | $(DIST)
	@curl -L $(BUILD_VM_SRC) > $@

$(BUILD_VM): $(BUILD_VM_CLOUD_INIT) $(BUILD_VM).orig $(DEVICETREE_DTB) $(BIOS_IMG) $(SWTPM) | $(DIST)
	cp $@.orig $@.active
	# currently a fulle EVE build *almost* fits into 40Gb -- we need twice as much in a VM
	qemu-img resize $@.active 100G
	$(QEMU_SYSTEM) $(QEMU_OPTS) -drive format=qcow2,file=$@.active -drive format=qcow2,file=$<
	mv $@.active $@

$(DEVICETREE_DTB): $(BIOS_IMG) | $(DIST)
	mkdir $(dir $@) 2>/dev/null || :
	# start swtpm to generate dtb
	$(MAKE) $(SWTPM)
	$(QEMU_SYSTEM) $(QEMU_OPTS) -machine dumpdtb=$@
	$(QUIET): $@: Succeeded

$(EFI_PART): PKG=grub
$(BOOT_PART): PKG=u-boot
$(INITRD_IMG): PKG=mkimage-raw-efi
$(INSTALLER_IMG): PKG=mkimage-raw-efi
$(VERIFICATION_IMG): PKG=mkverification-raw-efi
$(KERNEL_IMG): PKG=kernel
$(IPXE_IMG): PKG=ipxe
$(BIOS_IMG): PKG=uefi
$(UBOOT_IMG): PKG=u-boot
$(BSP_IMX_PART): PKG=bsp-imx
$(EFI_PART) $(BOOT_PART) $(INITRD_IMG) $(INSTALLER_IMG) $(VERIFICATION_IMG) $(KERNEL_IMG) $(IPXE_IMG) $(BIOS_IMG) $(UBOOT_IMG) $(BSP_IMX_PART): $(LINUXKIT) | $(INSTALLER)
	mkdir -p $(dir $@)
	$(LINUXKIT) pkg build --pull --platforms linux/$(ZARCH) pkg/$(PKG) # running linuxkit pkg build _without_ force ensures that we either pull it down or build it.
	cd $(dir $@) && $(LINUXKIT) cache export -arch $(DOCKER_ARCH_TAG) -format filesystem -outfile - $(shell $(LINUXKIT) pkg show-tag pkg/$(PKG)) | tar xvf - $(notdir $@)
	$(QUIET): $@: Succeeded

# run swtpm if TPM flag defined
# to run it please ensure that https://github.com/stefanberger/swtpm package built/installed in your system
# we use --terminate flag, so swtpm will terminate after qemu disconnection
SWTPM_:
SWTPM_Y:
	mkdir -p $(CURRENT_SWTPM)
	swtpm socket --daemon --terminate --tpmstate dir=$(CURRENT_SWTPM) --ctrl type=unixio,path=$(CURRENT_SWTPM)/swtpm-sock --log file=$(CURRENT_SWTPM)/swtpm.log,level=20 --pid file=$(CURRENT_SWTPM)/swtpm.pid --tpm2
SWTPM:=SWTPM_$(TPM:%=Y)

# patch /conf/grub.cfg for developer's builds to enable getty
GETTY:
	echo "Enabling GETTY in grub.cfg"
	grep -qxF 'set_getty' $(CONF_DIR)/grub.cfg || echo 'set_getty' >> $(CONF_DIR)/grub.cfg

# run-installer
#
# This creates an image equivalent to live.img (called target.img)
# through the installer. It's the long road to live.img. Good for
# testing.
#
run-installer-iso: $(BIOS_IMG) $(DEVICETREE_DTB) $(SWTPM) GETTY
	qemu-img create -f ${IMG_FORMAT} $(TARGET_IMG) ${MEDIA_SIZE}M
	$(QEMU_SYSTEM) -drive file=$(TARGET_IMG),format=$(IMG_FORMAT) -cdrom $(INSTALLER).iso -boot d $(QEMU_OPTS)

run-installer-raw: $(BIOS_IMG) $(DEVICETREE_DTB) $(SWTPM) GETTY
	qemu-img create -f ${IMG_FORMAT} $(TARGET_IMG) ${MEDIA_SIZE}M
	$(QEMU_SYSTEM) -drive file=$(TARGET_IMG),format=$(IMG_FORMAT) -drive file=$(INSTALLER).raw,format=raw $(QEMU_OPTS)

run-verification-raw: $(BIOS_IMG) $(DEVICETREE_DTB) $(SWTPM)
	qemu-img create -f ${IMG_FORMAT} $(TARGET_IMG) ${MEDIA_SIZE}M
	@if [ "$(BUILD_DIR)" != "$(shell readlink -f $(CURRENT_DIR))" ]; then\
		cp -r $(BUILD_DIR)/installer $(CURRENT_DIR);\
	fi
	$(QEMU_SYSTEM) -drive file=$(TARGET_IMG),format=$(IMG_FORMAT) -drive file=$(CURRENT_DIR)/verification.raw,format=raw $(QEMU_OPTS)

run-installer-net: QEMU_TFTP_OPTS=,tftp=$(dir $(IPXE_IMG)),bootfile=$(notdir $(IPXE_IMG))
run-installer-net: $(BIOS_IMG) $(IPXE_IMG) $(DEVICETREE_DTB) $(SWTPM) GETTY
	tar -C $(INSTALLER) -xvf $(INSTALLER).net || :
	qemu-img create -f ${IMG_FORMAT} $(TARGET_IMG) ${MEDIA_SIZE}M
	$(QEMU_SYSTEM) -drive file=$(TARGET_IMG),format=$(IMG_FORMAT) $(QEMU_OPTS)

# run MUST NOT change the current dir; it depends on the output being correct from a previous build
run-live run: $(BIOS_IMG) $(DEVICETREE_DTB) $(SWTPM) GETTY
	$(QEMU_SYSTEM) $(QEMU_OPTS) -drive file=$(CURRENT_IMG),format=$(IMG_FORMAT),id=uefi-disk

run-target: $(BIOS_IMG) $(DEVICETREE_DTB) $(SWTPM) GETTY
	$(QEMU_SYSTEM) $(QEMU_OPTS) -drive file=$(TARGET_IMG),format=$(IMG_FORMAT)

run-rootfs: $(BIOS_IMG) $(UBOOT_IMG) $(EFI_PART) $(DEVICETREE_DTB) $(SWTPM) GETTY
	(echo 'set devicetree="(hd0,msdos1)/eve.dtb"' ; echo 'set rootfs_root=/dev/vdb' ; echo 'set root=hd1' ; echo 'export rootfs_root' ; echo 'export devicetree' ; echo 'configfile /EFI/BOOT/grub.cfg' ) > $(EFI_PART)/BOOT/grub.cfg
	$(QEMU_SYSTEM) $(QEMU_OPTS) -drive file=$(ROOTFS_IMG),format=raw -drive file=fat:rw:$(EFI_PART)/..,label=CONFIG,id=uefi-disk,format=vvfat
	$(QUIET): $@: Succeeded

run-grub: $(BIOS_IMG) $(UBOOT_IMG) $(EFI_PART) $(DEVICETREE_DTB) $(SWTPM)  GETTY
	[ -f $(EFI_PART)/BOOT/grub.cfg ] && mv $(EFI_PART)/BOOT/grub.cfg $(EFI_PART)/BOOT/grub.cfg.$(notdir $(shell mktemp))
	$(QEMU_SYSTEM) $(QEMU_OPTS) -drive format=vvfat,id=uefi-disk,label=EVE,file=fat:rw:$(EFI_PART)/..
	$(QUIET): $@: Succeeded

run-compose: images/version.yml
	# we regenerate this on every run, in case things changed
	$(PARSE_PKGS) > tmp/images
	docker-compose -f docker-compose.yml run storage-init sh -c 'rm -rf /run/* /config/* ; cp -Lr /conf/* /config/ ; echo IMGA > /run/eve.id'
	docker-compose -f docker-compose.yml --env-file tmp/images up

run-proxy:
	ssh $(SSH_PROXY) -N -i $(SSH_KEY) -p $(SSH_PORT) -o StrictHostKeyChecking=no -o GlobalKnownHostsFile=/dev/null -o UserKnownHostsFile=/dev/null root@localhost &

run-build-vm: $(BIOS_IMG) $(DEVICETREE_DTB)
	$(QEMU_SYSTEM) $(QEMU_OPTS) -drive format=qcow2,file=$(BUILD_VM)

run-live-vb:
	@[ -f "$(LIVE).vdi" ] || { echo "Please run: make live-vdi"; exit 1; }
	VBoxManage list vms | grep $(VB_VM_NAME) >/dev/null &&  VBoxManage controlvm $(VB_VM_NAME) acpipowerbutton & sleep 10 & VBoxManage unregistervm $(VB_VM_NAME) --delete || echo "No VMs with $(VB_VM_NAME) name"
	VBoxManage createvm --name $(VB_VM_NAME) --register --basefolder $(DIST)/
	VBoxManage modifyvm $(VB_VM_NAME) --cpus $(VB_CPUS) --memory $(VB_MEMORY) --vram 16 --nested-hw-virt on --ostype Ubuntu_64  --mouse usbtablet --graphicscontroller vmsvga --boot1 disk --boot2 net
	VBoxManage storagectl $(VB_VM_NAME) --name "SATA Controller" --add SATA --controller IntelAhci --bootable on --hostiocache on
	VBoxManage storageattach $(VB_VM_NAME)  --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium $(LIVE).vdi
	VBoxManage modifyvm $(VB_VM_NAME) --nic1 natnetwork --nat-network1 natnet1 --cableconnected1 on --natpf1 ssh,tcp,,$(SSH_PORT),,22
	VBoxManage modifyvm $(VB_VM_NAME) --nic2 natnetwork --nat-network2 natnet2 --cableconnected2 on
	VBoxManage startvm  $(VB_VM_NAME)

run-live-parallels:
	@[ -d "$(LIVE).parallels" ] || { echo "Please run: make live-parallels"; exit 1; }
	@prlctl list -a | grep $(PARALLELS_VM_NAME) | grep "invalid" >/dev/null && prlctl unregister $(PARALLELS_VM_NAME) || echo "No invalid $(PARALLELS_VM_NAME) VM"
	@if prlctl list --all | grep "$(PARALLELS_VM_NAME)"; then \
		prlctl stop $(PARALLELS_VM_NAME) --kill; \
		prlctl set $(PARALLELS_VM_NAME) --device-set hdd0 --image $(LIVE).parallels --nested-virt on --adaptive-hypervisor on --hypervisor-type parallels --cpus $(PARALLELS_CPUS) --memsize $(PARALLELS_MEMORY); \
	else \
		prlctl create $(PARALLELS_VM_NAME) --distribution ubuntu --no-hdd --dst $(DIST)/ ; \
		prlctl set $(PARALLELS_VM_NAME) --device-add hdd --image $(LIVE).parallels --nested-virt on --adaptive-hypervisor on --hypervisor-type parallels --cpus $(PARALLELS_CPUS) --memsize $(PARALLELS_MEMORY); \
		prlctl set $(PARALLELS_VM_NAME) --device-del net0 ; \
		prlctl set $(PARALLELS_VM_NAME) --device-add net --type shared --adapter-type virtio --ipadd 192.168.1.0/24 --dhcp yes ; \
		prlctl set $(PARALLELS_VM_NAME) --device-add net --type shared --adapter-type virtio --ipadd 192.168.2.0/24 --dhcp yes ; \
		prlsrvctl net set Shared --nat-tcp-add ssh,$(SSH_PORT),$(PARALLELS_VM_NAME),22 ; \
		prlctl start $(PARALLELS_VM_NAME) ; \
	fi

# alternatively (and if you want greater control) you can replace the first command with
#    gcloud auth activate-service-account --key-file=-
#    gcloud compute images create $(CLOUD_IMG_NAME) --project=lf-edge-eve
#           --source-uri=https://storage.googleapis.com/eve-live/live.img.tar.gz
#           --licenses="https://www.googleapis.com/compute/v1/projects/vm-options/global/licenses/enable-vmx"
run-live-gcp: $(LINUXKIT)
	if gcloud compute images list -$(CLOUD_PROJECT) --filter="name=$(CLOUD_IMG_NAME)" 2>&1 | grep -q 'Listed 0 items'; then \
	    $^ push gcp -nested-virt -img-name $(CLOUD_IMG_NAME) $(CLOUD_PROJECT) $(CLOUD_BUCKET) $(LIVE).img.tar.gz           ;\
	fi
	$^ run gcp $(CLOUD_PROJECT) $(CLOUD_INSTANCE) $(CLOUD_IMG_NAME)

live-gcp-upload: $(LINUXKIT)
	if gcloud compute images list -$(CLOUD_PROJECT) --filter="name=$(CLOUD_IMG_NAME)" 2>&1 | grep -q 'Listed 0 items'; then \
	    $^ push gcp -nested-virt -img-name $(CLOUD_IMG_NAME) $(CLOUD_PROJECT) $(CLOUD_BUCKET) $(LIVE).img.tar.gz           ;\
		echo "Uploaded $(CLOUD_IMG_NAME)"; \
	else \
		echo "Image $(CLOUD_IMG_NAME) already exists in GCP" ;\
	fi

# ensure the dist directory exists
$(DIST) $(BUILD_DIR) $(INSTALLER_FIRMWARE_DIR):
	mkdir -p $@

# ensure the installer dir exists, and save the version in the directory
# we need to save the version including hypervisor and architecture
$(INSTALLER):
	@mkdir -p $@
	@cp -r pkg/eve/installer/* $@
	# sample output 0.0.0-HEAD-a437e8e4-xen-amd64
	@echo $(FULL_VERSION) > $(INSTALLER)/eve_version

$(VERIFICATION):
	@mkdir -p $@
	@cp -r $(INSTALLER)/* $@
	@cp -r pkg/eve-verification/verification/* $@
	@echo $(FULL_VERSION) > $(VERIFICATION)/eve_version

# convenience targets - so you can do `make config` instead of `make dist/config.img`, and `make installer` instead of `make dist/amd64/installer.img
linuxkit: $(LINUXKIT)
build-vm: $(BUILD_VM)
initrd: $(INITRD_IMG)
installer-img: $(INSTALLER_IMG)
kernel: $(KERNEL_IMG)
config: $(CONFIG_IMG)		; $(QUIET): "$@: Succeeded, CONFIG_IMG=$(CONFIG_IMG)"
ssh-key: $(SSH_KEY)
rootfs: $(ROOTFS_TAR) $(ROOTFS_IMG) current
rootfs.tar: $(ROOTFS_TAR)
rootfstar: $(ROOTFS_TAR)
sbom: $(SBOM)
live: $(LIVE_IMG) $(BIOS_IMG) current	; $(QUIET): "$@: Succeeded, LIVE_IMG=$(LIVE_IMG)"
live-%: $(LIVE).%		; $(QUIET): "$@: Succeeded, LIVE=$(LIVE)"
installer: $(INSTALLER_IMG)
installer-%: $(INSTALLER).% current ; @echo "$@: Succeeded, INSTALLER_IMG=$<"
collected_sources: $(COLLECTED_SOURCES)
gosources: $(GOSOURCES)
verification: $(VERIFICATION_IMG)
verification-%: $(VERIFICATION).% current ; @echo "$@: Succeeded, VERIFICATION_IMG=$<"

$(SSH_KEY):
	rm -f $@*
	ssh-keygen -P "" -f $@
	mv $@.pub $(CONF_DIR)/authorized_keys

$(CONFIG_IMG): $(CONF_FILES) | $(INSTALLER)
	./tools/makeconfig.sh $@ "$(ROOTFS_VERSION)" $(CONF_FILES)
	$(QUIET): $@: Succeeded

$(PERSIST_IMG): | $(INSTALLER)
	# 1M of zeroes should be enough to trigger filesystem wipe on first boot
	dd if=/dev/zero bs=1048576 count=1 >> $@
	$(QUIET): $@: Succeeded

$(ROOTFS)-%.img: $(ROOTFS_IMG)
	@rm -f $@ && ln -s $(notdir $<) $@
	$(QUIET): $@: Succeeded

$(ROOTFS_TAR): images/rootfs-$(HV).yml | $(INSTALLER)
	$(QUIET): $@: Begin
	./tools/makerootfs.sh tar -y $< -t $@ -a $(ZARCH)
	$(QUIET): $@: Succeeded

$(ROOTFS_IMG): $(ROOTFS_TAR) | $(INSTALLER)
	$(QUIET): $@: Begin
	./tools/makerootfs.sh imagefromtar -t $(ROOTFS_TAR) -i $@ -f $(ROOTFS_FORMAT) -a $(ZARCH)
	@echo "size of $@ is $$(wc -c < "$@")B"
	@[ $$(wc -c < "$@") -gt $$(( 250 * 1024 * 1024 )) ] && \
	        echo "ERROR: size of $@ is greater than 250MB (bigger than allocated partition)" && exit 1 || :
	$(QUIET): $@: Succeeded

sbom_info:
	@echo "$(SBOM)"

collected_sources_info:
	@echo "$(COLLECTED_SOURCES)"

$(SBOM): $(ROOTFS_TAR)| $(INSTALLER)
	$(QUIET): $@: Begin
	$(eval TMP_ROOTDIR := $(shell mktemp -d))
	# this is a bit of a hack, but we need to extract the rootfs tar to a directory, and it fails if
	# we try to extract character devices, block devices or pipes, so we just exclude the dir.
	# when syft supports reading straight from a tar archive with duplicate entries,
	# this all can go away, and we can read the rootfs.tar
	# see https://github.com/anchore/syft/issues/1400
	tar xf $< -C $(TMP_ROOTDIR) --exclude "dev/*"
	docker run -v $(TMP_ROOTDIR):/rootdir:ro -v $(CURDIR)/.syft.yaml:/syft.yaml:ro $(SYFT_IMAGE) -c /syft.yaml /rootdir > $@
	rm -rf $(TMP_ROOTDIR)
	$(QUIET): $@: Succeeded

$(GOSOURCES):
	$(QUIET): $@: Begin
	$(shell GOBIN=$(BUILDTOOLS_BIN) GO111MODULE=on CGO_ENABLED=0 go install $(GOSOURCES_SOURCE)@$(GOSOURCES_VERSION))
	@echo Done building packages
	$(QUIET): $@: Succeeded

$(COLLECTED_SOURCES): $(ROOTFS_TAR) $(GOSOURCES)| $(INSTALLER)
	$(QUIET): $@: Begin
	bash tools/collect-sources.sh $< $(CURDIR) $@
	$(QUIET): $@: Succeeded

$(LIVE).raw: $(BOOT_PART) $(EFI_PART) $(ROOTFS_IMG) $(CONFIG_IMG) $(PERSIST_IMG) $(BSP_IMX_PART) | $(INSTALLER)
	@[ "$(PLATFORM)" != "${PLATFORM/imx/}" ] && \
		cp $(INSTALLER)/bsp-imx/NXP-EULA-LICENSE.txt $(INSTALLER)/NXP-EULA-LICENSE.txt && \
		cp $(INSTALLER)/bsp-imx/NXP-EULA-LICENSE.txt $(BUILD_DIR)/NXP-EULA-LICENSE.txt && \
		cp $(INSTALLER)/bsp-imx/"$(PLATFORM)"-flash.bin $(INSTALLER)/imx8-flash.bin && \
		cp $(INSTALLER)/bsp-imx/"$(PLATFORM)"-flash.conf $(INSTALLER)/imx8-flash.conf && \
		cp $(INSTALLER)/bsp-imx/*.dtb $(INSTALLER)/boot  || :
	./tools/makeflash.sh -C 350 $| $@ $(PART_SPEC)
	$(QUIET): $@: Succeeded

$(INSTALLER).raw: $(BOOT_PART) $(EFI_PART) $(ROOTFS_IMG) $(INITRD_IMG) $(INSTALLER_IMG) $(CONFIG_IMG) $(PERSIST_IMG) | $(INSTALLER)
	./tools/makeflash.sh -C 350 $| $@ "conf_win installer inventory_win"
	$(QUIET): $@: Succeeded

$(INSTALLER).iso: $(EFI_PART) $(ROOTFS_IMG) $(INITRD_IMG) $(INSTALLER_IMG) $(CONFIG_IMG) $(PERSIST_IMG) | $(INSTALLER)
	./tools/makeiso.sh $| $@ installer
	$(QUIET): $@: Succeeded

$(INSTALLER).net: $(EFI_PART) $(ROOTFS_IMG) $(INITRD_IMG) $(INSTALLER_IMG) $(CONFIG_IMG) $(PERSIST_IMG) $(KERNEL_IMG) | $(INSTALLER)
	./tools/makenet.sh $| $@
	$(QUIET): $@: Succeeded

$(LIVE).vdi: $(LIVE).raw
	qemu-img resize -f raw $< ${MEDIA_SIZE}M
	qemu-img convert -O vdi $< $@

$(LIVE).parallels: $(LIVE).raw
	rm -rf $@; mkdir $@
	qemu-img resize -f raw $< ${MEDIA_SIZE}M
	qemu-img convert -O parallels $< $@/live.0.$(PARALLELS_UUID).hds
	qemu-img info -f parallels --output json $(LIVE).parallels/live.0.$(PARALLELS_UUID).hds | jq --raw-output '.["virtual-size"]' | xargs ./tools/parallels_disk.sh $(LIVE) $(PARALLELS_UUID)

$(VERIFICATION).raw: $(BOOT_PART) $(EFI_PART) $(ROOTFS_IMG) $(INITRD_IMG) $(VERIFICATION_IMG) $(CONFIG_IMG) $(PERSIST_IMG) $(BSP_IMX_PART) | $(VERIFICATION)
	@[ "$(PLATFORM)" != "${PLATFORM/imx/}" ] && \
		cp $(VERIFICATION)/bsp-imx/NXP-EULA-LICENSE.txt $(VERIFICATION)/NXP-EULA-LICENSE.txt && \
		cp $(VERIFICATION)/bsp-imx/NXP-EULA-LICENSE.txt $(BUILD_DIR)/NXP-EULA-LICENSE.txt && \
		cp $(VERIFICATION)/bsp-imx/"$(PLATFORM)"-flash.bin $(VERIFICATION)/imx8-flash.bin && \
		cp $(VERIFICATION)/bsp-imx/"$(PLATFORM)"-flash.conf $(VERIFICATION)/imx8-flash.conf && \
		cp $(VERIFICATION)/bsp-imx/*.dtb $(VERIFICATION)/boot  || :
	./tools/makeverification.sh -C 650 $| $@ "conf_win verification inventory_win"
	$(QUIET): $@: Succeeded

# top-level linuxkit packages targets, note the one enforcing ordering between packages
pkgs: RESCAN_DEPS=
pkgs: build-tools $(PKGS)
	@echo Done building packages

pkg/pillar: pkg/dnsmasq pkg/gpt-tools pkg/dom0-ztools eve-pillar
	$(QUIET): $@: Succeeded
pkg/xen-tools: pkg/uefi eve-xen-tools
	$(QUIET): $@: Succeeded
pkg/%: eve-% FORCE
	$(QUIET): $@: Succeeded

$(RUNME) $(BUILD_YML):
	cp pkg/eve/$(@F) $@

EVE_ARTIFACTS=$(BIOS_IMG) $(EFI_PART) $(CONFIG_IMG) $(PERSIST_IMG) $(INITRD_IMG) $(INSTALLER_IMG) $(ROOTFS_IMG) $(SBOM) $(BSP_IMX_PART) fullname-rootfs $(BOOT_PART)
eve: kernel-yml $(INSTALLER) $(EVE_ARTIFACTS) current $(RUNME) $(BUILD_YML) | $(BUILD_DIR)
	$(QUIET): "$@: Begin: EVE_REL=$(EVE_REL), HV=$(HV), LINUXKIT_PKG_TARGET=$(LINUXKIT_PKG_TARGET)"
	cp images/*.yml $|
	$(PARSE_PKGS) pkg/eve/Dockerfile.in > $|/Dockerfile
	$(LINUXKIT) $(DASH_V) pkg $(LINUXKIT_PKG_TARGET) --platforms linux/$(ZARCH) --hash-path $(CURDIR) --hash $(ROOTFS_VERSION)-$(HV) --docker $(if $(strip $(EVE_REL)),--release) $(EVE_REL)$(if $(strip $(EVE_REL)),-$(HV)) $(FORCE_BUILD) $|
	$(QUIET)if [ -n "$(EVE_REL)" ] && [ $(HV) = $(HV_DEFAULT) ]; then \
	   $(LINUXKIT) $(DASH_V) pkg $(LINUXKIT_PKG_TARGET) --platforms linux/$(ZARCH) --hash-path $(CURDIR) --hash $(EVE_REL)-$(HV) --docker --release $(EVE_REL) $(FORCE_BUILD) $| ;\
	fi
	$(QUIET): $@: Succeeded

.PHONY: image-set outfile-set cache-export cache-export-docker-load cache-export-docker-load-all

image-set:
ifndef IMAGE
	$(error IMAGE is not set)
endif

outfile-set:
ifndef OUTFILE
	$(error OUTFILE is not set)
endif

## exports an image from the linuxkit cache to stdout
cache-export: image-set outfile-set $(LINUXKIT)
	$(eval IMAGE_TAG_OPT := $(if $(IMAGE_NAME),-name $(IMAGE_NAME),))
	$(LINUXKIT) $(DASH_V) cache export -arch $(ZARCH) -outfile $(OUTFILE) $(IMAGE_TAG_OPT) $(IMAGE)

## export an image from linuxkit cache and load it into docker.
cache-export-docker-load: $(LINUXKIT)
	$(eval TARFILE := $(shell mktemp))
	$(MAKE) cache-export OUTFILE=${TARFILE} && cat ${TARFILE} | docker load
	rm -rf ${TARFILE}

%-cache-export-docker-load: $(LINUXKIT)
	$(eval IMAGE_TAG := $(shell $(MAKE) $*-show-tag))
	$(eval CACHE_CONTENT := $(shell $(LINUXKIT) cache ls 2>&1))
	$(if $(filter $(IMAGE_TAG),$(CACHE_CONTENT)),$(MAKE) cache-export-docker-load IMAGE=$(IMAGE_TAG),@echo "Missing image $(IMAGE_TAG) in cache")

## export list of images in PKGS_DOCKER_LOAD from linuxkit cache and load them into docker
## will skip image if not found in cache
cache-export-docker-load-all: $(LINUXKIT) $(addsuffix -cache-export-docker-load,$(PKGS_DOCKER_LOAD))

proto-vendor:
	@$(DOCKER_GO) "cd pkg/pillar ; go mod vendor" $(CURDIR) proto

proto-diagram: $(GOBUILDER)
	@$(DOCKER_GO) "/usr/local/bin/protodot -inc /usr/include -src ./api/proto/config/devconfig.proto -output devconfig && cp ~/protodot/generated/devconfig.* ./api/images && dot ./api/images/devconfig.dot -Tpng -o ./api/images/devconfig.png && echo generated ./api/images/devconfig.*" $(CURDIR) api

.PHONY: proto-api-%

proto: $(GOBUILDER) api/go api/python proto-diagram
	@echo Done building protobuf, you may want to vendor it into pillar by running proto-vendor

api/go: PROTOC_OUT_OPTS=paths=source_relative:
api/go: proto-api-go

api/python: proto-api-python

proto-api-%: $(GOBUILDER)
	rm -rf api/$*/*/; mkdir -p api/$* # building $@
	@$(DOCKER_GO) "protoc -I./proto --$(*)_out=$(PROTOC_OUT_OPTS)./$* \
		proto/*/*.proto" $(CURDIR)/api api

check-patch-%:
	@if ! echo $* | grep -Eq '^[0-9]+\.[0-9]+$$'; then echo "ERROR: must be on a release branch X.Y"; exit 1; fi
	@if ! echo $(EVE_TREE_TAG) | grep -Eq '^$*.[0-9]+-'; then echo "ERROR: can't find previous release's tag X.Y.Z"; exit 1; fi

patch-%: check-patch-%
	@$(eval PATCH_TAG:=$*.$(shell echo $$((`echo $(EVE_TREE_TAG) | sed -e 's#-.*$$##' | cut -f3 -d.` + 1))))

patch-%-stable: patch-%
	@$(eval PATCH_TAG:=$(PATCH_TAG)-lts)

patch: patch-$(REPO_BRANCH)
	@git tag -a -m"Release $(PATCH_TAG)" $(PATCH_TAG)
	@echo "Done tagging $(PATCH_TAG) patch release. Check the branch with git log and then run"
	@echo "  git push origin $(REPO_BRANCH) $(PATCH_TAG)"

release:
	@bail() { echo "ERROR: $$@" ; exit 1 ; } ;\
	 X=`echo $(VERSION) | cut -s -d. -f1` ; Y=`echo $(VERSION) | cut -s -d. -f2` ; Z=`echo $(VERSION) | cut -s -d. -f3` ;\
	 if echo $$Z | grep -Eq '[0-9]+-lts'; then BRANCH=$$X.$$Y-stable; else BRANCH=$$X.$$Y; fi ;\
	 [ -z "$$X" -o -z "$$Y" -o -z "$$Z" ] && bail "VERSION missing (or incorrect). Re-run as: make VERSION=x.y.z $@" ;\
	 (git fetch && [ `git diff origin/master..master | wc -l` -eq 0 ]) || bail "origin/master is different from master" ;\
	 if git checkout $$BRANCH 2>/dev/null ; then \
	    echo "WARNING: branch $$BRANCH already exists: you may want to run make patch instead" ;\
	    git merge origin/master ;\
	 else \
	    git checkout master -b $$BRANCH && echo zedcloud.zededa.net > conf/server &&\
	    git commit -m"Setting default server to prod" conf/server ;\
	 fi || bail "Can't create $$BRANCH branch" ;\
	 git tag -a -m"Release $$X.$$Y.$$Z" $$X.$$Y.$$Z &&\
	 echo "Done tagging $$X.$$Y.$$Z release. Check the branch with git log and then run" &&\
	 echo "  git push origin $$BRANCH $$X.$$Y.$$Z"

shell: $(GOBUILDER)
	$(QUIET)DOCKER_GO_ARGS=-t ; $(DOCKER_GO) bash $(GOTREE) $(GOMODULE)

#
# Utility targets in support of our Dockerized build infrastrucutre
#

# file to store current linuxkit version
# if version mismatch will delete linuxkit to rebuild
# we clean all old saved versions here as well
$(LINUXKIT).$(LINUXKIT_VERSION):
	@rm -rf $(LINUXKIT)*
	@touch $(LINUXKIT).$(LINUXKIT_VERSION)
# build linuxkit for the host OS, not the container OS
$(LINUXKIT): GOOS=$(shell uname -s | tr '[A-Z]' '[a-z]')
$(LINUXKIT): $(LINUXKIT).$(LINUXKIT_VERSION)
$(LINUXKIT): | $(GOBUILDER)
	$(QUIET)$(DOCKER_GO) \
	"unset GOFLAGS; rm -rf /tmp/linuxkit && \
	git clone $(LINUXKIT_SOURCE) /tmp/linuxkit && \
	cd /tmp/linuxkit && \
	git checkout $(LINUXKIT_VERSION) && \
	if [ -e /eve/$(LINUXKIT_PATCHES_DIR) ]; then \
	    patch -p1 < /eve/$(LINUXKIT_PATCHES_DIR)/*.patch; \
	fi && \
	cd /tmp/linuxkit/src/cmd/linuxkit && \
	GO111MODULE=on CGO_ENABLED=0 go build -o /go/bin/linuxkit -mod=vendor . && \
	cd && \
	rm -rf /tmp/linuxkit" \
	$(GOTREE) $(GOMODULE) $(BUILDTOOLS_BIN)
	$(QUIET): $@: Succeeded


$(GOBUILDER):
	$(QUIET): "$@: Begin: GOBUILDER=$(GOBUILDER)"
ifneq ($(BUILD),local)
	@echo "Creating go builder image for user $(USER)"
	$(QUIET)docker build --build-arg GOVER=$(GOVER) --build-arg USER=$(USER) --build-arg GROUP=$(GROUP) \
                      --build-arg UID=$(UID) --build-arg GID=$(GID) \
                      $(DOCKER_HTTP_PROXY) $(DOCKER_HTTPS_PROXY) $(DOCKER_NO_PROXY) $(DOCKER_ALL_PROXY) \
                      -t $@ build-tools/src/scripts > /dev/null
	@echo "$@ docker container is ready to use"
endif
	$(QUIET): $@: Succeeded

#
# Common, generalized rules
#
%.gcp: %.raw | $(DIST)
	cp $< $@
	dd of=$@ bs=1 seek=$$(($(MEDIA_SIZE) * 1024 * 1024)) count=0
	rm -f $(dir $@)/disk.raw ; ln -s $(notdir $@) $(dir $@)/disk.raw
	$(DOCKER_GO) "tar --mode=644 --owner=root --group=root -S -h -czvf $(notdir $*).img.tar.gz disk.raw" $(dir $@) dist
	rm -f $(dir $@)/disk.raw
	$(QUIET): $(dir $@)/$(notdir $*).img.tar.gz: Succeeded

%.qcow2: %.raw | $(DIST)
	qemu-img convert -c -f raw -O qcow2 $< $@
	qemu-img resize $@ ${MEDIA_SIZE}M
	$(QUIET): $@: Succeeded

%.yml: %.yml.in build-tools $(RESCAN_DEPS)
	$(QUIET)$(PARSE_PKGS) $< > $@
	$(QUIET): $@: Succeeded

%/Dockerfile: %/Dockerfile.in build-tools $(RESCAN_DEPS)
	$(QUIET)$(PARSE_PKGS) $< > $@
	$(QUIET): $@: Succeeded


# If DEV=y and file pkg/my_package/build-dev.yml returns the path to that file.
# If RSTATS=y and file pkg/my_package/build-rstats.yml returns the path to that file.
# Ortherwise returns pkg/my_package/build.yml.
get_pkg_build_yml = $(if $(filter y,$(RSTATS)), $(call get_pkg_build_rstats_yml,$1), $(call get_pkg_build_def_yml,$1))
get_pkg_build_def_yml = $(if $(filter y,$(DEV)),$(call get_pkg_build_dev_yml,$1),build.yml)
get_pkg_build_dev_yml = $(if $(wildcard pkg/$1/build-dev.yml),build-dev.yml,build.yml)
get_pkg_build_rstats_yml = $(if $(wildcard pkg/$1/build-rstats.yml),build-rstats.yml,build.yml)

eve-%: pkg/%/Dockerfile build-tools $(RESCAN_DEPS)
	$(QUIET)if [ "$@" = "eve-kernel" ] || [ "$@" = "eve-new-kernel" ]; then tools/kernel-build-yml.sh; fi
	$(QUIET): "$@: Begin: LINUXKIT_PKG_TARGET=$(LINUXKIT_PKG_TARGET)"
	$(eval LINUXKIT_DOCKER_LOAD := $(if $(filter $(PKGS_DOCKER_LOAD),$*),--docker,))
	$(eval LINUXKIT_BUILD_PLATFORMS_LIST := $(call uniq,linux/$(ZARCH) $(if $(filter $(PKGS_HOSTARCH),$*),linux/$(HOSTARCH),)))
	$(eval LINUXKIT_BUILD_PLATFORMS := --platforms $(subst $(space),$(comma),$(strip $(LINUXKIT_BUILD_PLATFORMS_LIST))))
	$(eval LINUXKIT_FLAGS := $(if $(filter manifest,$(LINUXKIT_PKG_TARGET)),,$(FORCE_BUILD) $(LINUXKIT_DOCKER_LOAD) $(LINUXKIT_BUILD_PLATFORMS)))
	$(QUIET)$(LINUXKIT) $(DASH_V) pkg $(LINUXKIT_PKG_TARGET) $(LINUXKIT_OPTS) $(LINUXKIT_FLAGS) -build-yml $(call get_pkg_build_yml,$*) pkg/$*
	$(QUIET)if [ -n "$(PRUNE)" ]; then \
  		$(LINUXKIT) pkg builder prune; \
  		docker image prune -f; \
  	fi
	$(QUIET): "$@: Succeeded (intermediate for pkg/%)"

images/rootfs-%.yml.in: images/rootfs.yml.in FORCE
	$(QUITE)tools/compose-image-yml.sh $< $@ "$(ROOTFS_VERSION)-$*-$(ZARCH)"

images-patches := $(wildcard images/*.yq)
test-images-patches: $(images-patches:%.yq=%)

$(ROOTFS_FULL_NAME)-adam-kvm-$(ZARCH).$(ROOTFS_FORMAT): $(ROOTFS_FULL_NAME)-kvm-adam-$(ZARCH).$(ROOTFS_FORMAT)
$(ROOTFS_FULL_NAME)-kvm-adam-$(ZARCH).$(ROOTFS_FORMAT): fullname-rootfs $(SSH_KEY)
fullname-rootfs: $(ROOTFS_FULL_NAME)-$(HV)-$(ZARCH).$(ROOTFS_FORMAT) current
$(ROOTFS_FULL_NAME)-%-$(ZARCH).$(ROOTFS_FORMAT): $(ROOTFS_IMG)
	@rm -f $@ && ln -s $(notdir $<) $@
	$(QUIET): $@: Succeeded

%-show-tag:
	@$(LINUXKIT) pkg show-tag -canonical pkg/$*

%Gopkg.lock: %Gopkg.toml | $(GOBUILDER)
	@$(DOCKER_GO) "dep ensure -update $(GODEP_NAME)" $(dir $@)
	@echo Done updating $@

docker-old-images:
	./tools/oldimages.sh

docker-image-clean:
	docker rmi -f $(shell ./tools/oldimages.sh)

.PRECIOUS: rootfs-% $(ROOTFS)-%.img $(ROOTFS_COMPLETE)
.PHONY: all clean test run pkgs help build-tools live rootfs config installer live current FORCE $(DIST) HOSTARCH image-set cache-export
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
	@echo "   build-vm       prepare a build VM for EVE in qcow2 format"
	@echo "   test           run EVE tests"
	@echo "   clean          clean build artifacts in a current directory (doesn't clean Docker)"
	@echo "   release        prepare branch for a release (VERSION=x.y.z required)"
	@echo "   patch          make a patch release on a current branch (must be a release branch)"
	@echo "   proto          generates Go and Python source from protobuf API definitions"
	@echo "   proto-vendor   update vendored API in packages that require it (e.g. pkg/pillar)"
	@echo "   shell          drop into docker container setup for Go development"
	@echo "   yetus          run Apache Yetus to check the quality of the source tree"
	@echo
	@echo "Commonly used build targets:"
	@echo "   build-tools      builds linuxkit utilities and installs under build-tools/bin"
	@echo "   config           builds a bundle with initial EVE configs"
	@echo "   pkgs             builds all EVE packages"
	@echo "   pkg/XXX          builds XXX EVE package"
	@echo "   rootfs           builds default EVE rootfs image (upload it to the cloud as BaseImage)"
	@echo "   live             builds a full disk image of EVE which can be function as a virtual device"
	@echo "   live-XXX         builds a particular kind of EVE live image (raw, qcow2, gcp, vdi, parallels)"
	@echo "   installer-raw    builds raw disk installer image (to be installed on bootable media)"
	@echo "   verification-raw builds raw disk verification image (to be installed on bootable media)"
	@echo "   installer-iso    builds an ISO installers image (to be installed on bootable media)"
	@echo "   installer-net    builds a tarball of artifacts to be used for PXE booting"
	@echo
	@echo "Commonly used run targets (note they don't automatically rebuild images they run):"
	@echo "   run-compose          runs all EVE microservices via docker-compose deployment"
	@echo "   run-build-vm         runs a build VM image"
	@echo "   run-live             runs a full fledged virtual device on qemu (as close as it gets to actual h/w)"
	@echo "   run-live-parallels   runs a full fledged virtual device on Parallels Desktop"
	@echo "   run-live-vb          runs a full fledged virtual device on VirtualBox"
	@echo "   run-rootfs           runs a rootfs.img (limited usefulness e.g. quick test before cloud upload)"
	@echo "   run-grub             runs our copy of GRUB bootloader and nothing else (very limited usefulness)"
	@echo "   run-installer-iso    runs installer.iso (via qemu) and 'installs' EVE into (initially blank) target.img"
	@echo "   run-installer-raw    runs installer.raw (via qemu) and 'installs' EVE into (initially blank) target.img"
	@echo "   run-verification-raw runs verification.raw (via qemu), installs EVE into (initially blank) target.img, and verifies it"
	@echo "   run-installer-net    runs installer.net (via qemu/iPXE) and 'installs' EVE into (initially blank) target.img"
	@echo "   run-target           runs a full fledged virtual device on qemu from target.img (similar to run-live)"
	@echo
	@echo "make run is currently an alias for make run-live"
	@echo
