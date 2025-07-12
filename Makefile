
# Copyright (c) 2018-2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Run make (with no arguments) to see help on what targets are available

# disable parallel builds by default
# it can be overridden from make command line using -jN
# we set it to 1 for now to still run it as sequential build by default
NCORES:=1
MAKEFLAGS += -j$(NCORES)

# universal constants and functions
null  :=
space := $(null) #
comma := ,
uniq = $(if $1,$(firstword $1) $(call uniq,$(filter-out $(firstword $1),$1)))

# you are not supposed to tweak these variables -- they are effectively R/O
HV_DEFAULT=kvm
# linuxkit version. This **must** be a published semver version so it can be downloaded already compiled from
# the release page at https://github.com/linuxkit/linuxkit/releases
LINUXKIT_VERSION=v1.7.0
GOVER ?= 1.24.1
PKGBASE=github.com/lf-edge/eve
GOMODULE=$(PKGBASE)/pkg/pillar
GOTREE=$(CURDIR)/pkg/pillar
BUILDTOOLS_BIN=$(CURDIR)/build-tools/bin
LINUXKIT=$(BUILDTOOLS_BIN)/linuxkit
PATH:=$(BUILDTOOLS_BIN):$(PATH)

GOPKGVERSION=$(shell tools/goversion.sh 2>/dev/null)

export CGO_ENABLED GOOS GOARCH PATH

ifeq ($(BUILDKIT_PROGRESS),)
export BUILDKIT_PROGRESS := plain
endif

# A set of tweakable knobs for our build needs (tweak at your risk!)
# Which version to assign to snapshot builds (0.0.0 if built locally, 0.0.0-snapshot if on CI/CD)
EVE_SNAPSHOT_VERSION=0.0.0
# which language bindings to generate for EVE API
PROTO_LANGS=go python
# Use 'make HV=acrn|xen|kvm|kubevirt' to build ACRN images (AMD64 only), Xen or KVM
HV=$(HV_DEFAULT)
# Enable development build (disabled by default)
DEV=n
# How large to we want the disk to be in Mb
MEDIA_SIZE?=32768
# Image type for final disk images
IMG_FORMAT=qcow2
ifdef LIVE_UPDATE
# For live updates we support read-write FS, like ext4
ROOTFS_FORMAT=ext4
# And generate tar faster
LIVE_FAST=1
else
# Filesystem type for rootfs image
ROOTFS_FORMAT?=squash
endif
# Image type for installer image
INSTALLER_IMG_FORMAT=raw
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
UNAME_S_LCASE=$(shell uname -s | tr '[A-Z]' '[a-z]')

# store the goos for local, as an easier-to-reference var
LOCAL_GOOS=$(UNAME_S_LCASE)

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
# set this variable to the current tag only if we are building from a tag (annotated or not), otherwise set it to "snapshot", which means rootfs version will be constructed differently
REPO_TAG=$(shell git describe --always --tags | grep -E '^[0-9]+\.[0-9]+\.[0-9]+(-lts|-rc[0-9]+)?$$' || echo snapshot)
REPO_DIRTY_TAG=$(if $(findstring -dirty,$(REPO_SHA)),-$(shell date -u +"%Y-%m-%d.%H.%M"))
EVE_TREE_TAG = $(shell git describe --abbrev=8 --always --dirty --tags)

ifeq ($(DEV),y)
	DEV_TAG:=-dev
endif

PLATFORM?=generic
export PLATFORM
TAGPLAT=$(if $(filter-out generic,$(PLATFORM)),$(PLATFORM))

# ROOTFS_VERSION used to construct the installer directory
# set this to the current tag only if we are building from a tag
ROOTFS_VERSION:=$(if $(findstring snapshot,$(REPO_TAG)),$(EVE_SNAPSHOT_VERSION)-$(REPO_BRANCH)-$(REPO_SHA)$(REPO_DIRTY_TAG)$(DEV_TAG),$(REPO_TAG))

#if KERNEL_TAG is set, append it to the ROOTFS_VERSION but replace docker.io/lfedge/eve-kernel:eve-kernel- part with k-
SHORT_KERNEL_TAG=$(subst docker.io/lfedge/eve-kernel:eve-kernel-,k-,$(KERNEL_TAG))
ROOTFS_VERSION:=$(if $(SHORT_KERNEL_TAG),$(ROOTFS_VERSION)-$(SHORT_KERNEL_TAG),$(ROOTFS_VERSION))

# For non-generic platforms, include the variant to the rootfs version
ROOTFS_VERSION:=$(if $(TAGPLAT),$(ROOTFS_VERSION)-$(TAGPLAT),$(ROOTFS_VERSION))

HOSTARCH:=$(subst aarch64,arm64,$(subst x86_64,amd64,$(shell uname -m)))
# by default, take the host architecture as the target architecture, but can override with `make ZARCH=foo`
#    assuming that the toolchain supports it, of course...
ZARCH ?= $(HOSTARCH)
export ZARCH
# warn if we are cross-compiling and track it
CROSS ?=
ifneq ($(HOSTARCH),$(ZARCH))
CROSS = 1
endif

DOCKER_ARCH_TAG=$(ZARCH)

FULL_VERSION:=$(ROOTFS_VERSION)-$(HV)-$(ZARCH)

# must be included after ZARCH is set
include $(CURDIR)/kernel-version.mk

# where we store outputs
DIST=$(CURDIR)/dist/$(ZARCH)
DOCKER_DIST=/eve/dist/$(ZARCH)

BUILD_DIR=$(DIST)/$(ROOTFS_VERSION)
INSTALLER=$(BUILD_DIR)/installer
LIVE=$(BUILD_DIR)/live
LIVE_IMG=$(BUILD_DIR)/live.$(IMG_FORMAT)
VERSION_FILE=$(INSTALLER)/eve_version
PLATFORM_FILE=$(INSTALLER)/eve_platform
CURRENT_DIR=$(DIST)/current
CURRENT_IMG=$(CURRENT_DIR)/live.$(IMG_FORMAT)
CURRENT_SWTPM=$(CURRENT_DIR)/swtpm
CURRENT_INSTALLER=$(CURRENT_DIR)/installer
TARGET_IMG=$(CURRENT_DIR)/target.img
INSTALLER_FIRMWARE_DIR=$(INSTALLER)/firmware
CURRENT_FIRMWARE_DIR=$(CURRENT_INSTALLER)/firmware
UBOOT_IMG=$(INSTALLER_FIRMWARE_DIR)/boot

# not every firmware file is used on every architecture
BIOS_IMG_amd64=$(INSTALLER_FIRMWARE_DIR)/OVMF.fd $(INSTALLER_FIRMWARE_DIR)/OVMF_CODE.fd $(INSTALLER_FIRMWARE_DIR)/OVMF_VARS.fd
BIOS_IMG_arm64=$(INSTALLER_FIRMWARE_DIR)/OVMF.fd $(INSTALLER_FIRMWARE_DIR)/OVMF_VARS.fd
BIOS_IMG_riscv64=$(INSTALLER_FIRMWARE_DIR)/OVMF.fd $(INSTALLER_FIRMWARE_DIR)/OVMF_CODE.fd $(INSTALLER_FIRMWARE_DIR)/OVMF_VARS.fd
BIOS_IMG:=$(BIOS_IMG_$(ZARCH))

RUNME=$(BUILD_DIR)/runme.sh
BUILD_YML=$(BUILD_DIR)/build.yml

BUILD_VM=$(DIST)/build-vm.qcow2
BUILD_VM_CLOUD_INIT=$(DIST)/build-vm-ci.qcow2

ROOTFS=$(INSTALLER)/rootfs
ROOTFS_FULL_NAME=$(INSTALLER)/rootfs-$(ROOTFS_VERSION)
ROOTFS_COMPLETE=$(ROOTFS_FULL_NAME)-%-$(ZARCH).$(ROOTFS_FORMAT)
ROOTFS_IMG_BASE=$(ROOTFS)
ROOTFS_IMG_EVAL_HWE=$(ROOTFS_IMG_BASE)-evaluation-hwe.img
ROOTFS_IMG_EVAL_LTS=$(ROOTFS_IMG_BASE)-evaluation-lts.img

ROOTFS_IMGS= $(if $(findstring evaluation,$(PLATFORM)), \
	$(ROOTFS_IMG_BASE).img $(ROOTFS_IMG_BASE)-b.img $(ROOTFS_IMG_BASE)-c.img, \
	$(ROOTFS_IMG_BASE).img)

ROOTFS_GENERIC_IMG_INTERMEDIATE:=$(if $(findstring evaluation,$(PLATFORM)), \
	$(ROOTFS_IMG_BASE)-evaluation-generic.img, \
	$(ROOTFS_IMG_BASE)-$(PLATFORM).img)

# we need intermediate image names with -<PLATFORM>-<ROOTFS FLAVOR> so we can use pattern rules to generate
# rootfs image(s) but scripts expect the rootfs image to be called rootfs[-b|c].img and it is hard to
# pass the names down the pipeline
$(ROOTFS_IMG_BASE).img: $(ROOTFS_GENERIC_IMG_INTERMEDIATE)
	mv $< $@
$(ROOTFS_IMG_BASE)-b.img: $(ROOTFS_IMG_EVAL_HWE)
	mv $< $@
$(ROOTFS_IMG_BASE)-c.img: $(ROOTFS_IMG_EVAL_LTS)
	mv $< $@

# ROOTFS_TAR is in BUILD_DIR, not installer, so it does not get installed
ROOTFS_TAR_BASE=$(BUILD_DIR)/rootfs
ROOTFS_TAR_EVAL_HWE=$(ROOTFS_TAR_BASE)-evaluation-hwe.tar
ROOTFS_TAR_EVAL_LTS=$(ROOTFS_TAR_BASE)-evaluation-lts.tar

# for evaluation platform we generate 3 rootfs tarballs:
ROOTFS_TARS= $(if $(findstring evaluation,$(PLATFORM)), \
	$(ROOTFS_TAR_EVAL_HWE) $(ROOTFS_TAR_EVAL_LTS) $(ROOTFS_TAR_BASE)-evaluation-generic.tar, \
	$(ROOTFS_TAR_BASE)-$(PLATFORM).tar)

CONFIG_IMG=$(INSTALLER)/config.img
INITRD_IMG=$(INSTALLER)/initrd.img
INSTALLER_TAR=$(BUILD_DIR)/installer.tar
INSTALLER_IMG=$(INSTALLER)/installer.img
PERSIST_IMG=$(INSTALLER)/persist.img
NETBOOT=$(BUILD_DIR)/netboot
IPXE_IMG=$(NETBOOT)/ipxe.efi
CURRENT_NETBOOT=$(CURRENT_DIR)/netboot
CURRENT_IPXE_IMG=$(CURRENT_NETBOOT)/ipxe.efi
EFI_PART=$(INSTALLER)/EFI
BOOT_PART=$(INSTALLER)/boot
BSP_IMX_PART=$(INSTALLER)/bsp-imx

SBOM?=$(if $(findstring evaluation,$(PLATFORM)), $(ROOTFS)-evaluation-generic.spdx.json $(ROOTFS)-evaluation-hwe.spdx.json \
    $(ROOTFS)-evaluation-lts.spdx.json , $(ROOTFS)-$(PLATFORM).spdx.json)
SOURCES_DIR=$(BUILD_DIR)/sources
COLLECTED_SOURCES=$(SOURCES_DIR)/collected_sources.tar.gz
DEVICETREE_DTB_amd64=
DEVICETREE_DTB_arm64=$(DIST)/dtb/eve.dtb
DEVICETREE_DTB=$(DEVICETREE_DTB_$(ZARCH))

CONF_FILES=$(shell ls -d $(CONF_DIR)/*)
LIVE_PART_SPEC=$(if $(findstring evaluation,$(PLATFORM)), efi conf imga imgb imgc, efi conf imga)

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
ifeq ($(UNAME_S)_$(ZARCH),Darwin_arm64)
QEMU_DEFAULT_MACHINE=virt,
endif
QEMU_ACCEL_Y_Darwin_amd64=-machine q35,accel=hvf,usb=off -cpu kvm64,kvmclock=off
QEMU_ACCEL_Y_Linux_amd64=-machine q35,accel=kvm,usb=off,dump-guest-core=off -cpu host,invtsc=on,kvmclock=off -machine kernel-irqchip=split -device intel-iommu,intremap=on,caching-mode=on,aw-bits=48
# -machine virt,gic_version=3
QEMU_ACCEL_Y_Darwin_arm64=-machine $(QEMU_DEFAULT_MACHINE)accel=hvf,usb=off -cpu host
QEMU_ACCEL_Y_Linux_arm64=-machine virt,accel=kvm,usb=off,dump-guest-core=off -cpu host
QEMU_ACCEL_Y_$(UNAME_S)_COMMON=
QEMU_ACCEL__$(UNAME_S)_arm64=-machine virt,virtualization=true -cpu cortex-a57
QEMU_ACCEL__$(UNAME_S)_amd64=-machine q35 -cpu SandyBridge
QEMU_ACCEL__$(UNAME_S)_riscv64=-machine virt -cpu rv64
QEMU_ACCEL__$(UNAME_S)_COMMON=-device virtio-rng-pci
QEMU_ACCEL:=$(QEMU_ACCEL_$(ACCEL:%=Y)_$(UNAME_S)_$(ZARCH)) $(QEMU_ACCEL_$(ACCEL:%=Y)_$(UNAME_S)_COMMON)

IPS_NET1=192.168.1.0/24
IPS_NET1_FIRST_IP=192.168.1.10
IPS_NET2=192.168.2.0/24
IPS_NET2_FIRST_IP=192.168.2.10

QEMU_MEMORY?=4096
QEMU_EVE_SERIAL?=31415926

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

ifneq ($(TAP),)
QEMU_OPTS_eth1=-netdev tap,id=eth1,ifname=$(TAP),script="" -device virtio-net-pci,netdev=eth1,csum=off,guest_csum=off,romfile=""
else
QEMU_OPTS_eth1=-netdev user,id=eth1,net=$(IPS_NET2),dhcpstart=$(IPS_NET2_FIRST_IP) -device virtio-net-pci,netdev=eth1,romfile=""
endif

QEMU_OPTS_amd64=-smbios type=1,serial=$(QEMU_EVE_SERIAL)
QEMU_OPTS_arm64=-smbios type=1,serial=$(QEMU_EVE_SERIAL) -drive file=fat:rw:$(dir $(DEVICETREE_DTB)),label=QEMU_DTB,format=vvfat
QEMU_OPTS_riscv64=-kernel $(UBOOT_IMG)/u-boot.bin -device virtio-blk,drive=uefi-disk
QEMU_OPTS_NO_DISPLAY=-display none
QEMU_OPTS_VGA_DISPLAY_amd64=-vga std
QEMU_OPTS_VGA_DISPLAY_arm64=-device virtio-gpu-pci -usb -device usb-ehci,id=ehci -device usb-kbd,bus=ehci.0
QEMU_OPTS_VGA_DISPLAY_riscv64=-vga std
QEMU_OPTS_COMMON= -m $(QEMU_MEMORY) -smp 4  $(QEMU_OPTS_BIOS) \
        -serial mon:stdio      \
        -global ICH9-LPC.noreboot=false -watchdog-action reset \
        -rtc base=utc,clock=rt \
        -netdev user,id=eth0,net=$(IPS_NET1),dhcpstart=$(IPS_NET1_FIRST_IP),hostfwd=tcp::$(SSH_PORT)-:22$(QEMU_TFTP_OPTS) -device virtio-net-pci,netdev=eth0,romfile="" \
	$(QEMU_OPTS_eth1) \
        -device nec-usb-xhci,id=xhci \
        -qmp unix:$(CURDIR)/qmp.sock,server,wait=off
QEMU_OPTS_CONF_PART=$(shell [ -d "$(CONF_PART)" ] && echo '-drive file=fat:rw:$(CONF_PART),format=raw')
QEMU_OPTS=$(QEMU_OPTS_NO_DISPLAY) $(QEMU_OPTS_COMMON) $(QEMU_ACCEL) $(QEMU_OPTS_$(ZARCH)) $(QEMU_OPTS_CONF_PART) $(QEMU_OPTS_TPM)
QEMU_OPTS_GUI=$(QEMU_OPTS_VGA_DISPLAY_$(ZARCH)) $(QEMU_OPTS_COMMON) $(QEMU_ACCEL) $(QEMU_OPTS_$(ZARCH)) $(QEMU_OPTS_CONF_PART) $(QEMU_OPTS_TPM)
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
  DASH_V := -v 2
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

PARSE_PKGS=$(if $(strip $(EVE_HASH)),EVE_HASH=)$(EVE_HASH) DOCKER_ARCH_TAG=$(DOCKER_ARCH_TAG) KERNEL_TAG=$(KERNEL_TAG) \
    KERNEL_EVAL_HWE_TAG=$(KERNEL_EVAL_HWE_TAG) KERNEL_EVAL_LTS_HWE_TAG=$(KERNEL_EVAL_LTS_HWE_TAG) PLATFORM=$(PLATFORM) ./tools/parse-pkgs.sh

LINUXKIT_PKG_TARGET=build

# buildkitd.toml configuration file can control a configuration of the buildkit daemon
# it is used for example to setup a Docker registry mirror for CI to speedup the builds
# this option can be overridden by setting BUILDKIT_CONFIG_FILE variable on make command line
BUILDKIT_CONFIG_FILE ?= /etc/buildkit/buildkitd.toml
BUILDKIT_CONFIG_OPTS := $(if $(filter manifest,$(LINUXKIT_PKG_TARGET)),,$(if $(wildcard $(BUILDKIT_CONFIG_FILE)),--builder-config $(BUILDKIT_CONFIG_FILE),))

LINUXKIT_OPTS=$(if $(strip $(EVE_HASH)),--hash) $(EVE_HASH) $(if $(strip $(EVE_REL)),--release) $(EVE_REL) $(BUILDKIT_CONFIG_OPTS)

ifdef LIVE_FAST
# Check the makerootfs.sh and the linuxkit tool invocation, the --input-tar
# parameter specifically. This will create a new tar based on the old one
# (already generated), which speeds tar generation up a bit.
UPDATE_TAR=-u
endif

RESCAN_DEPS=FORCE
# set FORCE_BUILD to --force to enforce rebuild
FORCE_BUILD=

# ROOTFS_DEPS enforces the scan of all rootfs image dependencies
ifdef ROOTFS_DEPS
ROOTFS_GET_DEPS=-r
else
ROOTFS_GET_DEPS=
endif

# for the go build sources
GOSOURCES=$(BUILDTOOLS_BIN)/go-sources-and-licenses
GOSOURCES_VERSION=v1.0.0
GOSOURCES_SOURCE=github.com/deitch/go-sources-and-licenses

# for the compare sbom and collecte sources
COMPARESOURCES=$(BUILDTOOLS_BIN)/compare-sbom-sources
COMPARE_SOURCE=./tools/compare-sbom-sources

# tool for scan docker package dependencies
GET_DEPS_DIR=./tools/get-deps
GET_DEPS=./tools/get-deps/get-deps

DOCKERFILE_FROM_CHECKER_DIR=./tools/dockerfile-from-checker/
DOCKERFILE_FROM_CHECKER=$(DOCKERFILE_FROM_CHECKER_DIR)/dockerfile-from-checker

SYFT_VERSION:=v0.85.0
SYFT_IMAGE:=docker.io/anchore/syft:$(SYFT_VERSION)

# we use the following block to assign correct tag to the Docker registry artifact
ifeq ($(LINUXKIT_PKG_TARGET),push)
  # only builds from master branch are allowed to be called snapshots
  # everything else gets tagged with a branch name itself UNLESS
  # we're building off of a annotated tag
  EVE_REL_$(REPO_BRANCH)_$(REPO_TAG):=$(if $(TAGPLAT),$(REPO_TAG)-$(TAGPLAT),$(REPO_TAG))
  EVE_REL_$(REPO_BRANCH)_snapshot:=$(REPO_BRANCH)
  EVE_REL_master_snapshot:=$(if $(TAGPLAT),$(TAGPLAT)-snapshot,snapshot)
  EVE_REL:=$(EVE_REL_$(REPO_BRANCH)_$(REPO_TAG))
  EVE_REL:=$(EVE_REL)$(if $(TAGPLAT),-$(TAGPLAT),)
endif

# Check for a custom registry (used for development purposes)
ifdef REGISTRY
LINUXKIT_ORG_TARGET=--org $(REGISTRY)/lfedge
export LINUXKIT_ORG_TARGET
else
LINUXKIT_ORG_TARGET=
endif

# The rootfs partition size is set to 512MB after 10.2.0 release (see commit 719b4d516)
# Before 10.2.0 it was 300MB. We must maintain compatibility with older versions so rootfs size cannot exceed 300MB.
# kubevirt and nvidia are not affected by this limitation because there no installation of kubevirt prior to 10.2.0
# Nevertheless lets check for ROOTFS_MAXSIZE_MB not exceeding 900MB for kubevirt, 450MB for NVIDIA based platforms (arm64) and 270MB for x86_64 and other arm64 platforms
# That helps in catching image size increases earlier than at later stage.
# We are currently filtering out a few packages from bulk builds since they are not getting published in Docker HUB
ifeq ($(HV),kubevirt)
        PKGS_$(ZARCH)=$(shell find pkg -maxdepth 1 -type d | grep -Ev "eve|alpine|sources$$")
        ROOTFS_MAXSIZE_MB=900
else
        #kube container will not be in non-kubevirt builds
        PKGS_$(ZARCH)=$(shell find pkg -maxdepth 1 -type d | grep -Ev "eve|alpine|sources|kube|external-boot-image$$")
        # evaluation platform is not limited by rootfs size, set to some large value
        ifeq ($(PLATFORM),evaluation)
            ROOTFS_MAXSIZE_MB=9999
        # nvidia platform requires more space
        else ifeq (, $(findstring nvidia,$(PLATFORM)))
            ROOTFS_MAXSIZE_MB=270
        else
            ROOTFS_MAXSIZE_MB=450
        endif
endif

PKGS_riscv64=pkg/ipxe pkg/mkconf pkg/mkimage-iso-efi pkg/grub     \
             pkg/mkimage-raw-efi pkg/uefi pkg/u-boot pkg/cross-compilers \
	     pkg/debug pkg/dom0-ztools pkg/gpt-tools pkg/storage-init pkg/mkrootfs-squash \
	     pkg/bsp-imx pkg/optee-os pkg/recovertpm pkg/bpftrace
# alpine-base and alpine must be the first packages to build
PKGS=pkg/alpine $(PKGS_$(ZARCH))
# eve-alpine-base is bootstrap image for eve-alpine
# to update please see https://github.com/lf-edge/eve/blob/master/docs/BUILD.md#how-to-update-eve-alpine-package
# if you want to bootstrap eve-alpine again, uncomment the line below
# PKGS:=pkg/alpine-base $(PKGS)

# these are the packages that, when built, also need to be loaded into docker
# if you need a pkg to be loaded into docker, in addition to the lkt cache, add it here
PKGS_DOCKER_LOAD=mkconf mkimage-iso-efi mkimage-raw-efi mkrootfs-ext4 mkrootfs-squash
# these packages should exists for HOSTARCH as well as for ZARCH
# alpine-base, alpine and cross-compilers are dependencies for others
PKGS_HOSTARCH=alpine-base alpine cross-compilers $(PKGS_DOCKER_LOAD)
# Package dependencies auto-generated by the build system
-include pkg-deps.mk

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
.PHONY: currentversion
currentversion:
	#echo $(shell readlink $(CURRENT) | sed -E 's/rootfs-(.*)\.[^.]*$/\1/')
	@cat $(CURRENT_DIR)/installer/eve_version

test: $(LINUXKIT) pkg/pillar | $(DIST)
	@echo Running tests on $(GOMODULE)
	make -C pkg/pillar test
	cp pkg/pillar/results.json $(DIST)/
	cp pkg/pillar/results.xml $(DIST)/
	make -C eve-tools/bpftrace-compiler test
	make -C pkg/dnsmasq test
	$(QUIET): $@: Succeeded

test-profiling:
	make -C pkg/pillar test-profiling

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
	rm -rf $(DIST) images/out pkg-deps.mk

$(DOCKERFILE_FROM_CHECKER): $(DOCKERFILE_FROM_CHECKER_DIR)/*.go $(DOCKERFILE_FROM_CHECKER_DIR)/go.*
	make -C $(DOCKERFILE_FROM_CHECKER_DIR)

# this next section checks that the FROM hashes for any image in any dockerfile anywhere here are consistent.
# For example, one Dockerfile has foo:abc and the next has foo:def, it will flag them.
# These are the packages that we are ignoring for now
IGNORE_DOCKERFILE_HASHES_PKGS=alpine installer
IGNORE_DOCKERFILE_HASHES_EVE_TOOLS=bpftrace-compiler

IGNORE_DOCKERFILE_DOT_GO_DIR=$(shell find .go/ -name Dockerfile -exec echo "-i {}" \;)
IGNORE_DOCKERFILE_HASHES_PKGS_ARGS=$(foreach pkg,$(IGNORE_DOCKERFILE_HASHES_PKGS),-i pkg/$(pkg)/Dockerfile)
IGNORE_DOCKERFILE_HASHES_EVE_TOOLS_ARGS=$(foreach tool,$(IGNORE_DOCKERFILE_HASHES_EVE_TOOLS),$(addprefix -i ,$(shell find eve-tools/$(tool) -path '*/vendor' -prune -o -name Dockerfile -print)))

.PHONY: check-docker-hashes-consistency
check-docker-hashes-consistency: $(DOCKERFILE_FROM_CHECKER)
	@echo "Checking Dockerfiles for inconsistencies"
	$(DOCKERFILE_FROM_CHECKER) ./ $(IGNORE_DOCKERFILE_HASHES_PKGS_ARGS) $(IGNORE_DOCKERFILE_HASHES_EVE_TOOLS_ARGS) $(IGNORE_DOCKERFILE_DOT_GO_DIR)

yetus:
	@echo Running yetus
	mkdir -p yetus-output
	docker run --rm -v $(CURDIR):/src:delegated,z ghcr.io/apache/yetus:0.15.1 \
		--basedir=/src \
		--test-parallel=true \
		--dirty-workspace \
		--empty-patch \
		--plugins=all \
		--patch-dir=/src/yetus-output

mini-yetus:
	@echo Running mini-yetus
	./tools/mini-yetus.sh $(if $(MYETUS_VERBOSE),-f) $(if $(MYETUS_SBRANCH),-s $(MYETUS_SBRANCH)) $(if $(MYETUS_DBRANCH),-d $(MYETUS_DBRANCH))

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
	$(QEMU_SYSTEM) $(QEMU_OPTS) -machine $(QEMU_DEFAULT_MACHINE)dumpdtb=$@
	$(QUIET): $@: Succeeded

$(EFI_PART): PKG=grub
$(BOOT_PART): PKG=u-boot
$(INITRD_IMG): PKG=mkimage-raw-efi
$(IPXE_IMG): PKG=ipxe
$(BIOS_IMG): PKG=uefi
$(UBOOT_IMG): PKG=u-boot
$(BSP_IMX_PART): PKG=bsp-imx
$(EFI_PART) $(BOOT_PART) $(INITRD_IMG) $(IPXE_IMG) $(BIOS_IMG) $(UBOOT_IMG) $(BSP_IMX_PART): $(LINUXKIT) | $(INSTALLER)
	mkdir -p $(dir $@)
	$(LINUXKIT) pkg build --pull $(LINUXKIT_ORG_TARGET) --platforms linux/$(ZARCH) pkg/$(PKG) # running linuxkit pkg build _without_ force ensures that we either pull it down or build it.
	cd $(dir $@) && $(LINUXKIT) cache export --platform linux/$(DOCKER_ARCH_TAG) --format filesystem --outfile - $(shell $(LINUXKIT) pkg $(LINUXKIT_ORG_TARGET) show-tag pkg/$(PKG)) | tar xvf - $(notdir $@)
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
	if [ ! -f $(CONF_DIR)/grub.cfg ]; then\
	       	cp $(CONF_DIR)/grub.cfg.tmpl $(CONF_DIR)/grub.cfg;\
	fi

# run-installer
#
# This creates an image equivalent to live.img (called target.img)
# through the installer. It's the long road to live.img. Good for
# testing.
#
run-installer-iso: $(SWTPM) GETTY
	qemu-img create -f ${IMG_FORMAT} $(TARGET_IMG) ${MEDIA_SIZE}M
	$(QEMU_SYSTEM) -drive file=$(TARGET_IMG),format=$(IMG_FORMAT) -cdrom $(CURRENT_INSTALLER).iso -boot d $(QEMU_OPTS)

run-installer-raw: $(SWTPM) GETTY
	qemu-img create -f ${IMG_FORMAT} $(TARGET_IMG) ${MEDIA_SIZE}M
	$(QEMU_SYSTEM) -drive file=$(TARGET_IMG),format=$(IMG_FORMAT) -drive file=$(CURRENT_INSTALLER).raw,format=raw $(QEMU_OPTS)

run-installer-net: QEMU_TFTP_OPTS=,tftp=$(dir $(CURRENT_IPXE_IMG)),bootfile=$(notdir $(CURRENT_IPXE_IMG))
run-installer-net: $(SWTPM) GETTY
	tar -C $(CURRENT_NETBOOT) -xvf $(CURRENT_INSTALLER).net || :
	qemu-img create -f ${IMG_FORMAT} $(TARGET_IMG) ${MEDIA_SIZE}M
	$(QEMU_SYSTEM) -drive file=$(TARGET_IMG),format=$(IMG_FORMAT) $(QEMU_OPTS)

# run MUST NOT change the current dir; it depends on the output being correct from a previous build
run-live run: $(SWTPM) GETTY
	$(QEMU_SYSTEM) $(QEMU_OPTS) -drive file=$(CURRENT_IMG),format=$(IMG_FORMAT),id=uefi-disk
run-live-gui: $(SWTPM) GETTY
	$(QEMU_SYSTEM) $(QEMU_OPTS_GUI) -drive file=$(CURRENT_IMG),format=$(IMG_FORMAT),id=uefi-disk

run-target: $(SWTPM) GETTY
	$(QEMU_SYSTEM) $(QEMU_OPTS) -drive file=$(TARGET_IMG),format=$(IMG_FORMAT)

run-rootfs%: $(SWTPM) GETTY
	(echo 'set devicetree="(hd0,msdos1)/eve.dtb"' ; echo 'set rootfs_root=/dev/vdb' ; echo 'set root=hd1' ; echo 'export rootfs_root' ; echo 'export devicetree' ; echo 'configfile /EFI/BOOT/grub.cfg' ) > $(EFI_PART)/BOOT/grub.cfg
	$(QEMU_SYSTEM) $(QEMU_OPTS) -drive file=$(ROOTFS_IMG_BASE)$*.img,format=raw -drive file=fat:rw:$(EFI_PART)/..,label=CONFIG,id=uefi-disk,format=vvfat
	$(QUIET): $@: Succeeded

run-grub: $(SWTPM)  GETTY
	[ -f $(EFI_PART)/BOOT/grub.cfg ] && mv $(EFI_PART)/BOOT/grub.cfg $(EFI_PART)/BOOT/grub.cfg.$(notdir $(shell mktemp))
	$(QEMU_SYSTEM) $(QEMU_OPTS) -drive format=vvfat,id=uefi-disk,label=EVE,file=fat:rw:$(EFI_PART)/..
	$(QUIET): $@: Succeeded

run-compose: images/out/version.yml
	# we regenerate this on every run, in case things changed
	$(PARSE_PKGS) > tmp/images
	docker-compose -f docker-compose.yml run storage-init sh -c 'rm -rf /run/* /config/* ; cp -Lr /conf/* /config/ ; echo IMGA > /run/eve.id'
	docker-compose -f docker-compose.yml --env-file tmp/images up

run-proxy:
	ssh $(SSH_PROXY) -N -i $(SSH_KEY) -p $(SSH_PORT) -o StrictHostKeyChecking=no -o GlobalKnownHostsFile=/dev/null -o UserKnownHostsFile=/dev/null root@localhost &

run-build-vm: $(BIOS_IMG) $(DEVICETREE_DTB)
	$(QEMU_SYSTEM) $(QEMU_OPTS) -drive format=qcow2,file=$(BUILD_VM)

run-live-vb:
	@[ -f "$(CURRENT_DIR)/live.vdi" ] || { echo "Please run: make live-vdi"; exit 1; }
	VBoxManage list vms | grep $(VB_VM_NAME) >/dev/null &&  VBoxManage controlvm $(VB_VM_NAME) acpipowerbutton & sleep 10 & VBoxManage unregistervm $(VB_VM_NAME) --delete || echo "No VMs with $(VB_VM_NAME) name"
	VBoxManage createvm --name $(VB_VM_NAME) --register --basefolder $(DIST)/
	VBoxManage modifyvm $(VB_VM_NAME) --cpus $(VB_CPUS) --memory $(VB_MEMORY) --vram 16 --nested-hw-virt on --ostype Ubuntu_64  --mouse usbtablet --graphicscontroller vmsvga --boot1 disk --boot2 net
	VBoxManage storagectl $(VB_VM_NAME) --name "SATA Controller" --add SATA --controller IntelAhci --bootable on --hostiocache on
	VBoxManage storageattach $(VB_VM_NAME)  --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium $(CURRENT_DIR)/live.vdi
	# Create NAT networks if they don't exist
	VBoxManage natnetwork add --netname natnet1 --network "$(IPS_NET1)" --enable 2>/dev/null || true
	VBoxManage natnetwork add --netname natnet2 --network "$(IPS_NET2)" --enable 2>/dev/null || true
	VBoxManage modifyvm $(VB_VM_NAME) --nic1 natnetwork --nat-network1 natnet1 --cableconnected1 on --natpf1 "ssh,tcp,,$(SSH_PORT),,22"
	VBoxManage modifyvm $(VB_VM_NAME) --nic2 natnetwork --nat-network2 natnet2 --cableconnected2 on
	VBoxManage setextradata $(VB_VM_NAME) "VBoxInternal/Devices/pcbios/0/Config/DmiSystemSerial" "$(QEMU_EVE_SERIAL)"
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
	@echo $(FULL_VERSION) > $(VERSION_FILE)
# for IMX8 platforms reduce the platform name to imx8
# the $(PLATFORM_FILE) is used onlt in eve container to determine the platform family
	@echo $(if $(findstring imx8,$(PLATFORM)),imx8,$(PLATFORM)) > $(PLATFORM_FILE)

$(NETBOOT):
	@mkdir -p $@

# convenience targets - so you can do `make config` instead of `make dist/config.img`, and `make installer` instead of `make dist/amd64/installer.img
build-vm: $(BUILD_VM)
initrd: $(INITRD_IMG)
config: $(CONFIG_IMG)		; $(QUIET): "$@: Succeeded, CONFIG_IMG=$(CONFIG_IMG)"
ssh-key: $(SSH_KEY)
rootfs: $(ROOTFS_IMGS) current
sbom: $(SBOM)
live: $(LIVE_IMG) $(BIOS_IMG) current	; $(QUIET): "$@: Succeeded, LIVE_IMG=$(LIVE_IMG)"
live-%: $(LIVE).%		current ;  $(QUIET): "$@: Succeeded, LIVE=$(LIVE)"
installer: $(INSTALLER).raw current
installer.tar: $(INSTALLER_TAR)
installertar: $(INSTALLER_TAR)
installer-img: $(INSTALLER_IMG)
installer-%: $(INSTALLER).% current ; @echo "$@: Succeeded, INSTALLER_IMG=$<"
collected_sources: $(COLLECTED_SOURCES)
gosources: $(GOSOURCES)

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

$(ROOTFS_TAR_BASE)-%.tar: images/out/rootfs-$(HV)-%.yml | $(INSTALLER)
	$(QUIET): $@: Begin
	echo "Building rootfs tarball $@ from $<"
	./tools/makerootfs.sh tar $(UPDATE_TAR) -y $< -t $@ -d $(INSTALLER) -a $(ZARCH)
	$(QUIET): $@: Succeeded
ifdef KERNEL_IMAGE
	# Consider this as a cry from the heart: enormous amount of time is
	# wasted during kernel rebuild on every small testing change. Now any
	# kernel image can be used by providing path to a file. You heard it
	# right: path-to-a-file. No docker. Yay!
	$(eval KIMAGE = $$(realpath $(KERNEL_IMAGE)))
	@echo "Replace kernel image in \"$@\" with \"$(KIMAGE)\""
	# Delete /boot/kernel kernel image
	tar --delete -f "$@" boot/kernel
	# Append new kernel image and rename
	tar -P -u --transform="flags=r;s|$(KIMAGE)|/boot/kernel|" -f "$@" "$(KIMAGE)"
endif

$(INSTALLER_TAR): images/out/installer-$(HV)-$(PLATFORM).yml $(ROOTFS_IMGS) $(PERSIST_IMG) $(CONFIG_IMG) | $(INSTALLER)
	$(QUIET): $@: Begin
	echo "Building installer tarball from $<"
	./tools/makerootfs.sh tar $(UPDATE_TAR) -y $< -t $@ -d $(INSTALLER) -a $(ZARCH)
	$(QUIET): $@: Succeeded

$(ROOTFS_IMG_BASE)-%.img: pkg/mkrootfs-$(ROOTFS_FORMAT)

ifdef LIVE_UPDATE
# Don't regenerate the whole image if tar was changed, but
# do generate if does not exist. qcow2 target will handle
# the rest
$(ROOTFS_IMG_BASE)-%.img: | $(ROOTFS_TAR_BASE)-%.tar $(INSTALLER)
else
$(ROOTFS_IMG_BASE)-%.img: $(ROOTFS_TAR_BASE)-%.tar | $(INSTALLER)
endif
	$(QUIET): $@: Begin
	echo "Building rootfs image $@ from $<"
	./tools/makerootfs.sh imagefromtar -t $< -i $@ -f $(ROOTFS_FORMAT) -a $(ZARCH)
	@echo "size of $@ is $$(wc -c < "$@")B"
ifeq ($(ROOTFS_FORMAT),squash)
	@[ $$(wc -c < "$@") -gt $$(( $(ROOTFS_MAXSIZE_MB) * 1024 * 1024 )) ] && \
	        echo "ERROR: size of $@ is greater than $(ROOTFS_MAXSIZE_MB)MB (bigger than allocated partition)" && exit 1 || :
endif
	$(QUIET): $@: Succeeded

$(GET_DEPS):
	$(MAKE) -C $(GET_DEPS_DIR) GOOS=$(LOCAL_GOOS)

sbom_info:
	@echo "$(SBOM)"

collected_sources_info:
	@echo "$(COLLECTED_SOURCES)"

$(ROOTFS)-%.spdx.json: $(BUILD_DIR)/rootfs-%.tar | $(INSTALLER)
	$(QUIET): $@: Begin
	# the rootfs-%.tar includes extended PAX headers, which GNU tar does not support.
	# It does not break, but logs two lines of warnings for each file, which is a lot.
	# For BSD tar, no need to do anything; for GNU tar, need to add `--warning=no-unknown-keyword`
	$(eval TAR_OPTS = $(shell tar --version | grep -qi 'GNU tar' && echo --warning=no-unknown-keyword || echo))
	tar $(TAR_OPTS) -xf $< -O sbom.spdx.json > $@
	$(QUIET): $@: Succeeded

$(GOSOURCES):
	$(QUIET): $@: Begin
	$(shell GOBIN=$(BUILDTOOLS_BIN) GO111MODULE=on CGO_ENABLED=0 go install $(GOSOURCES_SOURCE)@$(GOSOURCES_VERSION))
	@echo Done building packages
	$(QUIET): $@: Succeeded

# ensure the installer dir exists, and save the version in the directory
$(SOURCES_DIR):
	@mkdir -p $@

$(COLLECTED_SOURCES): $(ROOTFS_TARS) $(GOSOURCES)| $(INSTALLER) $(SOURCES_DIR)
	$(QUIET): $@: Begin
	bash tools/collect-sources.sh $< $(CURDIR) $@
	$(QUIET): $@: Succeeded

$(COMPARESOURCES):
	$(QUIET): $@: Begin
	cd $(COMPARE_SOURCE) && GOOS=$(LOCAL_GOOS) CGO_ENABLED=0 go build -o $(COMPARESOURCES)
	@echo Done building packages
	$(QUIET): $@: Succeeded

compare_sbom_collected_sources: $(COLLECTED_SOURCES) $(SBOM) | $(COMPARESOURCES)
	$(QUIET): $@: Begin
	$(COMPARESOURCES) $(COLLECTED_SOURCES):./collected_sources_manifest.csv $(SBOM)
	@echo Done comparing the sbom and collected sources manifest file
	$(QUIET): $@: Succeeded

publish_sources: $(COLLECTED_SOURCES)
	$(QUIET): $@: Begin
	cp pkg/sources/* $(SOURCES_DIR)
	$(LINUXKIT) $(DASH_V) pkg $(LINUXKIT_PKG_TARGET) $(LINUXKIT_ORG_TARGET) --platforms linux/$(ZARCH) --hash-path $(CURDIR) --hash $(ROOTFS_VERSION)-$(HV) --docker $(if $(strip $(EVE_REL)),--release) $(EVE_REL)$(if $(strip $(EVE_REL)),-$(HV)) $(SOURCES_DIR) $|
	$(QUIET)if [ -n "$(EVE_REL)" ] && [ $(HV) = $(HV_DEFAULT) ]; then \
	   $(LINUXKIT) $(DASH_V) pkg $(LINUXKIT_PKG_TARGET) $(LINUXKIT_ORG_TARGET) --platforms linux/$(ZARCH) --hash-path $(CURDIR) --hash $(EVE_REL)-$(HV) --docker --release $(EVE_REL) $(SOURCES_DIR) $| ;\
	fi
	$(QUIET): $@: Succeeded


$(LIVE).raw: $(BOOT_PART) $(EFI_PART) $(ROOTFS_IMGS) $(CONFIG_IMG) $(PERSIST_IMG) $(BSP_IMX_PART) $(BIOS_IMG) | $(INSTALLER)
	./tools/prepare-platform.sh "$(PLATFORM)" "$(BUILD_DIR)" "$(INSTALLER)"
	./tools/makeflash.sh "mkimage-raw-efi" -C $| $@ $(LIVE_PART_SPEC)
	$(QUIET): $@: Succeeded

$(INSTALLER_IMG): $(INSTALLER_TAR) | $(INSTALLER)
	$(QUIET): $@: Begin
	./tools/makerootfs.sh imagefromtar -t $(INSTALLER_TAR) -i $@ -f $(ROOTFS_FORMAT) -a $(ZARCH)
	$(QUIET): $@: Succeeded

$(INSTALLER).raw: $(INSTALLER_IMG) $(EFI_PART) $(BOOT_PART) $(CONFIG_IMG) $(BSP_IMX_PART) $(BIOS_IMG) | $(INSTALLER)
	./tools/prepare-platform.sh "$(PLATFORM)" "$(BUILD_DIR)" "$(INSTALLER)"
	./tools/makeflash.sh "mkimage-raw-efi" -C $| $@ "efi conf_win installer inventory_win"
	$(QUIET): $@: Succeeded

$(INSTALLER).iso: $(INSTALLER_TAR) $(BSP_IMX_PART) $(BIOS_IMG) | $(INSTALLER)
	DOCKER_ARCH_TAG=$(DOCKER_ARCH_TAG) ./tools/makeiso.sh $< $@ installer
	$(QUIET): $@: Succeeded

$(INSTALLER).net: $(INSTALLER).iso $(EFI_PART) $(INITRD_IMG) $(CONFIG_IMG) $(IPXE_IMG) $(BIOS_IMG) | $(INSTALLER)
	cp $(IPXE_IMG) $|
	./tools/makenet.sh $| $< $@
	$(QUIET): $@: Succeeded

$(LIVE).vdi: $(LIVE).raw
	qemu-img resize -f raw $< ${MEDIA_SIZE}M
	qemu-img convert -O vdi $< $@

$(LIVE).parallels: $(LIVE).raw
	rm -rf $@; mkdir $@
	qemu-img resize -f raw $< ${MEDIA_SIZE}M
	qemu-img convert -O parallels $< $@/live.0.$(PARALLELS_UUID).hds
	qemu-img info -f parallels --output json $(LIVE).parallels/live.0.$(PARALLELS_UUID).hds | jq --raw-output '.["virtual-size"]' | xargs ./tools/parallels_disk.sh $(LIVE) $(PARALLELS_UUID)

# top-level linuxkit packages targets, note the one enforcing ordering between packages
pkgs: RESCAN_DEPS=
pkgs: $(LINUXKIT) $(PKGS)
	@echo Done building packages

# No-op target for get-deps which looks at
# external-boot-image and sees a dep for eve-kernel
# and attempts to build pkg/kernel, which is in
# lf-edge/eve-kernel and not built here.
pkg/kernel:
	$(QUIET): $@: No-op pkg/kernel

# Need to force build.yml target in order to always get the current KERNEL_TAG
pkg/external-boot-image/build.yml: pkg/external-boot-image/build.yml.in pkg/xen-tools FORCE
	$(QUIET)tools/compose-external-boot-image-yml.sh $< $@ $(shell echo $(KERNEL_TAG) | cut -d':' -f2) $(shell $(LINUXKIT) pkg $(LINUXKIT_ORG_TARGET) show-tag pkg/xen-tools | cut -d':' -f2)
eve-external-boot-image: pkg/external-boot-image/build.yml
pkg/kube/external-boot-image.tar: pkg/external-boot-image
	$(eval BOOT_IMAGE_TAG := $(shell $(LINUXKIT) pkg $(LINUXKIT_ORG_TARGET) show-tag --canonical pkg/external-boot-image))
	$(eval CACHE_CONTENT := $(shell $(LINUXKIT) cache ls 2>&1))
	$(if $(filter $(BOOT_IMAGE_TAG),$(CACHE_CONTENT)),,$(LINUXKIT) cache pull $(BOOT_IMAGE_TAG))
	$(MAKE) cache-export IMAGE=$(BOOT_IMAGE_TAG) OUTFILE=pkg/kube/external-boot-image.tar
	rm -f pkg/external-boot-image/build.yml
pkg/kube: pkg/kube/external-boot-image.tar eve-kube
	$(QUIET): $@: Succeeded
pkg/%: eve-% FORCE
	$(QUIET): $@: Succeeded

$(RUNME) $(BUILD_YML):
	cp pkg/eve/$(@F) $@

EVE_ARTIFACTS=$(BIOS_IMG) $(EFI_PART) $(CONFIG_IMG) $(PERSIST_IMG) $(INITRD_IMG) $(ROOTFS_IMGS) $(INSTALLER_IMG) $(SBOM) $(BSP_IMX_PART) fullname-rootfs $(BOOT_PART)
eve: $(INSTALLER) $(EVE_ARTIFACTS) current $(RUNME) $(BUILD_YML) | $(BUILD_DIR)
	$(QUIET): "$@: Begin: EVE_REL=$(EVE_REL), HV=$(HV), LINUXKIT_PKG_TARGET=$(LINUXKIT_PKG_TARGET)"
	cp images/out/*.yml $|
	$(PARSE_PKGS) pkg/eve/Dockerfile.in > $|/Dockerfile
	$(LINUXKIT) $(DASH_V) pkg $(LINUXKIT_PKG_TARGET) $(LINUXKIT_ORG_TARGET) --platforms linux/$(ZARCH) --hash-path $(CURDIR) --hash $(ROOTFS_VERSION)-$(HV) --docker $(if $(strip $(EVE_REL)),--release) $(EVE_REL)$(if $(strip $(EVE_REL)),-$(HV)) $(FORCE_BUILD) $|
	$(QUIET)if [ -n "$(EVE_REL)" ] && [ $(HV) = $(HV_DEFAULT) ]; then \
	   $(LINUXKIT) $(DASH_V) pkg $(LINUXKIT_PKG_TARGET) $(LINUXKIT_ORG_TARGET) --platforms linux/$(ZARCH) --hash-path $(CURDIR) --hash $(EVE_REL)-$(if $(TAGPLAT),$(TAGPLAT)-)$(HV) --docker --release $(EVE_REL) $(FORCE_BUILD) $| ;\
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
	$(eval IMAGE_TAG_OPT := $(if $(IMAGE_NAME),--name $(IMAGE_NAME),))
	$(LINUXKIT) $(DASH_V) cache export --format docker --platform linux/$(ZARCH) --outfile $(OUTFILE) $(IMAGE_TAG_OPT) $(IMAGE)

## export an image from linuxkit cache and load it into docker.
cache-export-docker-load: $(LINUXKIT)
	$(eval TARFILE := $(shell mktemp))
	$(MAKE) cache-export OUTFILE=${TARFILE} && cat ${TARFILE} | docker load
	rm -rf ${TARFILE}

%-cache-export-docker-load: $(LINUXKIT)
	$(eval IMAGE_TAG := $(shell $(LINUXKIT) pkg $(LINUXKIT_ORG_TARGET) show-tag --canonical pkg/$*))
	$(eval CACHE_CONTENT := $(shell $(LINUXKIT) cache ls 2>&1))
	$(if $(filter $(IMAGE_TAG),$(CACHE_CONTENT)),$(MAKE) cache-export-docker-load IMAGE=$(IMAGE_TAG),@echo "Missing image $(IMAGE_TAG) in cache")

## export list of images in PKGS_DOCKER_LOAD from linuxkit cache and load them into docker
## will skip image if not found in cache
cache-export-docker-load-all: $(LINUXKIT) $(addsuffix -cache-export-docker-load,$(PKGS_DOCKER_LOAD))

proto-vendor:
	@$(DOCKER_GO) "cd pkg/pillar ; go mod vendor" $(CURDIR) proto

bump-eve-api:
	find . -type f -name "go.mod" -exec grep -q 'github.com/lf-edge/eve-api/go' {} \; -execdir go get -u github.com/lf-edge/eve-api/go \; -execdir go mod tidy \; -execdir go mod vendor \;

bump-eve-libs:
	find . -type f -name "go.mod" -exec grep -q 'github.com/lf-edge/eve-libs' {} \; -execdir go get -u github.com/lf-edge/eve-libs \; -execdir go mod tidy \; -execdir go mod vendor \;

bump-eve-pillar:
	find . -type f -name "go.mod" -exec grep -q 'github.com/lf-edge/eve/pkg/pillar' {} \; -execdir go get -u github.com/lf-edge/eve/pkg/pillar \; -execdir go mod tidy \; -execdir go mod vendor \;

.PHONY: proto-api-%

rc-release:
	./tools/rc-release.sh

lts-release:
	./tools/lts-release.sh

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
# Linuxkit
#
.PHONY: linuxkit
linuxkit: $(LINUXKIT)

LINUXKIT_SOURCE=https://github.com/linuxkit/linuxkit
PARALLEL_BUILD_LOCK:=$(shell mktemp -u $(BUILD_DIR)/eve-parallel-build-XXXXXX)

$(PARALLEL_BUILD_LOCK): $(BUILD_DIR)
	$(QUIET): "$@: Begin: PARALLEL_BUILD_LOCK=$(PARALLEL_BUILD_LOCK)"
	@touch $@
	$(QUIET): $@: Succeeded

# $(PARALLEL_BUILD_LOCK) is unique for each build, so we can use is a flag
# to cleanup possibly old linuxkit-builder containers because this
# target is executed only once per build for both secuential and parallel builds
$(LINUXKIT): $(BUILDTOOLS_BIN)/linuxkit-$(LINUXKIT_VERSION) $(PARALLEL_BUILD_LOCK)
	$(QUIET)docker stop linuxkit-builder >/dev/null 2>&1 || true
	$(QUIET)docker rm linuxkit-builder >/dev/null 2>&1 || true
	$(QUIET)ln -sf  $(notdir $<) $@
	$(QUIET): $@: Succeeded

$(BUILDTOOLS_BIN)/linuxkit-$(LINUXKIT_VERSION):
	$(QUIET) curl -L -o $@ $(LINUXKIT_SOURCE)/releases/download/$(LINUXKIT_VERSION)/linuxkit-$(LOCAL_GOOS)-$(HOSTARCH) && chmod +x $@
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

ifdef LIVE_UPDATE
# Target depends on rootfs tarbar directly, which gives possibility to
# detect when qcow2 should be updated with a tarball and when it should
# be recreated from scratch.
%.qcow2: %.raw $(ROOTFS_TARS) | $(DIST)
#	Detect if the first %.raw ($<) prerequisite is in the "$?" list,
#	which means qcow has to be fully recreated. If not - just update
#	with the existing tar.
	$(eval RECREATE := $(if $(filter $<,$?),1,0))
#	Convert raw to qcow or update rootfs with all files from tar:
#	guestfish one line magic.
	$(QUIET)if [ "$(RECREATE)" = "1" ]; then \
		echo "Recreate $@:"; \
		echo "	qemu-img convert ..."; \
		qemu-img convert -c -f raw -O qcow2 $< $@; \
		echo "	qemu-img resize ..."; \
		qemu-img resize $@ ${MEDIA_SIZE}M; \
	else \
		echo "Update $@ with generated tarball:"; \
		echo "	guestfish ..."; \
		guestfish -a $@ run : mount /dev/sda2 / : tar-in $(ROOTFS_TARS) /; \
	fi
	$(QUIET): $@: Succeeded
else
%.qcow2: %.raw | $(DIST)
	qemu-img convert -c -f raw -O qcow2 $< $@
	qemu-img resize $@ ${MEDIA_SIZE}M
	$(QUIET): $@: Succeeded
endif

.PRECIOUS: %.yml
%.yml: %.yml.in $(RESCAN_DEPS) $(LINUXKIT)
	@echo "Building $@ from $<"
	$(QUIET)$(PARSE_PKGS) $< > $@
	$(QUIET): $@: Succeeded

%/Dockerfile: %/Dockerfile.in $(LINUXKIT) $(RESCAN_DEPS)
	@echo "Building $@ from $<"
	$(QUIET)$(PARSE_PKGS) $< > $@
	$(QUIET): $@: Succeeded

# If DEV=y and file pkg/my_package/build-dev.yml exists, returns the path to that file.
# If RSTATS=y and file pkg/my_package/build-rstats.yml exists, returns the path to that file.
# If HV=kubevirt and DEV=y and file pkg/my_package/build-kubevirt-dev.yml exists, returns the path to that file.
# If HV=kubevirt and DEV!=y and file pkg/my_package/build-kubevirt.yml exists, returns the path to that file.
# If pkg/my_package/build-<PLATFORM>.yml exists, returns the path to that file.
# Otherwise returns pkg/my_package/build.yml.
get_pkg_build_yml = $(if $(filter kubevirt,$(HV)), $(call get_pkg_build_kubevirt_yml,$1), \
                    $(if $(filter y,$(RSTATS)), $(call get_pkg_build_rstats_yml,$1), \
                    $(if $(filter y,$(DEV)), $(call get_pkg_build_dev_yml,$1), \
                    $(if $(wildcard pkg/$1/build-$(PLATFORM).yml),build-$(PLATFORM).yml,build.yml))))
get_pkg_build_dev_yml = $(if $(wildcard pkg/$1/build-dev.yml),build-dev.yml,build.yml)
get_pkg_build_rstats_yml = $(if $(wildcard pkg/$1/build-rstats.yml),build-rstats.yml,build.yml)
get_pkg_build_kubevirt_yml = $(if $(and $(filter y,$(DEV)),$(wildcard pkg/$1/build-kubevirt-dev.yml)),build-kubevirt-dev.yml, \
                             $(if $(wildcard pkg/$1/build-kubevirt.yml),build-kubevirt.yml,build.yml))

eve-%: pkg/%/Dockerfile $(LINUXKIT) $(RESCAN_DEPS)
	$(QUIET): "$@: Begin: LINUXKIT_PKG_TARGET=$(LINUXKIT_PKG_TARGET)"
	$(eval LINUXKIT_DOCKER_LOAD := $(if $(filter $(PKGS_DOCKER_LOAD),$*),--docker,))
	$(eval LINUXKIT_BUILD_PLATFORMS_LIST := $(call uniq,linux/$(ZARCH) $(if $(filter $(PKGS_HOSTARCH),$*),linux/$(HOSTARCH),)))
	$(eval LINUXKIT_BUILD_PLATFORMS := --platforms $(subst $(space),$(comma),$(strip $(LINUXKIT_BUILD_PLATFORMS_LIST))))
	$(eval LINUXKIT_FLAGS := $(if $(filter manifest,$(LINUXKIT_PKG_TARGET)),,$(FORCE_BUILD) $(LINUXKIT_DOCKER_LOAD) $(LINUXKIT_BUILD_PLATFORMS)))
	$(QUIET)$(LINUXKIT) $(DASH_V) pkg $(LINUXKIT_PKG_TARGET) $(LINUXKIT_ORG_TARGET) $(LINUXKIT_OPTS) $(LINUXKIT_FLAGS) --build-yml $(call get_pkg_build_yml,$*) pkg/$*
	$(QUIET)if [ -n "$(PRUNE)" ]; then \
		flock $(PARALLEL_BUILD_LOCK) docker image prune -f; \
	fi
	$(QUIET): "$@: Succeeded (intermediate for pkg/%)"

images/out:
	mkdir -p $@

# Find modifiers for an installer .yml filename
# the $1 contains the target name in following format:
# $(HV)-$(PLATFORM)
# NOTE: PLATFORM may contains dashes, so we read platform from $(PLATFORM) variable
# the rules are following:
# 1. if the file <HV>.yq exists in the images/modifiers/hv directory, it will be added to the list
# of the files we return
# 2. if the file installer.yq exists in the images/modifiers/platform directory, it will be added to the list
# 3. if the file $(PLATFORM).yq exists in the images/modifiers/platform directory, it will be added to the list
define find-modifiers-installer
$(foreach hv,$(firstword $(subst -, ,$1)), \
    $(if $(wildcard images/modifiers/hv/$(hv).yq), \
       	$(info [INFO] Found hv modifier file images/modifiers/hv/$(hv).yq) \
		images/modifiers/hv/$(hv).yq \
	) \
    $(if $(wildcard images/modifiers/platform/$(PLATFORM)/), \
   		$(info [INFO] Found platform directory images/modifiers/platform/$(PLATFORM)) \
        $(if $(wildcard images/modifiers/platform/$(PLATFORM)/installer.yq), \
           	$(info [INFO] Found installer modifier file images/modifiers/platform/$(PLATFORM)/installer.yq) \
			images/modifiers/platform/$(PLATFORM)/installer.yq \
		) \
		$(if $(wildcard images/modifiers/platform/$(PLATFORM)/$(PLATFORM).yq), \
			$(info [INFO] Found platform modifier file images/modifiers/platform/$(PLATFORM)/$(PLATFORM).yq) \
			images/modifiers/platform/$(PLATFORM)/$(PLATFORM).yq \
		) \
    , \
    	$(info [INFO] platform directory images/modifiers/platform/$(PLATFORM)/ doesn't exist)
    ) \
)
endef

# Find modifiers for a rootfs .yml filename
# the $1 contains the target name in following format:
# <HV>-<PLATFORM>-<FLAVOR>
# NOTE: PLATFORM may contains dashes, so we read platform from $(PLATFORM) variable
# the rules are following:
# 1. if the file <HV>.yq exists in the images/modifiers/hv directory, it will be added to the list
# of the files we return
# 2. if the file rootfs-<FLAVOR>.yq exists in the images/modifiers/platform directory, it will be added to the list
# 3. if the file $(PLATFORM).yq exists in the images/modifiers/platform directory, it will be added to the list
define find-modifiers-rootfs
$(eval _hv := $(firstword $(subst -, ,$1))) \
$(eval _rootfs-flavor := $(subst -,,$(subst $(_hv)-$(PLATFORM),,$1))) \
$(info [INFO] HV=$(_hv)) \
$(info [INFO] PLATFORM=$(PLATFORM)) \
$(info [INFO] rootfs flavor=$(_rootfs-flavor)) \
$(if $(wildcard images/modifiers/hv/$(_hv).yq), \
	$(info [INFO] Found hv modifier file images/modifiers/hv/$(_hv).yq) \
	images/modifiers/hv/$(_hv).yq \
) \
$(if $(wildcard images/modifiers/platform/$(PLATFORM)/), \
	$(info [INFO] Found platform directory images/modifiers/platform/$(PLATFORM)) \
	$(if $(wildcard images/modifiers/platform/$(PLATFORM)/rootfs-$(_rootfs-flavor).yq), \
		$(info [INFO] Found rootfs flavor modifier file images/modifiers/platform/$(PLATFORM)/rootfs-$(_rootfs-flavor).yq) \
		images/modifiers/platform/$(PLATFORM)/rootfs-$(_rootfs-flavor).yq \
	) \
	$(if $(wildcard images/modifiers/platform/$(PLATFORM)/$(PLATFORM).yq), \
		$(info [INFO] Found platform modifier file images/modifiers/platform/$(PLATFORM)/$(PLATFORM).yq) \
		images/modifiers/platform/$(PLATFORM)/$(PLATFORM).yq \
	) \
	, \
	$(info [INFO] platform directory images/modifiers/platform/$(PLATFORM)/ doesn't exist)
)
endef

.PRECIOUS: images/out/rootfs-%.yml.in
images/out/rootfs-%.yml.in: images/rootfs.yml.in $(RESCAN_DEPS) | images/out
	$(info [INFO] Building rootfs for target: $*)
	$(info [INFO] Building $@ from $<)
	$(QUIET)tools/compose-image-yml.sh -b $< -v "$(ROOTFS_VERSION)-$*-$(ZARCH)" -o $@ -h $(HV) -p $(PLATFORM) $(call find-modifiers-rootfs,$*)

.PRECIOUS: images/out/installer-%.yml.in
images/out/installer-%.yml.in: images/installer.yml.in $(RESCAN_DEPS) | images/out
	$(info [INFO] Building installer for target: $*)
	$(info [INFO] Building $@ from $<)
	$(QUIET)tools/compose-image-yml.sh -b $< -v "$(ROOTFS_VERSION)-$*-$(ZARCH)" -o $@ -h $(HV) -p $(PLATFORM) $(call find-modifiers-installer,$*)

pkg-deps.mk: $(GET_DEPS)
	$(QUIET)$(GET_DEPS) $(ROOTFS_GET_DEPS) -m $@

$(ROOTFS_FULL_NAME)-kvm-adam-$(ZARCH).$(ROOTFS_FORMAT): fullname-rootfs $(SSH_KEY)
fullname-rootfs: $(ROOTFS_FULL_NAME)-$(HV)-$(ZARCH).$(ROOTFS_FORMAT) current
$(ROOTFS_FULL_NAME)-%-$(ZARCH).$(ROOTFS_FORMAT): $(ROOTFS_IMG)
	@rm -f $@ && ln -s $(notdir $<) $@
	$(QUIET): $@: Succeeded

%-show-tag:
	@$(LINUXKIT) pkg $(LINUXKIT_ORG_TARGET) show-tag --canonical pkg/$*

%Gopkg.lock: %Gopkg.toml | $(GOBUILDER)
	@$(DOCKER_GO) "dep ensure -update $(GODEP_NAME)" $(dir $@)
	@echo Done updating $@

docker-old-images:
	./tools/oldimages.sh

docker-image-clean:
	docker rmi -f $(shell ./tools/oldimages.sh)

kernel-tag:
	@echo $(KERNEL_TAG)

.PRECIOUS: rootfs-% $(ROOTFS)-%.img $(ROOTFS_COMPLETE)
.PHONY: all clean test run pkgs help live rootfs config installer live current FORCE $(DIST) HOSTARCH image-set cache-export
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
	@echo "   build-vm                         prepare a build VM for EVE in qcow2 format"
	@echo "   test                             run EVE tests"
	@echo "   test-profiling                   run pillar tests with memory profiler"
	@echo "   clean                            clean build artifacts in a current directory (doesn't clean Docker)"
	@echo "   release                          prepare branch for a release (VERSION=x.y.z required)"
	@echo "   rc-release                       make a rc release on a current branch (must be a release branch)"
	@echo "                                    If the latest lts tag is 14.4.0 then running make rc-release will"
	@echo "                                    create 14.4.0-rc1 tag and if the latest tag is 14.4.1-lts then"
	@echo "   lts-release                      make a lts release on a current branch (must be a release branch)"
	@echo "                                    If the latest lts tag is 14.4.0-lts then running make lts-release"
	@echo "                                    will create a new lts release 14.4.1-lts"
	@echo "   proto                            generates Go and Python source from protobuf API definitions"
	@echo "   proto-vendor                     update vendored API in packages that require it (e.g. pkg/pillar)"
	@echo "   shell                            drop into docker container setup for Go development"
	@echo "   yetus                            run Apache Yetus to check the quality of the source tree"
	@echo "   mini-yetus                       run Apache Yetus to check the quality of the source tree"
	@echo "                                    only on the files that have changed in the source branch"
	@echo "                                    compared to the destination branch, by default master is"
	@echo "                                    the source and current branch the destination, but this"
	@echo "                                    can be changed by setting the MYETUS_SBRANCH and"
	@echo "                                    MYETUS_DBRANCH, in addition if MYETUS_VERBOSE is set to"
	@echo "                                    Y, the output will be echoed to the console"
	@echo "   check-docker-hashes-consistency  check for Dockerfile image inconsistencies"
	@echo "   kernel-tag                       show current KERNEL_TAG"
	@echo
	@echo "Seldom used maintenance and development targets:"
	@echo "   bump-eve-api    bump eve-api in all subprojects"
	@echo "   bump-eve-libs   bump eve-libs in all subprojects"
	@echo "   bump-eve-pillar bump eve/pkg/pillar in all subprojects"
	@echo
	@echo "Commonly used build targets:"
	@echo "   config               builds a bundle with initial EVE configs"
	@echo "   pkgs                 builds all EVE packages"
	@echo "   pkg/XXX              builds XXX EVE package"
	@echo "   rootfs               builds default EVE rootfs image (upload it to the cloud as BaseImage)"
	@echo "   live                 builds a full disk image of EVE which can be function as a virtual device"
	@echo "   LIVE_UPDATE=1 live   updates existing qcow2 disk image of EVE with RW rootfs (ext4) by only"
	@echo "                        copying generated rootfs tarball. This significantly reduced overall build"
	@echo "                        time of the disk image. Used by developers only!"
	@echo "   live-XXX             builds a particular kind of EVE live image (raw, qcow2, gcp, vdi, parallels)"
	@echo "   installer-raw        builds raw disk installer image (to be installed on bootable media)"
	@echo "   installer-iso        builds an ISO installers image (to be installed on bootable media)"
	@echo "   installer-net        builds a tarball of artifacts to be used for PXE booting"
	@echo
	@echo "Commonly used run targets (note they don't automatically rebuild images they run):"
	@echo "   run-compose          runs all EVE microservices via docker-compose deployment"
	@echo "   run-build-vm         runs a build VM image"
	@echo "   run-live             runs a full fledged virtual device on qemu (as close as it gets to actual h/w)"
	@echo "   run-live-gui         same as run-live but with an emulated graphics card"
	@echo "   run-live-parallels   runs a full fledged virtual device on Parallels Desktop"
	@echo "   run-live-vb          runs a full fledged virtual device on VirtualBox"
	@echo "   run-rootfs           runs a rootfs.img (limited usefulness e.g. quick test before cloud upload)"
	@echo "   run-grub             runs our copy of GRUB bootloader and nothing else (very limited usefulness)"
	@echo "   run-installer-iso    runs installer.iso (via qemu) and 'installs' EVE into (initially blank) target.img"
	@echo "   run-installer-raw    runs installer.raw (via qemu) and 'installs' EVE into (initially blank) target.img"
	@echo "   run-installer-net    runs installer.net (via qemu/iPXE) and 'installs' EVE into (initially blank) target.img"
	@echo "   run-target           runs a full fledged virtual device on qemu from target.img (similar to run-live)"
	@echo
	@echo "make run is currently an alias for make run-live"
	@echo
