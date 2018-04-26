PATH := $(CURDIR)/build-tools/bin:$(PATH)

# How large to we want the disk to be in Mb
MEDIA_SIZE=700

ZARCH=$(shell uname -m)
DOCKER_ARCH_TAG_aarch64=arm64
DOCKER_ARCH_TAG_x86_64=amd64
DOCKER_ARCH_TAG=$(DOCKER_ARCH_TAG_$(ZARCH))
QEMU_OPTS_aarch64=-machine virt,gic_version=3 -machine virtualization=true -cpu cortex-a57 -machine type=virt \
                  -drive file=./bios/OVMF.fd,format=raw,if=pflash -drive file=./bios/flash1.img,format=raw,if=pflash
QEMU_OPTS_x86_64=--bios ./bios/OVMF.fd -cpu SandyBridge
QEMU_OPTS_COMMON= -m 4096 -smp 4 -display none -serial mon:stdio \
	-net nic,vlan=0 -net user,id=eth0,vlan=0,net=192.168.1.0/24,dhcpstart=192.168.1.10,hostfwd=tcp::2222-:22 \
	-net nic,vlan=1 -net user,id=eth1,vlan=1,net=192.168.2.0/24,dhcpstart=192.168.2.10
QEMU_OPTS=$(QEMU_OPTS_COMMON) $(QEMU_OPTS_$(ZARCH))

DOCKER_UNPACK= _() { C=`docker create $$1 fake` ; docker export $$C | tar -xf - $$2 ; docker rm $$C ; } ; _

DEFAULT_PKG_TARGET=build

.PHONY: run pkgs build-pkgs help build-tools

all: help

help:
	@echo zenbuild: LinuxKit-based Xen images composer
	@echo
	@echo amd64 targets:
	@echo "   'make fallback.img'   builds an image with the fallback"
	@echo "                         bootloader"
	@echo "   'make run'            run fallback.img image using qemu'"
	@echo

build-tools:
	${MAKE} -C build-tools all

build-pkgs: build-tools
	make -C build-pkgs $(DEFAULT_PKG_TARGET)

# FIXME: the following is an ugly workaround against linuxkit complaining:
# FATA[0030] Failed to create OCI spec for zededa/zedctr:XXX: 
#    Error response from daemon: pull access denied for zededa/zedctr, repository does not exist or may require ‘docker login’
# But wait! There's more! Since zedctr depends on ztools container (go-provision)
# we have to make sure that when it is specified by the user explicitly via ZTOOLS_TAG env var we:
#   1. don't attempt a docker pull
#   2. touch a file in the zedctr package (thus making it dirty and changing a reference in image.yml) 
# Finally, we only forcefully rebuild the zedctr IF either docker pull brught a new image or ZTOOLS_TAG was given 
zedctr-workaround:
	@if [ -z "$$ZTOOLS_TAG" ]; then \
	  docker pull `bash -c "./parse-pkgs.sh <(echo ZTOOLS_TAG)"` | tee /dev/tty | grep -q 'Downloaded newer image' ;\
	else \
	  date +%s > pkg/zedctr/trigger ;\
        fi ; if [ $$? -eq 0 ]; then make -C pkg PKGS=zedctr LINUXKIT_OPTS="--disable-content-trust --force --disable-cache" $(DEFAULT_PKG_TARGET) ; fi

pkgs: build-tools build-pkgs zedctr-workaround
	make -C pkg $(DEFAULT_PKG_TARGET)

bios:
	mkdir bios

bios/OVMF.fd: bios
	cd bios ; $(DOCKER_UNPACK) $(shell make -s -C build-pkgs BUILD-PKGS=uefi show-tag)-$(DOCKER_ARCH_TAG) OVMF.fd

# run-installer
#
# This creates an image equivalent to fallback.img (called target.img)
# through the installer. It's the long road to fallback.img. Good for
# testing.
#
run-installer:
	dd if=/dev/zero of=target.img seek=${MEDIA_SIZE} count=1 bs=1M
	qemu-system-$(ZARCH) $(QEMU_OPTS) -hda target.img -cdrom installer.iso -boot d

run-fallback run: bios/OVMF.fd
	qemu-system-$(ZARCH) $(QEMU_OPTS) -hda fallback.img

# NOTE: that we have to depend on zedctr-workaround here to make sure
# it gets triggered when we build any kind of image target
images/%.yml: zedctr-workaround parse-pkgs.sh images/%.yml.in FORCE
	./parse-pkgs.sh $@.in > $@

rootfs.img: images/fallback.yml
	./makerootfs.sh images/fallback.yml squash rootfs.img

config.img:
	./maketestconfig.sh config.img

fallback.img: rootfs.img config.img
	tar c rootfs.img config.img | ./makeflash.sh -C ${MEDIA_SIZE} $@

.PHONY: pkg_installer
pkg_installer: rootfs.img config.img
	cp rootfs.img config.img pkg/installer
	make -C pkg PKGS=installer LINUXKIT_OPTS="--disable-content-trust --disable-cache --force" $(DEFAULT_PKG_TARGET)

#
# INSTALLER IMAGE CREATION:
#
# Use makeiso instead of linuxkit own's format because the
# former are able to boot on our platforms.

installer.iso: images/installer.yml pkg_installer
	./makeiso.sh images/installer.yml installer.iso	

installer.img: images/installer.yml pkg_installer
	./makeraw.sh images/installer.yml installer.iso

publish: Makefile rootfs.img config.img fallback.img installer.iso bios/OVMF.fd
	cp $^ build-pkgs/zenix
	make -C build-pkgs BUILD-PKGS=zenix LINUXKIT_OPTS="--disable-content-trust --disable-cache --force" $(DEFAULT_PKG_TARGET)

.PHONY: FORCE
FORCE:
