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
	make -C build-pkgs

pkgs: build-tools build-pkgs
	make -C pkg

bios/OVMF.fd:
	mkdir bios || :
	[ -f bios/flash1.img ] || dd if=/dev/zero of=bios/flash1.img bs=1048576 count=64
	C=`docker create $(shell make -s -C build-pkgs BUILD-PKGS=uefi show-tag)-$(DOCKER_ARCH_TAG) fake` ;\
	   docker export $$C | tar -C bios -xf - OVMF* ; docker rm $$C

# run-installer
#
# This creates an image equivalent to fallback.img (called target.img)
# through the installer. It's the long road to fallback.img. Good for
# testing.
#
run-installer:
	dd if=/dev/zero of=target.img count=750000 bs=1024
	qemu-system-$(ZARCH) $(QEMU_OPTS) -hda target.img -cdrom installer.iso -boot d

run-fallback run: bios/OVMF.fd
	qemu-system-$(ZARCH) $(QEMU_OPTS) -hda fallback.img

images/%.yml: pkgs parse-pkgs.sh images/%.yml.in FORCE
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
	make -C pkg PKGS=installer LINUXKIT_OPTS="--disable-content-trust --disable-cache" forcebuild

#
# INSTALLER IMAGE CREATION:
#
# Use makeiso instead of linuxkit own's format because the
# former are able to boot on our platforms.

installer.iso: images/installer.yml pkg_installer
	./makeiso.sh images/installer.yml installer.iso	

.PHONY: FORCE
FORCE:
