PATH := $(CURDIR)/build-tools/bin:$(PATH)

# How large to we want the disk to be in Mb
MEDIA_SIZE=700

QEMU_OPTS= --bios ./bios/OVMF.fd -m 4096 -cpu SandyBridge -smp 4 -serial mon:stdio \
	-net nic,vlan=0 -net user,id=eth0,vlan=0,net=192.168.1.0/24,dhcpstart=192.168.1.10,hostfwd=tcp::2222-:22 \
	-net nic,vlan=1 -net user,id=eth1,vlan=1,net=192.168.2.0/24,dhcpstart=192.168.2.10

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

# run-installer
#
# This creates an image equivalent to fallback.img (called target.img)
# through the installer. It's the long road to fallback.img. Good for
# testing.
#
run-installer:
	dd if=/dev/zero of=target.img count=750000 bs=1024
	qemu-system-x86_64 $(QEMU_OPTS) -hda target.img -cdrom installer.iso -boot d

run-fallback run:
	qemu-system-x86_64 $(QEMU_OPTS) -hda fallback.img


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
	./parse-pkgs.sh pkg/installer/Dockerfile.in > pkg/installer/Dockerfile
	cp rootfs.img config.img pkg/installer
	linuxkit pkg build --disable-content-trust pkg/installer

#
# INSTALLER IMAGE CREATION:
#
# Use makeiso instead of linuxkit own's format because the
# former are able to boot on our platforms.

installer.iso: images/installer.yml pkg_installer
	./makeiso.sh images/installer.yml installer.iso	

.PHONY: FORCE
FORCE:
