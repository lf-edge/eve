PATH := $(CURDIR)/build-tools/bin:$(PATH)

# How large to we want the disk to be in Mb
MEDIA_SIZE=610

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

run-fallback run:
	qemu-system-x86_64 --bios ./bios/OVMF.fd -m 4096 -cpu SandyBridge -smp 4 -serial mon:stdio -hda fallback.img \
				-net nic,vlan=0 -net user,id=eth0,vlan=0,net=192.168.1.0/24,dhcpstart=192.168.1.10,hostfwd=tcp::2222-:22 \
				-net nic,vlan=1 -net user,id=eth1,vlan=1,net=192.168.2.0/24,dhcpstart=192.168.2.10

images/%.yml: pkgs parse-pkgs.sh images/%.yml.in FORCE
	./parse-pkgs.sh $@.in > $@

rootfs.img: images/fallback.yml
	./makerootfs.sh images/fallback.yml squash rootfs.img

fallback.img: rootfs.img
	./maketestconfig.sh config.img
	tar c rootfs.img config.img | ./makeflash.sh -C ${MEDIA_SIZE} $@

.PHONY: FORCE
FORCE:
