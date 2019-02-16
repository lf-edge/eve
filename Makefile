PATH := $(CURDIR)/build-tools/bin:$(PATH)

# How large to we want the disk to be in Mb
MEDIA_SIZE=8192
IMG_FORMAT=qcow2
ROOTFS_FORMAT=squash

SSH_PORT := 2222

CONF_DIR=conf

ZARCH=$(shell uname -m)
DOCKER_ARCH_TAG_aarch64=arm64
DOCKER_ARCH_TAG_x86_64=amd64
DOCKER_ARCH_TAG=$(DOCKER_ARCH_TAG_$(ZARCH))

FALLBACK_IMG_aarch64=fallback_aarch64
FALLBACK_IMG_x86_64=fallback
FALLBACK_IMG=$(FALLBACK_IMG_$(ZARCH))

ROOTFS_IMG_aarch64=rootfs_aarch64.img
ROOTFS_IMG_x86_64=rootfs.img
ROOTFS_IMG=$(ROOTFS_IMG_$(ZARCH))

TARGET_IMG_aarch64=target_aarch64.img
TARGET_IMG_x86_64=target.img
TARGET_IMG=$(TARGET_IMG_$(ZARCH))

INSTALLER_IMG_aarch64=installer_aarch64
INSTALLER_IMG_x86_64=installer
INSTALLER_IMG=$(INSTALLER_IMG_$(ZARCH))

QEMU_OPTS_aarch64= -machine virt,gic_version=3 -machine virtualization=true -cpu cortex-a57 -machine type=virt
# -drive file=./bios/flash0.img,format=raw,if=pflash -drive file=./bios/flash1.img,format=raw,if=pflash
# [ -f bios/flash1.img ] || dd if=/dev/zero of=bios/flash1.img bs=1048576 count=64
QEMU_OPTS_x86_64= -cpu SandyBridge
QEMU_OPTS_COMMON= -m 4096 -smp 4 -display none -serial mon:stdio -bios ./bios/OVMF.fd \
        -rtc base=utc,clock=rt \
        -nic user,id=eth0,net=192.168.1.0/24,dhcpstart=192.168.1.10,hostfwd=tcp::$(SSH_PORT)-:22 \
        -nic user,id=eth1,net=192.168.2.0/24,dhcpstart=192.168.2.10
QEMU_OPTS=$(QEMU_OPTS_COMMON) $(QEMU_OPTS_$(ZARCH))

DOCKER_UNPACK= _() { C=`docker create $$1 fake` ; docker export $$C | tar -xf - $$2 ; docker rm $$C ; } ; _

PARSE_PKGS:=ZENIX_HASH=$(ZENIX_HASH) DOCKER_ARCH_TAG=$(DOCKER_ARCH_TAG) ./parse-pkgs.sh
LK_HASH_REL=LINUXKIT_HASH="$(if $(strip $(ZENIX_HASH)),--hash) $(ZENIX_HASH) $(if $(strip $(ZENIX_REL)),--release) $(ZENIX_REL)"

DEFAULT_PKG_TARGET=build

.PHONY: run pkgs build-pkgs help build-tools

all: help

build-tools:
	${MAKE} -C build-tools all

build-pkgs: build-tools
	make -C build-pkgs $(LK_HASH_REL) $(DEFAULT_PKG_TARGET)

pkgs: build-tools build-pkgs
	make -C pkg $(LK_HASH_REL) $(DEFAULT_PKG_TARGET)

bios:
	mkdir bios

bios/EFI: bios
	cd bios ; $(DOCKER_UNPACK) $(shell make -s -C pkg PKGS=grub show-tag)-$(DOCKER_ARCH_TAG) EFI
	(echo "set root=(hd0)" ; echo "chainloader /EFI/BOOT/BOOTX64.EFI" ; echo boot) > bios/EFI/BOOT/grub.cfg

bios/OVMF.fd: bios
	cd bios ; $(DOCKER_UNPACK) $(shell make -s -C build-pkgs BUILD-PKGS=uefi show-tag)-$(DOCKER_ARCH_TAG) OVMF.fd

# run-installer
#
# This creates an image equivalent to fallback.img (called target.img)
# through the installer. It's the long road to fallback.img. Good for
# testing.
#
# -machine dumpdtb=virt.dtb 
#
run-installer-iso: bios/OVMF.fd
	qemu-img create -f ${IMG_FORMAT} $(TARGET_IMG) ${MEDIA_SIZE}M
	qemu-system-$(ZARCH) $(QEMU_OPTS) -drive file=$(TARGET_IMG),format=$(IMG_FORMAT) -cdrom $(INSTALLER_IMG).iso -boot d

run-installer-raw: bios/OVMF.fd
	qemu-img create -f ${IMG_FORMAT} $(TARGET_IMG) ${MEDIA_SIZE}M
	qemu-system-$(ZARCH) $(QEMU_OPTS) -drive file=$(TARGET_IMG),format=$(IMG_FORMAT) -drive file=$(INSTALLER_IMG).raw,format=raw

run-fallback run: bios/OVMF.fd
	qemu-system-$(ZARCH) $(QEMU_OPTS) -drive file=$(FALLBACK_IMG).img,format=$(IMG_FORMAT)

run-target: bios/OVMF.fd
	qemu-system-$(ZARCH) $(QEMU_OPTS) -drive file=$(TARGET_IMG),format=$(IMG_FORMAT)

run-rootfs: bios/OVMF.fd bios/EFI
	qemu-system-$(ZARCH) $(QEMU_OPTS) -drive file=$(ROOTFS_IMG),format=raw -drive file=fat:rw:./bios/,format=raw 

run-grub: bios/OVMF.fd bios/EFI
	qemu-system-$(ZARCH) $(QEMU_OPTS) -drive file=fat:rw:./bios/,format=raw

# NOTE: that we have to depend on pkg/zedctr here to make sure
# it gets triggered when we build any kind of image target
images/%.yml: build-tools pkg/zedctr parse-pkgs.sh images/%.yml.in FORCE
	$(PARSE_PKGS) $@.in > $@
	@# the following is a horrible hack that needs to go away ASAP \
	if [ "$(ZARCH)" = aarch64 ] ; then \
           sed -e '/source:/s#rootfs.img#rootfs_aarch64.img#' -i.orig $@ ;\
	   [ $$(uname -m) = aarch64 ] || echo "WARNING: We are assembling a $(ZARCH) image on `uname -m`. Things may break." ;\
        fi

config.img: conf/server conf/onboard.cert.pem conf/wpa_supplicant.conf conf/
	./maketestconfig.sh $(CONF_DIR) config.img

$(ROOTFS_IMG): images/rootfs.yml
	./makerootfs.sh $< $(ROOTFS_FORMAT) $@
	@[ $$(wc -c < "$@") -gt $$(( 250 * 1024 * 1024 )) ] && \
          echo "ERROR: size of $@ is greater than 250MB (bigger than allocated partition)" && exit 1 || :

$(FALLBACK_IMG).img: $(FALLBACK_IMG).$(IMG_FORMAT)
	@rm -f $@ >/dev/null 2>&1 || :
	ln -s $< $@

$(FALLBACK_IMG).qcow2: $(FALLBACK_IMG).raw
	qemu-img convert -c -f raw -O qcow2 $< $@
	rm $<

$(FALLBACK_IMG).raw: $(ROOTFS_IMG) config.img
	tar c $^ | ./makeflash.sh -C ${MEDIA_SIZE} $@

$(ROOTFS_IMG)_installer.img: images/installer.yml $(ROOTFS_IMG) config.img
	./makerootfs.sh $< $(ROOTFS_FORMAT) $@
	@[ $$(wc -c < "$@") -gt $$(( 300 * 1024 * 1024 )) ] && \
          echo "ERROR: size of $@ is greater than 300MB (bigger than allocated partition)" && exit 1 || :

$(INSTALLER_IMG).raw: $(ROOTFS_IMG)_installer.img config.img
	tar c $^ | ./makeflash.sh -C 350 $@ "efi imga conf_win"
	rm $(ROOTFS_IMG)_installer.img

$(INSTALLER_IMG).iso: images/installer.yml $(ROOTFS_IMG) config.img
	./makeiso.sh $< $@

zenix: ZENIX_HASH:=$(shell echo ZENIX_TAG | $(PARSE_PKGS) | sed -e 's#^.*:##' -e 's#-.*$$##')
zenix: Makefile bios/OVMF.fd config.img $(INSTALLER_IMG).iso $(INSTALLER_IMG).raw $(ROOTFS_IMG) $(FALLBACK_IMG).img images/rootfs.yml images/installer.yml
	cp $^ build-pkgs/zenix
	make -C build-pkgs BUILD-PKGS=zenix $(LK_HASH_REL) $(DEFAULT_PKG_TARGET)

# FIXME: the following is an ugly workaround against linuxkit complaining:
# FATA[0030] Failed to create OCI spec for zededa/zedctr:XXX: 
#    Error response from daemon: pull access denied for zededa/zedctr, repository does not exist or may require ‘docker login’
# The underlying problem is that running pkg target doesn't guarantee that
# the zededa/zedctr:XXX container will end up in a local docker cache (if linuxkit 
# doesn't rebuild the package) and we need it there for the linuxkit build to work.
# Which means, that we have to either forcefully rebuild it or fetch from docker hub.
pkg/zedctr: ZENIX_HASH:=$(shell echo ZEDEDA_TAG | $(PARSE_PKGS) | sed -e 's#^.*:##' -e 's#-.*$$##')
pkg/zedctr: ZEDCTR_TAG:=zededa/zedctr:$(ZENIX_HASH)-$(DOCKER_ARCH_TAG)
pkg/zedctr: FORCE
	docker pull $(ZEDCTR_TAG) >/dev/null 2>&1 || : ;\
	if ! docker inspect $(ZEDCTR_TAG) >/dev/null 2>&1 ; then \
	  if [ $(ZARCH) != $$(uname -m) ] ; then \
	    $(PARSE_PKGS) < pkg/zedctr/Dockerfile.cross.in > pkg/zedctr/Dockerfile ;\
	    PKG_HASH=`mktemp -u XXXXXXXXXX` ;\
	    make -C pkg PKGS=zedctr RESCAN_DEPS="" LINUXKIT_OPTS="--disable-content-trust --force --disable-cache --hash $$PKG_HASH" $(DEFAULT_PKG_TARGET) ;\
	    PKG_HASH=zededa/zedctr:$$PKG_HASH ;\
	    docker tag $$PKG_HASH $(ZEDCTR_TAG) ;\
	    docker rmi $$PKG_HASH $$PKG_HASH-$(DOCKER_ARCH_TAG_$(shell uname -m)) ;\
	  else \
	    make -C pkg PKGS=zedctr LINUXKIT_OPTS="--disable-content-trust --force --disable-cache --hash $(ZENIX_HASH)" $(DEFAULT_PKG_TARGET) ;\
	  fi ;\
	fi

pkg/%: FORCE
	make -C pkg PKGS=$(notdir $@) LINUXKIT_OPTS="--disable-content-trust --disable-cache --force" $(LK_HASH_REL) $(DEFAULT_PKG_TARGET)

.PHONY: FORCE
FORCE:

help:
	@echo "zenbuild: Linuxkit based IoT Edge Operating System (Zenix)"
	@echo
	@echo "This Makefile automates commons tasks of building and running"
	@echo "  * Zenix"
	@echo "  * Installer of Zenix OS"
	@echo "  * linuxkit command line tools"
	@echo "We currently support two platforms: x86_64 and aarch64. There is"
	@echo "even rudimentary support for cross-compiling that can be triggered"
	@echo "by forcing a particular architecture via adding ZARCH=[x86_64|aarch64]"
	@echo "to the make's command line. You can also run in a cross- way since"
	@echo "all the execution is done via qemu."
	@echo
	@echo "Commonly used build targets:"
	@echo "   build-tools    builds linuxkit and manifest-tool utilities under build-tools/bin"
	@echo "   build-pkgs     builds all built-time linuxkit packages"
	@echo "   config.img     builds a bundle with initial Zenix configs"
	@echo "   pkgs           builds all Zenix packages"
	@echo "   pkg/XXX        builds XXX Zenix package"
	@echo "   rootfs.img     builds Zenix rootfs image (upload it to the cloud as BaseImage)"
	@echo "   fallback.img   builds a full disk image of Zenix which can be function as a virtual device"
	@echo "   installer.raw  builds raw disk installer image (to be installed on bootable media)"
	@echo "   installer.iso  builds an ISO installers image (to be installed on bootable media)"
	@echo
	@echo "Commonly used run targets (note they don't automatically rebuild images they run):"
	@echo "   run-grub          runs our copy of GRUB bootloader and nothing else (very limited usefulness)"
	@echo "   run-rootfs        runs a rootfs.img (limited usefulness e.g. quick test before cloud upload)"
	@echo "   run-installer-iso runs installer.iso on qemu and 'installs' Zenix on fallback.img" 
	@echo "   run-installer-raw runs installer.raw on qemu and 'installs' Zenix on fallback.img"
	@echo "   run-fallback      runs a full fledged virtual device on qemu (as close as it gets to actual h/w)"
	@echo
	@echo "make run is currently an alias for make run-fallback"
	@echo
