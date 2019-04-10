PATH := $(CURDIR)/build-tools/bin:$(PATH)

# How large to we want the disk to be in Mb
MEDIA_SIZE=8192
IMG_FORMAT=qcow2
ROOTFS_FORMAT=squash

SSH_PORT := 2222

CONF_DIR=conf

HOSTARCH:=$(shell uname -m)
# by default, take the host architecture as the target architecture, but can override with `make ZARCH=foo`
#    assuming that the toolchain supports it, of course...
ZARCH ?= $(HOSTARCH)
# warn if we are cross-compiling and track it
CROSS ?=
ifneq ($(HOSTARCH),$(ZARCH))
CROSS = 1
$(warning "WARNING: We are assembling a $(ZARCH) image on $(HOSTARCH). Things may break.")
endif
# qemu-system-<arch> uses the local versions, so save the name early on
QEMU_SYSTEM:=qemu-system-$(ZARCH)
# canonicalized names for architecture
ifeq ($(ZARCH),aarch64)
        ZARCH=arm64
endif
ifeq ($(ZARCH),x86_64)
        ZARCH=amd64
endif

# where we store outputs
DIST=dist/$(ZARCH)

DOCKER_ARCH_TAG=$(ZARCH)

FALLBACK_IMG=$(DIST)/fallback
ROOTFS_IMG=$(DIST)/rootfs.img
TARGET_IMG=$(DIST)/target.img
INSTALLER_IMG=$(DIST)/installer
CONFIG_IMG=$(DIST)/config.img

BIOS_IMG=$(DIST)/bios/OVMF.fd
EFI_PART=$(DIST)/bios/EFI

QEMU_OPTS_arm64= -machine virt,gic_version=3 -machine virtualization=true -cpu cortex-a57 -machine type=virt
# -drive file=./bios/flash0.img,format=raw,if=pflash -drive file=./bios/flash1.img,format=raw,if=pflash
# [ -f bios/flash1.img ] || dd if=/dev/zero of=bios/flash1.img bs=1048576 count=64
QEMU_OPTS_amd64= -cpu SandyBridge
QEMU_OPTS_COMMON= -smbios type=1,serial=31415926 -m 4096 -smp 4 -display none -serial mon:stdio -bios $(BIOS_IMG) \
        -rtc base=utc,clock=rt \
        -nic user,id=eth0,net=192.168.1.0/24,dhcpstart=192.168.1.10,hostfwd=tcp::$(SSH_PORT)-:22 \
        -nic user,id=eth1,net=192.168.2.0/24,dhcpstart=192.168.2.10
QEMU_OPTS=$(QEMU_OPTS_COMMON) $(QEMU_OPTS_$(ZARCH))

DOCKER_UNPACK= _() { C=`docker create $$1 fake` ; docker export $$C | tar -xf - $$2 ; docker rm $$C ; } ; _

PARSE_PKGS:=$(if $(strip $(ZENIX_HASH)),ZENIX_HASH=)$(ZENIX_HASH) DOCKER_ARCH_TAG=$(DOCKER_ARCH_TAG) ./tools/parse-pkgs.sh
LK_HASH_REL=LINUXKIT_HASH="$(if $(strip $(ZENIX_HASH)),--hash) $(ZENIX_HASH) $(if $(strip $(ZENIX_REL)),--release) $(ZENIX_REL)"

DEFAULT_PKG_TARGET=build

.PHONY: run pkgs build-pkgs help build-tools fallback rootfs config installer live

all: help

build-tools:
	${MAKE} -C build-tools all

build-pkgs: build-tools
	make -C build-pkgs $(LK_HASH_REL) $(DEFAULT_PKG_TARGET)

pkgs: build-tools build-pkgs
	make -C pkg $(LK_HASH_REL) $(DEFAULT_PKG_TARGET)

$(EFI_PART): | $(DIST)/bios
	cd $| ; $(DOCKER_UNPACK) $(shell make -s -C pkg PKGS=grub show-tag)-$(DOCKER_ARCH_TAG) EFI
	(echo "set root=(hd0)" ; echo "chainloader /EFI/BOOT/BOOTX64.EFI" ; echo boot) > $@/BOOT/grub.cfg

$(BIOS_IMG): | $(DIST)/bios
	cd $| ; $(DOCKER_UNPACK) $(shell make -s -C build-pkgs BUILD-PKGS=uefi show-tag)-$(DOCKER_ARCH_TAG) OVMF.fd

# run-installer
#
# This creates an image equivalent to fallback.img (called target.img)
# through the installer. It's the long road to fallback.img. Good for
# testing.
#
# -machine dumpdtb=virt.dtb 
#
run-installer-iso: $(BIOS_IMG)
	qemu-img create -f ${IMG_FORMAT} $(TARGET_IMG) ${MEDIA_SIZE}M
	$(QEMU_SYSTEM) $(QEMU_OPTS) -drive file=$(TARGET_IMG),format=$(IMG_FORMAT) -cdrom $(INSTALLER_IMG).iso -boot d

run-installer-raw: $(BIOS_IMG)
	qemu-img create -f ${IMG_FORMAT} $(TARGET_IMG) ${MEDIA_SIZE}M
	$(QEMU_SYSTEM) $(QEMU_OPTS) -drive file=$(TARGET_IMG),format=$(IMG_FORMAT) -drive file=$(INSTALLER_IMG).raw,format=raw

run-fallback run: $(BIOS_IMG)
	$(QEMU_SYSTEM) $(QEMU_OPTS) -drive file=$(FALLBACK_IMG).img,format=$(IMG_FORMAT)

run-target: $(BIOS_IMG)
	$(QEMU_SYSTEM) $(QEMU_OPTS) -drive file=$(TARGET_IMG),format=$(IMG_FORMAT)

run-rootfs: $(BIOS_IMG) $(EFI_PART)
	$(QEMU_SYSTEM) $(QEMU_OPTS) -drive file=$(ROOTFS_IMG),format=raw -drive file=fat:rw:$(EFI_PART)/..,format=raw 

run-grub: $(BIOS_IMG) $(EFI_PART)
	$(QEMU_SYSTEM) $(QEMU_OPTS) -drive file=fat:rw:$(EFI_PART)/..,format=raw

# ensure the dist directory exists
$(DIST) $(DIST)/bios:
	mkdir -p $@

# convenience targets - so you can do `make config` instead of `make dist/config.img`, and `make installer` instead of `make dist/amd64/installer.img
config: $(CONFIG_IMG)
rootfs: $(ROOTFS_IMG)
fallback: $(FALLBACK_IMG).img
live: fallback
installer: $(INSTALLER_IMG).raw
installer-iso: $(INSTALLER_IMG).iso

# NOTE: that we have to depend on pkg/zedctr here to make sure
# it gets triggered when we build any kind of image target
images/%.yml: build-tools pkg/zedctr tools/parse-pkgs.sh images/%.yml.in FORCE
	$(PARSE_PKGS) $@.in > $@

$(CONFIG_IMG): conf/server conf/onboard.cert.pem conf/wpa_supplicant.conf conf/ | $(DIST)
	./tools/makeconfig.sh $(CONF_DIR) $@

$(ROOTFS_IMG): images/rootfs.yml | $(DIST)
	./tools/makerootfs.sh $< $(ROOTFS_FORMAT) $@
	@[ $$(wc -c < "$@") -gt $$(( 250 * 1024 * 1024 )) ] && \
          echo "ERROR: size of $@ is greater than 250MB (bigger than allocated partition)" && exit 1 || :

$(FALLBACK_IMG).img: $(FALLBACK_IMG).$(IMG_FORMAT) | $(DIST)
	@rm -f $@ >/dev/null 2>&1 || :
	ln -s $(notdir $<) $@

$(FALLBACK_IMG).qcow2: $(FALLBACK_IMG).raw | $(DIST)
	qemu-img convert -c -f raw -O qcow2 $< $@
	rm $<

$(FALLBACK_IMG).raw: $(ROOTFS_IMG) $(CONFIG_IMG) | $(DIST)
	tar -C $(DIST) -c $(notdir $^) | ./tools/makeflash.sh -C ${MEDIA_SIZE} $@

$(ROOTFS_IMG)_installer.img: images/installer.yml $(ROOTFS_IMG) $(CONFIG_IMG) | $(DIST)
	./tools/makerootfs.sh $< $(ROOTFS_FORMAT) $@
	@[ $$(wc -c < "$@") -gt $$(( 300 * 1024 * 1024 )) ] && \
          echo "ERROR: size of $@ is greater than 300MB (bigger than allocated partition)" && exit 1 || :

$(INSTALLER_IMG).raw: $(ROOTFS_IMG)_installer.img $(CONFIG_IMG) | $(DIST)
	tar -C $(DIST) -c $(notdir $^) | ./tools/makeflash.sh -C 350 $@ "efi imga conf_win"
	rm $(ROOTFS_IMG)_installer.img

$(INSTALLER_IMG).iso: images/installer.yml $(ROOTFS_IMG) $(CONFIG_IMG) | $(DIST)
	./tools/makeiso.sh $< $@

zenix: ZENIX_HASH=$(shell echo ZENIX_TAG | PATH="$(PATH)" $(PARSE_PKGS) | sed -e 's#^.*:##' -e 's#-.*$$##')
zenix: Makefile $(BIOS_IMG) $(CONFIG_IMG) $(INSTALLER_IMG).iso $(INSTALLER_IMG).raw $(ROOTFS_IMG) $(FALLBACK_IMG).img images/rootfs.yml images/installer.yml
	cp $^ build-pkgs/zenix
	make -C build-pkgs BUILD-PKGS=zenix $(LK_HASH_REL) $(DEFAULT_PKG_TARGET)

# FIXME: the following is an ugly workaround against linuxkit complaining:
# FATA[0030] Failed to create OCI spec for zededa/zedctr:XXX: 
#    Error response from daemon: pull access denied for zededa/zedctr, repository does not exist or may require ‘docker login’
# The underlying problem is that running pkg target doesn't guarantee that
# the zededa/zedctr:XXX container will end up in a local docker cache (if linuxkit 
# doesn't rebuild the package) and we need it there for the linuxkit build to work.
# Which means, that we have to either forcefully rebuild it or fetch from docker hub.
pkg/zedctr: ZENIX_HASH=$(shell echo ZEDEDA_TAG | PATH="$(PATH)" $(PARSE_PKGS) | sed -e 's#^.*:##' -e 's#-.*$$##')
pkg/zedctr: ZEDCTR_TAG=zededa/zedctr:$(ZENIX_HASH)-$(DOCKER_ARCH_TAG)
pkg/zedctr: FORCE
	docker pull $(ZEDCTR_TAG) >/dev/null 2>&1 || : ;\
	if ! docker inspect $(ZEDCTR_TAG) >/dev/null 2>&1 ; then \
	  if [ -n "$(CROSS)" ] ; then \
	    $(PARSE_PKGS) < pkg/zedctr/Dockerfile.cross.in > pkg/zedctr/Dockerfile ;\
	    PKG_HASH=`mktemp -u XXXXXXXXXX` ;\
	    make -C pkg PKGS=zedctr RESCAN_DEPS="" LINUXKIT_OPTS="--disable-content-trust --force --disable-cache --hash $$PKG_HASH" $(DEFAULT_PKG_TARGET) ;\
	    PKG_HASH=zededa/zedctr:$$PKG_HASH ;\
	    docker tag $$PKG_HASH $(ZEDCTR_TAG) ;\
	    docker rmi $$PKG_HASH $$PKG_HASH-$(DOCKER_ARCH_TAG_$(HOSTARCH)) ;\
	  else \
	    make -C pkg PKGS=zedctr LINUXKIT_OPTS="--disable-content-trust --force --disable-cache $(subst LINUXKIT_HASH=",,$(LK_HASH_REL)) $(DEFAULT_PKG_TARGET) ;\
	  fi ;\
	fi

pkg/%: FORCE
	make -C pkg PKGS=$(notdir $@) LINUXKIT_OPTS="--disable-content-trust --disable-cache --force" $(LK_HASH_REL) $(DEFAULT_PKG_TARGET)

release:
	@function bail() { echo "ERROR: $$@" ; exit 1 ; } ;\
	 X=`echo $(VERSION) | cut -s -d. -f1` ; Y=`echo $(VERSION) | cut -s -d. -f2` ; Z=`echo $(VERSION) | cut -s -d. -f3` ;\
	 [ -z "$$X" -o -z "$$Y" -o -z "$$Z" ] && bail "VERSION missing (or incorrect). Re-run as: make VERSION=x.y.z $@" ;\
	 (git fetch && [ `git diff origin/master..master | wc -l` -eq 0 ]) || bail "origin/master is different from master" ;\
	 if git checkout $$X.$$Y 2>/dev/null ; then \
	    git merge origin/master ;\
	 else \
	    git checkout master -b $$X.$$Y && echo zedcloud.zededa.net > conf/server &&\
	    git commit -m"Setting default server to prod" conf/server ;\
	 fi || bail "Can't create $$X.$$Y branch" ;\
	 git commit -m"Pinning down versions in tools/parse-pkgs.sh" tools/parse-pkgs.sh 2>/dev/null ;\
	 (echo ZTOOLS_TAG ; echo LISP_TAG) | ZENIX_HASH=$$X.$$Y.$$Z ./tools/parse-pkgs.sh | grep -q zededa/debug &&\
	     bail "Couldn't find matching versions for ztools and/or lisp. You may want to edit tools/parse-pkg.sh" ;\
	 git tag -a -m"Release $$X.$$Y.$$Z" $$X.$$Y.$$Z &&\
	 echo "Done tagging $$X.$$Y.$$Z release. Check the branch with git log and then run" &&\
	 echo "  git push origin $$X.$$Y $$X.$$Y.$$Z"

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
	@echo "Commonly used maitenance targets:"
	@echo "   release        prepare branch for a release (VERSION=x.y.z required)"
	@echo
	@echo "Commonly used build targets:"
	@echo "   build-tools    builds linuxkit and manifest-tool utilities under build-tools/bin"
	@echo "   build-pkgs     builds all built-time linuxkit packages"
	@echo "   config         builds a bundle with initial Zenix configs"
	@echo "   pkgs           builds all Zenix packages"
	@echo "   pkg/XXX        builds XXX Zenix package"
	@echo "   rootfs         builds Zenix rootfs image (upload it to the cloud as BaseImage)"
	@echo "   fallback       builds a full disk image of Zenix which can be function as a virtual device"
	@echo "   installer      builds raw disk installer image (to be installed on bootable media)"
	@echo "   installer-iso  builds an ISO installers image (to be installed on bootable media)"
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
