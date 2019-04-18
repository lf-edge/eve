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
# canonicalized names for architecture
ifeq ($(ZARCH),aarch64)
        ZARCH=arm64
endif
ifeq ($(ZARCH),x86_64)
        ZARCH=amd64
endif
QEMU_SYSTEM_arm64:=qemu-system-aarch64
QEMU_SYSTEM_amd64:=qemu-system-x86_64
QEMU_SYSTEM=$(QEMU_SYSTEM_$(ZARCH))

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

PARSE_PKGS:=$(if $(strip $(EVE_HASH)),EVE_HASH=)$(EVE_HASH) DOCKER_ARCH_TAG=$(DOCKER_ARCH_TAG) ./tools/parse-pkgs.sh
LK_HASH_REL=LINUXKIT_HASH="$(if $(strip $(EVE_HASH)),--hash) $(EVE_HASH) $(if $(strip $(EVE_REL)),--release) $(EVE_REL)"

DEFAULT_PKG_TARGET=build

.PHONY: run pkgs help build-tools fallback rootfs config installer live

all: help

build-tools:
	${MAKE} -C build-tools all

pkgs: build-tools
	make -C pkg $(LK_HASH_REL) $(DEFAULT_PKG_TARGET)

$(EFI_PART): | $(DIST)/bios
	cd $| ; $(DOCKER_UNPACK) $(shell make -s -C pkg PKGS=grub show-tag)-$(DOCKER_ARCH_TAG) EFI
	(echo "set root=(hd0)" ; echo "chainloader /EFI/BOOT/BOOTX64.EFI" ; echo boot) > $@/BOOT/grub.cfg

$(BIOS_IMG): | $(DIST)/bios
	cd $| ; $(DOCKER_UNPACK) $(shell make -s -C pkg PKGS=uefi show-tag)-$(DOCKER_ARCH_TAG) OVMF.fd

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

images/%.yml: build-tools tools/parse-pkgs.sh images/%.yml.in FORCE
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

eve: EVE_HASH=$(shell echo EVE_TAG | PATH="$(PATH)" $(PARSE_PKGS) | sed -e 's#^.*:##' -e 's#-.*$$##')
eve: Makefile $(BIOS_IMG) $(CONFIG_IMG) $(INSTALLER_IMG).iso $(INSTALLER_IMG).raw $(ROOTFS_IMG) $(FALLBACK_IMG).img images/rootfs.yml images/installer.yml
	cp pkg/eve/* Makefile images/rootfs.yml images/installer.yml $(DIST)
	export $(LK_HASH_REL) ; linuxkit pkg $(DEFAULT_PKG_TARGET) --disable-content-trust $${LINUXKIT_HASH} $(DIST)

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
	 git tag -a -m"Release $$X.$$Y.$$Z" $$X.$$Y.$$Z &&\
	 echo "Done tagging $$X.$$Y.$$Z release. Check the branch with git log and then run" &&\
	 echo "  git push origin $$X.$$Y $$X.$$Y.$$Z"

.PHONY: FORCE
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
	@echo "Commonly used maitenance targets:"
	@echo "   release        prepare branch for a release (VERSION=x.y.z required)"
	@echo
	@echo "Commonly used build targets:"
	@echo "   build-tools    builds linuxkit and manifest-tool utilities under build-tools/bin"
	@echo "   config         builds a bundle with initial EVE configs"
	@echo "   pkgs           builds all EVE packages"
	@echo "   pkg/XXX        builds XXX EVE package"
	@echo "   rootfs         builds EVE rootfs image (upload it to the cloud as BaseImage)"
	@echo "   fallback       builds a full disk image of EVE which can be function as a virtual device"
	@echo "   installer      builds raw disk installer image (to be installed on bootable media)"
	@echo "   installer-iso  builds an ISO installers image (to be installed on bootable media)"
	@echo
	@echo "Commonly used run targets (note they don't automatically rebuild images they run):"
	@echo "   run-grub          runs our copy of GRUB bootloader and nothing else (very limited usefulness)"
	@echo "   run-rootfs        runs a rootfs.img (limited usefulness e.g. quick test before cloud upload)"
	@echo "   run-installer-iso runs installer.iso on qemu and 'installs' EVE on fallback.img"
	@echo "   run-installer-raw runs installer.raw on qemu and 'installs' EVE on fallback.img"
	@echo "   run-fallback      runs a full fledged virtual device on qemu (as close as it gets to actual h/w)"
	@echo
	@echo "make run is currently an alias for make run-fallback"
	@echo
