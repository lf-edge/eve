# disable content trust for now
PATH := $(CURDIR)/../build-tools/bin:$(PATH)
LINUXKIT_OPTS= --disable-content-trust

PKGS = grub xen kernel kmod_pfring xen-tools dnsmasq gpt-tools dom0-ztools	\
	qrexec-lib qrexec-dom0 wwan wlan	\
	watchdog \
	zedctr mkconf mkrootfs-ext4 mkrootfs-squash mkflash mkimage-iso-efi mkimage-raw-efi

.PHONY: push force-push build forcebuild show-tag clean dockerfiles

build: dockerfiles
	@set -e; for d in $(PKGS); do linuxkit pkg build ${LINUXKIT_OPTS} "$$d"; done

push: dockerfiles
	@set -e; for d in $(PKGS); do linuxkit pkg push ${LINUXKIT_OPTS} "$$d"; done

forcepush: dockerfiles
	@set -e; for d in $(PKGS); do linuxkit pkg push --force ${LINUXKIT_OPTS} "$$d"; done

forcebuild: dockerfiles
	@set -e; for d in $(PKGS); do linuxkit pkg build --force ${LINUXKIT_OPTS} "$$d"; done

show-tag:
	@set -e; for d in $(PKGS); do linuxkit pkg show-tag "$$d"; done

clean:

dockerfiles: $(addsuffix /Dockerfile, $(PKGS)/)

%: %.in FORCE
	(cd ..; ./parse-pkgs.sh pkg/$< > pkg/$@)
FORCE:
