# pass HASH to parse-pkgs
# disable content trust for now
PATH := $(CURDIR)/../build-tools/bin:$(PATH)
LINUXKIT_OPTS= --disable-content-trust $(LINUXKIT_HASH)
RESCAN_DEPS=FORCE

PKGS = grub xen kernel fw xen-tools dnsmasq strongswan gpt-tools dom0-ztools	\
	qrexec-lib qrexec-dom0 wwan wlan rngd	\
	watchdog \
        guacd \
	lisp \
        device-trees \
        debug \
	mkconf mkrootfs-ext4 mkrootfs-squash mkimage-raw-efi mkimage-iso-efi

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

%: %.in $(RESCAN_DEPS)
	(cd ..; ./tools/parse-pkgs.sh pkg/$< > pkg/$@)
FORCE:
