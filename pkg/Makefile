# disable content trust for now
LINUXKIT_OPTS= --disable-content-trust

PKGS = xen kernel xen-tools mkimage-iso-efi mkimage-raw-efi \
	dnsmasq dom0-ztools test-cert test-microsvcs \
	qrexec-lib qrexec-dom0

.PHONY: push force-push build forcebuild show-tag clean dockerfiles

build: #dockerfiles
	@set -e; for d in $(PKGS); do linuxkit pkg build ${LINUXKIT_OPTS} "$$d"; done

push:
	@set -e; for d in $(PKGS); do linuxkit pkg push ${LINUXKIT_OPTS} "$$d"; done

forcepush:
	@set -e; for d in $(PKGS); do linuxkit pkg push --force ${LINUXKIT_OPTS} "$$d"; done

forcebuild:
	@set -e; for d in $(PKGS); do linuxkit pkg build --force ${LINUXKIT_OPTS} "$$d"; done

show-tag:
	@set -e; for d in $(PKGS); do linuxkit pkg show-tag "$$d"; done

clean:

dockerfiles: $(addsuffix Dockerfile, $(PKGS)/)

%: %.template FORCE
	(cd ..; ./parse-pkgs.sh pkg/$< > pkg/$@)
FORCE:
