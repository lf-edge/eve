# pass hash to parse-pkgs
# disable content trust for now
PATH := $(CURDIR)/../build-tools/bin:$(PATH)
LINUXKIT_OPTS= --disable-content-trust $(LINUXKIT_HASH)

BUILDARCH ?= $(shell uname -m) # The target CPU architecture == host arch if unspecified.

BUILD-PKGS =  abuild uefi

.PHONY: push force-push build forcebuild show-tag clean dockerfiles

build: dockerfiles
	@set -e; for d in $(BUILD-PKGS); do linuxkit pkg build ${LINUXKIT_OPTS} "$$d"; done

push:
	@set -e; for d in $(BUILD-PKGS); do linuxkit pkg push ${LINUXKIT_OPTS} "$$d"; done

forcepush:
	@set -e; for d in $(BUILD-PKGS); do linuxkit pkg push --force ${LINUXKIT_OPTS} "$$d"; done

forcebuild:
	@set -e; for d in $(BUILD-PKGS); do linuxkit pkg build --force ${LINUXKIT_OPTS} "$$d"; done

show-tag:
	@set -e; for d in $(BUILD-PKGS); do linuxkit pkg show-tag "$$d"; done

clean:

dockerfiles: $(addsuffix /Dockerfile, $(BUILD-PKGS)/)

%: %.in FORCE
	(cd ..; ./parse-pkgs.sh build-pkgs/$< > build-pkgs/$@)
FORCE:
