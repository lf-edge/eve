# disable content trust for now
LINUXKIT_OPTS= --disable-content-trust

DIRS = $(dir $(shell find . -maxdepth 2 -mindepth 2 -type f -name build.yml))
.PHONY: push force-push build forcebuild show-tag clean

build:
	@set -e; for d in $(DIRS); do linuxkit pkg build ${LINUXKIT_OPTS} "$$d"; done

push:
	@set -e; for d in $(DIRS); do linuxkit pkg push ${LINUXKIT_OPTS} "$$d"; done

forcepush:
	@set -e; for d in $(DIRS); do linuxkit pkg push --force ${LINUXKIT_OPTS} "$$d"; done

forcebuild:
	@set -e; for d in $(DIRS); do linuxkit pkg build --force ${LINUXKIT_OPTS} "$$d"; done

show-tag:
	@set -e; for d in $(DIRS); do linuxkit pkg show-tag "$$d"; done

clean:
