# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# mk/linuxkit.mk — linuxkit binary acquisition
#
# Priority (first match wins):
#   1. LINUXKIT_SRC=/path   build from local source tree, no network
#   2. LINUXKIT_GIT_URL set clone at LINUXKIT_GIT_REF (commit hash) and build
#   3. (neither)            download official release binary
#
# Set LINUXKIT_GIT_URL="" to use the release binary (case 3).
# LINUXKIT_VERSION must remain a published semver tag — it is used only for
# the release-download URL in case 3.

# linuxkit version. This **must** be a published semver version so it can be
# downloaded already compiled from the release page at
# https://github.com/linuxkit/linuxkit/releases
LINUXKIT_VERSION ?= v1.8.1
LINUXKIT_SOURCE  ?= https://github.com/linuxkit/linuxkit

# LINUXKIT_GIT_REF must be a commit hash (reproducible, no ls-remote needed).
# Update by running: git ls-remote https://github.com/linuxkit/linuxkit master
LINUXKIT_GIT_URL ?= https://github.com/linuxkit/linuxkit
LINUXKIT_GIT_REF ?= 3bf33c3a11fc20b459195294a7d8980cbca4195b
# Optional local source tree — takes priority over LINUXKIT_GIT_URL.
#   make LINUXKIT_SRC=/path/to/linuxkit <target>
LINUXKIT_SRC ?=

.PHONY: linuxkit
linuxkit: $(LINUXKIT)

ifneq ($(LINUXKIT_SRC),)
# ── Case 1: local source tree ────────────────────────────────────────────────
# Rebuild whenever Go sources change; no network access needed.
$(LINUXKIT): $(PARALLEL_BUILD_LOCK) | $(BUILDTOOLS_BIN)
	@echo "Building linuxkit from local source: $(LINUXKIT_SRC)"
	$(QUIET)$(MAKE) -C $(LINUXKIT_SRC) local-build LOCAL_TARGET=$(abspath $@)
	$(QUIET)docker stop linuxkit-builder >/dev/null 2>&1 || true
	$(QUIET)docker rm linuxkit-builder >/dev/null 2>&1 || true
	$(QUIET): $@: Succeeded

else ifneq ($(LINUXKIT_GIT_URL),)
# ── Case 2: commit hash from a git repo ──────────────────────────────────────
# The hash is used directly as the versioned binary name — no network call at
# parse time.  Make skips the recipe if the binary already exists (cached).
_LK_VERSION := $(shell printf '%s' '$(LINUXKIT_GIT_REF)' | cut -c1-12)

$(LINUXKIT): $(BUILDTOOLS_BIN)/linuxkit-$(_LK_VERSION) $(PARALLEL_BUILD_LOCK)
	$(QUIET)docker stop linuxkit-builder >/dev/null 2>&1 || true
	$(QUIET)docker rm linuxkit-builder >/dev/null 2>&1 || true
	$(QUIET)ln -sf $(notdir $<) $@
	$(QUIET): $@: Succeeded

$(BUILDTOOLS_BIN)/linuxkit-$(_LK_VERSION): | $(BUILDTOOLS_BIN)
	@echo "Building linuxkit from $(LINUXKIT_GIT_URL) at $(LINUXKIT_GIT_REF)"
	$(QUIET)tmp=$$(mktemp -d) && \
	  git clone --filter=blob:none $(LINUXKIT_GIT_URL) $$tmp && \
	  git -C $$tmp checkout $(LINUXKIT_GIT_REF) && \
	  $(MAKE) -C $$tmp local-build LOCAL_TARGET=$(abspath $@) && \
	  rm -rf $$tmp
	$(QUIET): $@: Succeeded

else
# ── Case 3: download upstream release binary ──────────────────────────────────
$(LINUXKIT): $(BUILDTOOLS_BIN)/linuxkit-$(LINUXKIT_VERSION) $(PARALLEL_BUILD_LOCK)
	$(QUIET)docker stop linuxkit-builder >/dev/null 2>&1 || true
	$(QUIET)docker rm linuxkit-builder >/dev/null 2>&1 || true
	$(QUIET)ln -sf $(notdir $<) $@
	$(QUIET): $@: Succeeded

$(BUILDTOOLS_BIN)/linuxkit-$(LINUXKIT_VERSION): | $(BUILDTOOLS_BIN)
	@echo "Downloading linuxkit release $(LINUXKIT_VERSION)"
	$(QUIET)curl -fsSL -o $@ \
	  $(LINUXKIT_SOURCE)/releases/download/$(LINUXKIT_VERSION)/linuxkit-$(LOCAL_GOOS)-$(HOSTARCH) \
	  && chmod +x $@
	$(QUIET): $@: Succeeded

endif
