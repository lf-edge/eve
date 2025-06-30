# Copyright (c) 2023-2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# This file is included by the main Makefile.
# Four variables are used as input for the kernel build:
#   ZARCH - architecture (amd64, arm64)
#   PLATFORM - platform (generic, nvidia, rt, imx*) based on these two
#              variables we set kernel version, commit hash and branch
#              when new kernel is built and pushed to the corresponding
#              dockerhub
#   KERNEL_COMMIT_xxx variable must be manually updated
#   KERNEL_KONFIG_FLAVOR - optional, used to select kernel's docker tag
#                          which corresponds to the kernel config file

KERNEL_COMPILER=gcc

# kernel may have severla config files eve-<KERNEL_KONFIG_FLAVOR>_defconfig
# this variable can be passed to the make command line to select
# 'evaluation' platform has hardcoded config flavors for different rootfs images
# by default the flavor is empty to keep compatibility with the old EVE version
KERNEL_KONFIG_FLAVOR ?=
KERNEL_KONFIG_FLAVOR := $(if $(KERNEL_KONFIG_FLAVOR),$(KERNEL_KONFIG_FLAVOR)-,)

PLATFORMS_amd64=generic rt evaluation
PLATFORMS_arm64=generic nvidia-jp5 nvidia-jp6 imx8mp_pollux imx8mp_epc_r3720 imx8mq_evk
PLATFORMS_riscv64=generic
ARCHS=amd64 arm64 riscv64

# check if ZARCH is supported
ifeq (, $(filter $(ZARCH), $(ARCHS)))
    $(error "Unsupported architecture $(ZARCH)")
endif

# check if PLATFORM is supported
ifeq (, $(filter $(PLATFORM), $(PLATFORMS_$(ZARCH))))
    $(error "Unsupported combination of ZARCH=$(ZARCH) and PLATFORM=$(PLATFORM)")
endif

KERNEL_LTS_VERSION=v6.12.33

ifeq ($(ZARCH), amd64)
    ifeq ($(PLATFORM), rt)
        KERNEL_FLAVOR=rt
        KERNEL_VERSION=v6.1.111
    else
        KERNEL_FLAVOR=generic
        KERNEL_VERSION=v6.1.112
    endif
else ifeq ($(ZARCH), arm64)
    ifeq (, $(findstring nvidia,$(PLATFORM)))
        KERNEL_FLAVOR=generic
        KERNEL_VERSION=v6.1.112
    else
        KVER_nvidia=v5.10.192
        KVER_nvidia-jp5=v5.10.192
        KVER_nvidia-jp6=v5.15.136

        KERNEL_FLAVOR=$(PLATFORM)
        KERNEL_VERSION=$(KVER_$(PLATFORM))
    endif
else ifeq ($(ZARCH), riscv64)
    KERNEL_VERSION=v6.1.112
    KERNEL_FLAVOR=generic
endif

include kernel-commits.mk

# check if KERNEL_VERSION is defined
ifeq ($(origin KERNEL_VERSION), undefined)
    $(error "KERNEL_VERSION is not defined. did you introduced new platform or ARCH?")
endif

# at this point ZARCH, KERNEL_VERSION and FLAVOR must be defined.
# Check that we defined a commit for combination
ifeq ($(origin KERNEL_COMMIT_$(ZARCH)_$(KERNEL_VERSION)_$(KERNEL_FLAVOR)), undefined)
    $(error "KERNEL_COMMIT_$(ZARCH)_$(KERNEL_VERSION)_$(KERNEL_FLAVOR) is not defined. did you introduce new platform or ARCH?")
endif

KERNEL_COMMIT=$(KERNEL_COMMIT_$(ZARCH)_$(KERNEL_VERSION)_$(KERNEL_FLAVOR))
KERNEL_BRANCH = eve-kernel-$(ZARCH)-$(KERNEL_VERSION)-$(KERNEL_FLAVOR)
KERNEL_DOCKER_TAG = $(KERNEL_BRANCH)-$(KERNEL_KONFIG_FLAVOR)$(KERNEL_COMMIT)-$(KERNEL_COMPILER)

# LTS commit is not any speccial, one day it becomes a regular commit
# TODO: LTS branch is not yet available in the eve-kernel repository
# uncomment the following lines when it is
# ifeq ($(origin KERNEL_COMMIT_$(ZARCH)_$(KERNEL_LTS_VERSION)_$(KERNEL_FLAVOR)), undefined)
#     $(error "KERNEL_COMMIT_$(ZARCH)_$(KERNEL_LTS_VERSION)_$(KERNEL_FLAVOR) is not defined. did you introduce new platform or ARCH?")
# endif

KERNEL_LTS_COMMIT=$(KERNEL_COMMIT_$(ZARCH)_$(KERNEL_LTS_VERSION)_$(KERNEL_FLAVOR))
KERNEL_LTS_BRANCH = eve-kernel-$(ZARCH)-$(KERNEL_LTS_VERSION)-$(KERNEL_FLAVOR)

# one can override the whole tag from the command line and set it to
# output of make -f Makefile.eve docker-tag-${KERNEL_COMPILER} in github.com/lf-edge/eve-kernel
KERNEL_TAG ?= docker.io/lfedge/eve-kernel:$(KERNEL_DOCKER_TAG)

# these tags are valid for evaluation platforms only
KERNEL_EVAL_HWE_DOCKER_TAG = $(KERNEL_BRANCH)-hwe-$(KERNEL_COMMIT)-$(KERNEL_COMPILER)
KERNEL_EVAL_LTS_HWE_DOCKER_TAG = $(KERNEL_LTS_BRANCH)-hwe-$(KERNEL_LTS_COMMIT)-$(KERNEL_COMPILER)
KERNEL_EVAL_HWE_TAG ?= docker.io/lfedge/eve-kernel:$(KERNEL_EVAL_HWE_DOCKER_TAG)
# TODO: docker tag for LTS is not published yet. KERNEL_EVAL_HWE_DOCKER_TAG will be replaced
# with KERNEL_EVAL_LTS_HWE_DOCKER_TAG when it is available
KERNEL_EVAL_LTS_HWE_TAG ?= docker.io/lfedge/eve-kernel:$(KERNEL_EVAL_HWE_DOCKER_TAG)
