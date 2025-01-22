# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# This file is included by the main Makefile.
# Two variables are used as input for the kernel build:
#   ZARCH - architecture (amd64, arm64)
#   PLATFORM - platform (generic, nvidia, rt, imx*) based on these two
#              variables we set kernel version, commit hash and branch
#              when new kernel is built and pushed to the corresponding
#              dockerhub
#   KERNEL_COMMIT_xxx variable must be manually updated
#

KERNEL_COMPILER=gcc
PLATFORM?=generic

PLATFORMS_amd64=generic rt
PLATFORMS_arm64=generic nvidia nvidia-jp5 nvidia-jp6 imx8mp_pollux imx8mp_epc_r3720 imx8mq_evk
PLATFORMS_riscv64=generic
ARCHS=amd64 arm64 riscv64

# check if ZARCH is supported
ifeq (, $(findstring $(ZARCH), $(ARCHS)))
    $(error "Unsupported architecture $(ZARCH)")
endif

# check if PLATFORM is supported
ifeq (, $(findstring $(PLATFORM), $(PLATFORMS_$(ZARCH))))
    $(error "Unsupported combination of ZARCH=$(ZARCH) and PLATFORM=$(PLATFORM)")
endif

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
    $(error "KERNEL_COMMIT_$(KERNEL_FLAVOR) is not defined. did you introduce new platform or ARCH?")
endif

KERNEL_COMMIT=$(KERNEL_COMMIT_$(ZARCH)_$(KERNEL_VERSION)_$(KERNEL_FLAVOR))
KERNEL_BRANCH = eve-kernel-$(ZARCH)-$(KERNEL_VERSION)-$(KERNEL_FLAVOR)
KERNEL_DOCKER_TAG = $(KERNEL_BRANCH)-$(KERNEL_COMMIT)-$(KERNEL_COMPILER)

# one can override the whole tag from the command line and set it to
# output of make -f Makefile.eve docker-tag-${KERNEL_COMPILER} in github.com/lf-edge/eve-kernel
KERNEL_TAG ?= docker.io/lfedge/eve-kernel:$(KERNEL_DOCKER_TAG)
