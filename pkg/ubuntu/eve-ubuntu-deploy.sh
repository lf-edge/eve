#!/bin/sh
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
# shellcheck disable=SC2086
#
# This script is used to setup Ubuntu build environments
# for EVE containers and produce the resulting, Ubuntu-based
# executable container if needed (note that not all builds produce
# executable containers -- some just wrap binaries).
#
# This script is driven by the following environment variables:
#   BUILD_PKGS - packages required for the build stage
#   BUILD_PKGS_[amd64|arm64|riscv64] - like BUILD_PKGS but arch specific
#   PKGS - packages required for the executable container
#   PKGS_[amd64|arm64|riscv64] - like PKGS but arch specific
#
# The build stage installs from the local mirror directly. The executable
# container is the Ubuntu rootfs under /out: apt runs outside of it, with
# -o Dir=/out it uses the sources, lists and cache below /out, and with
# DPkg::Chroot-Directory it chroots into /out before calling dpkg, so the
# debs it copied to /out/var/cache/apt/archives are visible to dpkg.
set -e

arch="$(dpkg --print-architecture)"
eval "BUILD_PKGS=\"\$BUILD_PKGS \$BUILD_PKGS_$arch\""
eval "PKGS=\"\$PKGS \$PKGS_$arch\""

set -- $BUILD_PKGS
[ $# -eq 0 ] || apt-get -y install "$@"

set -- $PKGS
if [ $# -gt 0 ]; then
   cp /out/etc/apt/sources.list.mirror /out/etc/apt/sources.list
   apt-get -o Dir=/out -o DPkg::Chroot-Directory=/out -q update
   apt-get -o Dir=/out -o DPkg::Chroot-Directory=/out -y install "$@"
fi

# the mirror is only reachable at build time: leave the snapshot behind as
# the apt source of the container and drop the debs and the mirror index
cp /out/etc/apt/sources.list.upstream /out/etc/apt/sources.list
rm -rf /out/var/cache/apt/archives/*.deb /out/var/cache/apt/archives/partial \
       /out/var/cache/apt/*.bin /out/var/lib/apt/lists/*
# nothing reconfigures packages or reads the install logs in a running container
rm -rf /out/var/cache/debconf/* /out/var/log/apt /out/var/log/dpkg.log /out/var/log/alternatives.log /out/var/log/bootstrap.log
