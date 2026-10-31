#!/bin/sh
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
# shellcheck disable=SC2086
# shellcheck disable=SC2154
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
set -e

bail() {
   echo "$@"
   exit 1
}

case "$(uname -m)" in
   x86_64) BUILD_PKGS="$BUILD_PKGS $BUILD_PKGS_amd64"
           PKGS="$PKGS $PKGS_amd64"
           ;;
  aarch64) BUILD_PKGS="$BUILD_PKGS $BUILD_PKGS_arm64"
           PKGS="$PKGS $PKGS_arm64"
           ;;
  riscv64) BUILD_PKGS="$BUILD_PKGS $BUILD_PKGS_riscv64"
           PKGS="$PKGS $PKGS_riscv64"
           ;;
esac

set -- $BUILD_PKGS
[ $# -eq 0 ] || apt-get -y install "$@"

set -- $PKGS
[ $# -eq 0 ] || chroot /out apt-get -y install --no-install-recommends --no-install-suggests "$@"
