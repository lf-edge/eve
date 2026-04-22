#!/bin/sh
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
# shellcheck disable=SC2086
#
# Extract target-architecture Alpine packages into /out/ without QEMU.
#
# This script is used during cross-compilation to build a sysroot from
# the target-arch eve-alpine mirror that was copied into the build container.
# It re-indexes the foreign-arch packages with the native arch tag so that
# apk treats them as installable, then extracts them into /out/.
#
# Required environment variables:
#   EVE_TARGET_ARCH - target architecture (aarch64, x86_64, riscv64)
#   PKGS            - space-separated list of packages to install
#
# Optional:
#   ALPINE_VERSION  - Alpine version (default: 3.16)
#   TARGET_MIRROR   - path to target-arch mirror (default: /target-mirror)
#
set -e

ALPINE_VERSION=${ALPINE_VERSION:-3.22}
TARGET_MIRROR=${TARGET_MIRROR:-/target-mirror}

bail() {
    echo "$@"
    exit 1
}

[ -n "$EVE_TARGET_ARCH" ] || bail "EVE_TARGET_ARCH is not set"
[ -n "$PKGS" ] || bail "PKGS is not set"

# Map Docker/EVE arch names to apk arch names
case "$EVE_TARGET_ARCH" in
    amd64|x86_64)   TARGET_APK_ARCH=x86_64  ;;
    arm64|aarch64)   TARGET_APK_ARCH=aarch64 ;;
    riscv64)         TARGET_APK_ARCH=riscv64 ;;
    *)               bail "Unknown architecture: $EVE_TARGET_ARCH" ;;
esac

NATIVE_APK_ARCH=$(apk --print-arch)
SOURCE_DIR="$TARGET_MIRROR/$ALPINE_VERSION/$TARGET_APK_ARCH"

[ -d "$SOURCE_DIR" ] || bail "Target mirror not found: $SOURCE_DIR"

# If target == native, just use eve-alpine-deploy.sh directly
if [ "$TARGET_APK_ARCH" = "$NATIVE_APK_ARCH" ]; then
    exec eve-alpine-deploy.sh "$ALPINE_VERSION"
fi

# Set up a temporary repo with the foreign-arch packages re-indexed as native
WORK_DIR="/tmp/cross-sysroot"
REPO_DIR="$WORK_DIR/repo"
CACHE_DIR="$REPO_DIR/$NATIVE_APK_ARCH"
mkdir -p "$CACHE_DIR"

# Copy target-arch APKs to the cache dir named after native arch
cp "$SOURCE_DIR"/*.apk "$CACHE_DIR/"

# Import signing keys from the target-arch mirror so apk trusts the packages
TARGET_ROOTFS="$TARGET_MIRROR/$ALPINE_VERSION/rootfs"
if [ -d "$TARGET_ROOTFS/etc/apk/keys" ]; then
    cp "$TARGET_ROOTFS"/etc/apk/keys/*.pub /etc/apk/keys/ 2>/dev/null || true
fi

# Re-index with native arch tag — this is the same trick used in build-cache.sh
# It makes apk treat the foreign-arch packages as if they were native
apk index --rewrite-arch "$NATIVE_APK_ARCH" \
    -o "$CACHE_DIR/APKINDEX.unsigned.tar.gz" "$CACHE_DIR"/*.apk
cp "$CACHE_DIR/APKINDEX.unsigned.tar.gz" "$CACHE_DIR/APKINDEX.tar.gz"

# Prepare /out/ for package installation
# --allow-untrusted: APKINDEX is unsigned (no abuild-sign in final image)
# --initdb: create a fresh apk database in /out
# -X: use our re-indexed repo
# -p: install into /out/ prefix
set $PKGS
apk add --no-cache --allow-untrusted --initdb \
    -X "$REPO_DIR" -p /out "$@"

# Clean up
rm -rf "$WORK_DIR"
