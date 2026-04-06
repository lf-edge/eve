#!/bin/sh
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Build and push the eve-cross-compilers image.
# Build logs are saved under ./logs/
#
# Usage:
#   ./build.sh                    # build for current arch, load locally
#   ./build.sh --push             # build + push (arch-suffixed tag)
#   ./build.sh --push --single    # build + push WITHOUT arch suffix
#   ./build.sh --manifest --push  # create and push multi-arch manifest
#
# For single-arch testing (no arm64 machine available):
#   REPO=myrepo/eve-cross-compilers ./build.sh --push --single
#
# For full multi-arch (run on each arch, then merge):
#   ./build.sh --push              # on amd64
#   ./build.sh --push              # on arm64
#   ./build.sh --manifest --push   # from either
#
# Environment:
#   REPO          - image repo (default: lfedge/eve-cross-compilers)
#   GCC_VER       - GCC version (default: 11.2.0)
#   ALPINE_VER    - Alpine version for tag (default: 3.16)
#
set -e

REPO="${REPO:-lfedge/eve-cross-compilers}"
GCC_VER="${GCC_VER:-11.2.0}"
ALPINE_VER="${ALPINE_VER:-3.16}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GIT_REV="$(git -C "$SCRIPT_DIR" describe --always --dirty 2>/dev/null || echo unknown)"
TAG="gcc-${GCC_VER}-alpine-${ALPINE_VER}-${GIT_REV}"
LOG_DIR="${SCRIPT_DIR}/logs"

PUSH=false
MANIFEST=false
SINGLE=false

for arg in "$@"; do
    case "$arg" in
        --push) PUSH=true ;;
        --manifest) MANIFEST=true ;;
        --single) SINGLE=true ;;
        --help|-h)
            echo "Usage: $0 [--push] [--single] [--manifest]"
            echo ""
            echo "  --push      Push images/manifest to registry"
            echo "  --single    Push without arch suffix (for single-arch testing)"
            echo "  --manifest  Create multi-arch manifest (skip build)"
            echo ""
            echo "Environment:"
            echo "  REPO=$REPO"
            echo "  GCC_VER=$GCC_VER"
            echo "  ALPINE_VER=$ALPINE_VER"
            echo "  Tag: $TAG"
            exit 0
            ;;
    esac
done

if [ "$MANIFEST" = true ]; then
    echo "Creating multi-arch manifest: ${REPO}:${TAG}"
    docker manifest create "${REPO}:${TAG}" \
        "${REPO}:${TAG}-amd64" \
        "${REPO}:${TAG}-arm64"
    if [ "$PUSH" = true ]; then
        docker manifest push "${REPO}:${TAG}"
        echo "Pushed: ${REPO}:${TAG}"
    fi
    exit 0
fi

ARCH="$(docker info --format '{{.Architecture}}')"
case "$ARCH" in
    x86_64)  PLATFORM="linux/amd64"; ARCH_TAG="amd64" ;;
    aarch64) PLATFORM="linux/arm64"; ARCH_TAG="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Single-arch mode: tag without arch suffix (usable directly by consumers)
if [ "$SINGLE" = true ]; then
    IMAGE_TAG="${TAG}"
else
    IMAGE_TAG="${TAG}-${ARCH_TAG}"
fi

echo "Building cross-compilers for ${PLATFORM}"
echo "  Tag: ${REPO}:${IMAGE_TAG}"
echo "  GCC: ${GCC_VER}"

if [ "$PUSH" = true ]; then
    PUSH_FLAG="--push"
else
    PUSH_FLAG="--load"
fi

mkdir -p "${LOG_DIR}"
LOG_FILE="${LOG_DIR}/build-${ARCH_TAG}.log"

echo "  Log: ${LOG_FILE}"
echo ""

docker buildx build \
    --progress=plain \
    --platform "${PLATFORM}" \
    --build-arg GCC_VER="${GCC_VER}" \
    --build-arg ALPINE_VERSION="${ALPINE_VER}" \
    ${PUSH_FLAG} \
    --tag "${REPO}:${IMAGE_TAG}" \
    "$SCRIPT_DIR" 2>&1 | tee "${LOG_FILE}"

echo ""
echo "Done: ${REPO}:${IMAGE_TAG}"
echo "Full log: ${LOG_FILE}"

if [ "$PUSH" = false ]; then
    echo ""
    echo "To push:          $0 --push"
    echo "To push (single): $0 --push --single"
    echo "To manifest:      $0 --manifest --push"
fi
