#!/bin/bash
#
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Run prep-and-test.sh inside a Ubuntu 22.04 Docker container, matching the CI
# environment.

set -e

REPO_ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
IMAGE="eve-tpm-ci-test"
NO_CACHE=""

SNIFF_ARG=""
for arg in "$@"; do
    case "$arg" in
        --no-cache) NO_CACHE="--no-cache" ;;
        -sniff)     SNIFF_ARG="-sniff" ;;
    esac
done

echo "[+] Cleaning up any previous run ..."
docker rm -f eve-tpm-test 2>/dev/null || true

echo "[+] Building Docker image ($IMAGE) ..."
docker build $NO_CACHE -t "$IMAGE" -f - "$REPO_ROOT" <<'EOF'
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV GOVERSION=1.23.4

# Install Go
RUN apt-get update -qq && \
    apt-get install -y -qq curl ca-certificates && \
    curl -sL "https://go.dev/dl/go${GOVERSION}.linux-amd64.tar.gz" | tar -C /usr/local -xz
ENV PATH="/usr/local/go/bin:${PATH}"

# Pre-install sudo and ZFS headers (needed to build pillar packages)
RUN apt-get install -y -qq sudo && \
    echo "root ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

WORKDIR /eve
EOF

echo "[+] Running prep-and-test.sh inside container ..."
docker run --rm \
    --name eve-tpm-test \
    -v "$REPO_ROOT:/eve:ro" \
    "$IMAGE" \
    bash -c "cp -a /eve /eve-rw && cd /eve-rw && bash tests/tpm/prep-and-test.sh $SNIFF_ARG"
