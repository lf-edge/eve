#!/bin/sh
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Trigger the cross-compilers CI workflow on GitHub and wait for it.
#
# Usage:
#   ./trigger-ci-build.sh [GCC_VER] [ALPINE_VER]
#   ./trigger-ci-build.sh 11.2.0 3.16
#   ./trigger-ci-build.sh              # uses defaults
#
# Requires: gh CLI authenticated with lf-edge/eve repo access
#
set -e

GCC_VER="${1:-11.2.0}"
ALPINE_VER="${2:-3.16}"
REPO="lf-edge/eve"
WORKFLOW="build-cross-compilers.yml"

GIT_REV="$(git describe --always --dirty 2>/dev/null || echo unknown)"

echo "Triggering cross-compilers build on ${REPO}"
echo "  GCC: ${GCC_VER}"
echo "  Alpine: ${ALPINE_VER}"
echo "  Tag: gcc-${GCC_VER}-alpine-${ALPINE_VER}-<git-rev>"
echo "  (git rev on CI will be: ${GIT_REV})"
echo ""

gh workflow run "${WORKFLOW}" \
    --repo "${REPO}" \
    --ref master \
    -f gcc_ver="${GCC_VER}" \
    -f alpine_ver="${ALPINE_VER}"

echo "Workflow triggered. Waiting for run to start..."
sleep 5

RUN_ID=$(gh run list --repo "${REPO}" --workflow "${WORKFLOW}" --limit 1 --json databaseId --jq '.[0].databaseId')

echo "Run ID: ${RUN_ID}"
echo "URL: https://github.com/${REPO}/actions/runs/${RUN_ID}"
echo ""
echo "Watching run (Ctrl+C to stop watching — build continues)..."

gh run watch "${RUN_ID}" --repo "${REPO}"
