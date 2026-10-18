#!/bin/sh
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Compare Ubuntu package versions between two lfedge/eve-ubuntu mirror images.
#
# By default reads the local image hash from pkg/pillar/Dockerfile and fetches
# the upstream (lf-edge/eve master) hash via the GitHub API.
#
# Usage:
#   compare-eve-ubuntu-mirror.sh [LOCAL_HASH [MASTER_HASH]]
#
# Requires: docker
# Optional: gh (GitHub CLI) or curl, to auto-detect the master hash

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PILLAR_DOCKERFILE="${REPO_ROOT}/pkg/pillar/Dockerfile"

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

hash_from_dockerfile() {
    grep -m1 'ARG EVE_UBUNTU_IMAGE=' | sed 's|.*lfedge/eve-ubuntu:||'
}

# --- Resolve image hashes ---

if [ -n "${1:-}" ]; then
    LOCAL_HASH="$1"
else
    LOCAL_HASH=$(hash_from_dockerfile < "${PILLAR_DOCKERFILE}")
    [ -n "${LOCAL_HASH}" ] \
        || die "Could not read local eve-ubuntu hash from ${PILLAR_DOCKERFILE}"
fi

if [ -n "${2:-}" ]; then
    MASTER_HASH="$2"
elif command -v gh >/dev/null 2>&1; then
    MASTER_HASH=$(gh api repos/lf-edge/eve/contents/pkg/pillar/Dockerfile \
                      --jq '.content' \
                  | base64 -d \
                  | hash_from_dockerfile)
    [ -n "${MASTER_HASH}" ] \
        || die "Could not read master eve-ubuntu hash from lf-edge/eve via gh"
elif command -v curl >/dev/null 2>&1; then
    MASTER_HASH=$(curl -sf \
        "https://raw.githubusercontent.com/lf-edge/eve/master/pkg/pillar/Dockerfile" \
                  | hash_from_dockerfile)
    [ -n "${MASTER_HASH}" ] \
        || die "Could not read master eve-ubuntu hash from lf-edge/eve via curl"
else
    die "Pass MASTER_HASH as the second argument, or install gh or curl"
fi

printf 'Local  lfedge/eve-ubuntu: %s\n' "${LOCAL_HASH}"
printf 'Master lfedge/eve-ubuntu: %s\n\n' "${MASTER_HASH}"

if [ "${LOCAL_HASH}" = "${MASTER_HASH}" ]; then
    printf 'Hashes are identical - no comparison needed.\n'
    exit 0
fi

# --- Ensure local image is available ---
# The hash from the Dockerfile may refer to an image that exists only in the
# linuxkit cache (never loaded into the Docker daemon).  Fall back to the
# most-recently-pulled local eve-ubuntu image in that case.

if ! docker image inspect "lfedge/eve-ubuntu:${LOCAL_HASH}" >/dev/null 2>&1; then
    FALLBACK=$(docker images lfedge/eve-ubuntu --format '{{.Tag}}' \
               | grep -v 'amd64\|arm64\|riscv64' | head -1)
    if [ -n "${FALLBACK}" ]; then
        printf 'NOTE: lfedge/eve-ubuntu:%s not in local daemon; using %s instead.\n\n' \
               "${LOCAL_HASH}" "${FALLBACK}"
        LOCAL_HASH="${FALLBACK}"
    else
        die "Local image lfedge/eve-ubuntu:${LOCAL_HASH} is not available. Build pkg/ubuntu first (make ubuntu-cache-export-docker-load)."
    fi
fi

# --- Mirror index extraction ---
# Outputs "name version" lines sorted by name from the mirror inside the image.
# Returns non-zero and prints nothing if the image is unavailable.

extract_pkgs() {
    image="$1"     # image ref without arch suffix
    dtag="$2"      # docker arch suffix: amd64, arm64
    docker run --rm "${image}-${dtag}" sh -c \
        "zcat /mirror/archives/Packages.gz 2>/dev/null" \
        2>/dev/null \
    | awk '/^Package:/{p=$2} /^Version:/{if(p){print p" "$2}; p=""}' \
    | sort
}

# --- Per-architecture comparison ---

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

for DTAG in amd64 arm64; do
    LOCAL_FILE="${WORK_DIR}/local_${DTAG}.txt"
    MASTER_FILE="${WORK_DIR}/master_${DTAG}.txt"

    extract_pkgs "lfedge/eve-ubuntu:${LOCAL_HASH}"  "${DTAG}" > "${LOCAL_FILE}"  || true
    extract_pkgs "lfedge/eve-ubuntu:${MASTER_HASH}" "${DTAG}" > "${MASTER_FILE}" || true

    LOCAL_COUNT=$(wc -l < "${LOCAL_FILE}")
    MASTER_COUNT=$(wc -l < "${MASTER_FILE}")

    if [ "${LOCAL_COUNT}" -eq 0 ] && [ "${MASTER_COUNT}" -eq 0 ]; then
        printf '=== %s: skipped (neither image available locally) ===\n\n' "${DTAG}"
        continue
    fi

    printf '=== %s ===\n\n' "${DTAG}"
    printf 'Package count: master=%d  local=%d\n\n' "${MASTER_COUNT}" "${LOCAL_COUNT}"

    DIFF_OUT=$(diff "${MASTER_FILE}" "${LOCAL_FILE}" || true)

    if [ -z "${DIFF_OUT}" ]; then
        printf 'No differences.\n\n'
        continue
    fi

    printf '%-10s %-36s %-20s %s\n' "STATUS" "PACKAGE" "MASTER" "LOCAL"
    printf '%-10s %-36s %-20s %s\n' "------" "-------" "------" "-----"
    printf '%s\n' "${DIFF_OUT}" \
    | awk '
        /^< / { m[$2] = $3 }
        /^> / { l[$2] = $3 }
        END {
            for (pkg in l) {
                if (pkg in m) {
                    if (l[pkg] != m[pkg])
                        printf "CHANGED    %-36s %-20s %s\n", pkg, m[pkg], l[pkg]
                } else {
                    printf "ADDED      %-36s %-20s %s\n", pkg, "-", l[pkg]
                }
            }
            for (pkg in m) {
                if (!(pkg in l))
                    printf "REMOVED    %-36s %-20s %s\n", pkg, m[pkg], "-"
            }
        }' | sort -k2
    printf '\n'
done
