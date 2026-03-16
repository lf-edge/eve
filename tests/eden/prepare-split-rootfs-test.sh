#!/bin/bash
#
# Prepare and run split-rootfs Eden tests.
#
# This script:
#   1. Builds a split-rootfs EVE OCI image from the current branch
#   2. Pushes it to a Docker registry
#   3. Sets up Eden with a stock monolithic EVE base
#   4. Runs the split-rootfs test workflow
#
# Prerequisites:
#   - Docker daemon running
#   - Docker Hub login (docker login) if using Docker Hub
#   - EVE repo with split-rootfs changes on current branch
#   - Eden repo checked out at ~/projects/eden (with split-rootfs tests)
#
# Usage:
#   # Basic: monolith->split + rollback (one build)
#   ./tests/eden/prepare-split-rootfs-test.sh
#
#   # Full: also split->split (requires two pre-built versions)
#   EVE_VERSION=<v1> EVE_VERSION_2=<v2> SKIP_BUILD=1 \
#     ./tests/eden/prepare-split-rootfs-test.sh
#
# Options:
#   REGISTRY_USER=<user>   Docker Hub username (default: auto-detect)
#   EVE_REGISTRY=<path>    Full registry path (default: <REGISTRY_USER>/eve)
#   EDEN_DIR=<path>        Path to Eden checkout (default: ~/projects/eden)
#   EVE_VERSION=<ver>      Use pre-built split v1 instead of building
#   EVE_VERSION_2=<ver>    Pre-built split v2 for split->split tests
#   SKIP_BUILD=1           Skip EVE build (reuse existing image)
#   SKIP_PUSH=1            Skip push (image already in registry)
#   SKIP_EDEN_SETUP=1      Skip Eden setup (already running)
#   SETUP_ONLY=1           Only build+push+setup, don't run tests
#   EVE_HV=<hv>            Hypervisor (default: kvm)
#   EVE_ARCH=<arch>        Architecture (default: amd64)
#   EDEN_TAG=<tag>         Eden version for fallback clone (default: 1.0.13)

set -e

PREFIX="[SPLIT-TEST]"

# ── Configuration ──────────────────────────────────────────────
EVE_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EDEN_DIR="${EDEN_DIR:-$HOME/projects/eden}"
EVE_HV="${EVE_HV:-kvm}"
EVE_ARCH="${EVE_ARCH:-amd64}"
EDEN_TAG="${EDEN_TAG:-1.0.13}"

# Auto-detect Docker Hub username
if [ -z "$REGISTRY_USER" ]; then
    REGISTRY_USER=$(docker info 2>/dev/null | grep "Username:" | awk '{print $2}')
fi

if [ -z "$REGISTRY_USER" ] && [ -z "$SKIP_PUSH" ] && [ -z "$EVE_REGISTRY" ]; then
    echo "$PREFIX Error: Cannot detect Docker Hub username."
    echo "         Either run 'docker login' or set REGISTRY_USER=<user>"
    exit 1
fi

EVE_REGISTRY="${EVE_REGISTRY:-${REGISTRY_USER}/eve}"

echo "$PREFIX Configuration:"
echo "  EVE repo:     $EVE_ROOT"
echo "  Eden dir:     $EDEN_DIR"
echo "  Registry:     docker.io/$EVE_REGISTRY"
echo "  HV/Arch:      $EVE_HV/$EVE_ARCH"
echo ""

# Helper: get the actual built version from the dist/current symlink.
# This is stable (set at build time), unlike `make version` which
# regenerates the dirty timestamp on every call.
get_built_version() {
    local dist_current="$EVE_ROOT/dist/$EVE_ARCH/current"
    if [ -L "$dist_current" ]; then
        basename "$(readlink -f "$dist_current")"
    else
        echo "$PREFIX Warning: dist/current symlink not found, falling back to make version" >&2
        make -C "$EVE_ROOT" version
    fi
}

# ── Step 1: Build split-rootfs EVE ────────────────────────────
if [ -z "$SKIP_BUILD" ]; then
    echo "================================================================"
    echo "$PREFIX Building split-rootfs EVE (UNIVERSAL=1)..."
    echo "================================================================"
    cd "$EVE_ROOT"

    # Build packages first (includes eve-pillar-k for universal/split)
    make UNIVERSAL=1 pkgs

    # Build split OCI image
    make UNIVERSAL=1 eve-split

    # Use build version unless user overrode EVE_VERSION
    BUILD_VER=$(get_built_version)
    EVE_VERSION="${EVE_VERSION:-$BUILD_VER}"
    echo "$PREFIX Built split-rootfs EVE: $EVE_VERSION"
else
    cd "$EVE_ROOT"
    if [ -z "$EVE_VERSION" ]; then
        EVE_VERSION=$(get_built_version)
    fi
    echo "$PREFIX Skipping build, using: $EVE_VERSION"
fi

SPLIT_TAG_V1="${EVE_VERSION}-${EVE_HV}-${EVE_ARCH}"

# ── Step 2: Push to registry ──────────────────────────────────
if [ -z "$SKIP_PUSH" ]; then
    echo "================================================================"
    echo "$PREFIX Pushing to docker.io/$EVE_REGISTRY:$SPLIT_TAG_V1"
    echo "================================================================"

    docker tag "lfedge/eve:${SPLIT_TAG_V1}" \
               "docker.io/${EVE_REGISTRY}:${SPLIT_TAG_V1}"
    docker push "docker.io/${EVE_REGISTRY}:${SPLIT_TAG_V1}"

    echo "$PREFIX Pushed: docker.io/$EVE_REGISTRY:$SPLIT_TAG_V1"

    # Push v2 if provided and exists locally
    if [ -n "$EVE_VERSION_2" ]; then
        SPLIT_TAG_V2="${EVE_VERSION_2}-${EVE_HV}-${EVE_ARCH}"
        if docker image inspect "lfedge/eve:${SPLIT_TAG_V2}" > /dev/null 2>&1; then
            docker tag "lfedge/eve:${SPLIT_TAG_V2}" \
                       "docker.io/${EVE_REGISTRY}:${SPLIT_TAG_V2}"
            docker push "docker.io/${EVE_REGISTRY}:${SPLIT_TAG_V2}"
            echo "$PREFIX Pushed v2: docker.io/$EVE_REGISTRY:$SPLIT_TAG_V2"
        else
            echo "$PREFIX Warning: EVE_VERSION_2=$EVE_VERSION_2 image not found locally, skipping push"
        fi
    fi
else
    echo "$PREFIX Skipping push."
fi

# ── Step 3: Setup Eden ────────────────────────────────────────
if [ -z "$SKIP_EDEN_SETUP" ]; then
    echo "================================================================"
    echo "$PREFIX Setting up Eden from $EDEN_DIR"
    echo "================================================================"

    # Check Eden checkout exists and has tests
    if [ ! -d "$EDEN_DIR" ]; then
        echo "$PREFIX Eden directory not found at $EDEN_DIR"
        echo "  Cloning Eden (tag $EDEN_TAG)..."
        git clone --branch "$EDEN_TAG" https://github.com/lf-edge/eden.git "$EDEN_DIR"
    fi

    if [ ! -f "$EDEN_DIR/tests/workflow/split-rootfs.tests.txt" ]; then
        echo "$PREFIX Warning: split-rootfs test files not found in $EDEN_DIR"
        echo "         Make sure your Eden checkout has the split-rootfs tests."
        exit 1
    fi

    cd "$EDEN_DIR"

    # Build Eden if needed
    if [ ! -f "eden" ]; then
        echo "$PREFIX Building Eden..."
        make build
        make build-tests
    else
        echo "$PREFIX Eden binary exists. Skipping build."
    fi

    # Clean previous state if exists
    if [ -f "eden" ]; then
        ./eden clean 2>/dev/null || true
    fi
    docker rm -f eden_adam eden_redis 2>/dev/null || true

    # Remove stale certs so eden setup regenerates them everywhere
    # (eden setup skips generation if dist/default-certs exists,
    # but adam needs ~/.eden/certs which eden clean removes)
    rm -rf dist/default-certs
    rm -rf "$HOME/.eden/certs"

    # Configure (uses default monolithic EVE from Docker Hub)
    echo "$PREFIX Configuring Eden (default monolithic EVE from Docker Hub)..."
    ./eden config add default
    ./eden config set default --key=eve.accel --value=true
    ./eden config set default --key=eve.tpm --value=true

    # Port mappings
    ./dist/bin/eden+ports.sh 2223:2223 2224:2224 5912:5902 5911:5901 \
        8027:8027 8028:8028 8029:8029 8030:8030 8031:8031

    # Setup (pulls monolithic EVE from Docker Hub)
    echo "$PREFIX Running eden setup (downloading monolithic EVE)..."
    ./eden setup

    # Start
    echo "$PREFIX Starting Eden..."
    ./eden start

    # Onboard
    echo "$PREFIX Onboarding EVE..."
    ./eden eve onboard
else
    echo "$PREFIX Skipping Eden setup."
    cd "$EDEN_DIR"
fi

if [ -n "$SETUP_ONLY" ]; then
    echo ""
    echo "$PREFIX Setup complete. To run tests manually:"
    echo ""
    echo "  cd $EDEN_DIR"
    echo "  EVE_VERSION=$EVE_VERSION EVE_REGISTRY=$EVE_REGISTRY \\"
    echo "    ./eden test ./tests/workflow -s split-rootfs.tests.txt -v debug"
    echo ""
    exit 0
fi

# ── Step 4: Run tests ─────────────────────────────────────────
echo "================================================================"
echo "$PREFIX Running split-rootfs tests"
echo "  EVE_VERSION=$EVE_VERSION"
[ -n "$EVE_VERSION_2" ] && echo "  EVE_VERSION_2=$EVE_VERSION_2"
echo "  EVE_REGISTRY=$EVE_REGISTRY"
echo "================================================================"

cd "$EDEN_DIR"

export EVE_VERSION
export EVE_REGISTRY

if [ -n "$EVE_VERSION_2" ]; then
    export EVE_VERSION_2
    # Run the full workflow (all 5 scenarios)
    ./eden test ./tests/workflow -s split-rootfs.tests.txt -v debug
else
    # Without a second version, run only monolith->split and split->monolith
    echo "$PREFIX Running monolith->split upgrade..."
    ./eden test ./tests/update_eve_image -v debug \
        -r TestEdenScripts/update_eve_image_split

    echo "$PREFIX Running split->monolith rollback..."
    ./eden test ./tests/update_eve_image -v debug \
        -r TestEdenScripts/revert_split_to_monolithic
fi

echo ""
echo "================================================================"
echo "$PREFIX Tests complete!"
echo "================================================================"
