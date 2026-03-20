#!/bin/bash
#
# Prepare and run split-rootfs Eden tests.
#
# This script:
#   1. Builds good split-rootfs EVE OCI image v1
#   2. Builds good split-rootfs EVE OCI image v2
#   3. Builds a broken split-rootfs OCI image (corrupted ext-verity-roothash)
#   4. Pushes all required images to a registry
#   5. Sets up Eden with a stock monolithic EVE base
#   6. Runs the full split-rootfs workflow
#
# Prerequisites:
#   - Docker daemon running
#   - Docker Hub login (docker login) if using Docker Hub
#   - EVE repo with split-rootfs changes on current branch
#   - Eden repo checked out at ~/projects/eden (with split-rootfs tests)
#
# Usage:
#   # Full matrix: build v1 + v2 + broken, push them, setup Eden, run tests
#   ./tests/eden/prepare-split-rootfs-test.sh
#
#   # Reuse pre-built images and only run the full workflow
#   EVE_VERSION=<v1> EVE_VERSION_2=<v2> EVE_VERSION_BROKEN=<broken> SKIP_BUILD=1 \
#     ./tests/eden/prepare-split-rootfs-test.sh
#
#   # Skip the broken-image build and run the shorter 5-step workflow
#   BUILD_BROKEN=0 ./tests/eden/prepare-split-rootfs-test.sh
#
# Options:
#   REGISTRY_USER=<user>     Docker Hub username (default: auto-detect)
#   EVE_REGISTRY=<path>      Full registry path (default: <REGISTRY_USER>/eve)
#   EDEN_DIR=<path>          Path to Eden checkout (default: ~/projects/eden)
#   EVE_VERSION=<ver>        Pre-built good split v1
#   EVE_VERSION_2=<ver>      Pre-built good split v2
#   EVE_VERSION_BROKEN=<ver> Pre-built broken split image
#   BUILD_V2=0              Skip building v2 locally
#   BUILD_BROKEN=0          Skip building broken image locally
#   SKIP_BUILD=1            Skip EVE builds (reuse existing images)
#   SKIP_PUSH=1             Skip push (images already in registry)
#   SKIP_EDEN_SETUP=1       Skip Eden setup (already running)
#   SETUP_ONLY=1            Only build+push+setup, don't run tests
#   EVE_HV=<hv>             Hypervisor (default: kvm)
#   EVE_ARCH=<arch>         Architecture (default: amd64)
#   EDEN_TAG=<tag>          Eden version for fallback clone (default: 1.0.13)
#   KERNEL_TAG=<tag>        Custom kernel tag passed into make

set -e

PREFIX="[SPLIT-TEST]"

# ── Configuration ──────────────────────────────────────────────
EVE_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EDEN_DIR="${EDEN_DIR:-$HOME/projects/eden}"
EVE_HV="${EVE_HV:-kvm}"
EVE_ARCH="${EVE_ARCH:-amd64}"
EDEN_TAG="${EDEN_TAG:-1.0.13}"
BUILD_V2="${BUILD_V2:-1}"
BUILD_BROKEN="${BUILD_BROKEN:-1}"
RUNME_FILE="$EVE_ROOT/pkg/eve/runme.sh"
RUNME_BACKUP=""
WORKFLOW_SHORT="split-rootfs.tests.txt"
WORKFLOW_FULL="split-rootfs-full.tests.txt"
SUDO_KEEPALIVE_PID=""

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
[ -n "$KERNEL_TAG" ] && echo "  Kernel tag:   $KERNEL_TAG"
echo ""

restore_build_marker() {
    if [ -n "$RUNME_BACKUP" ] && [ -f "$RUNME_BACKUP" ]; then
        cp "$RUNME_BACKUP" "$RUNME_FILE"
        rm -f "$RUNME_BACKUP"
        RUNME_BACKUP=""
    fi
}

stop_sudo_keepalive() {
    if [ -n "$SUDO_KEEPALIVE_PID" ]; then
        kill "$SUDO_KEEPALIVE_PID" >/dev/null 2>&1 || true
        wait "$SUDO_KEEPALIVE_PID" >/dev/null 2>&1 || true
        SUDO_KEEPALIVE_PID=""
    fi
}

cleanup_script() {
    stop_sudo_keepalive
    restore_build_marker
}

trap cleanup_script EXIT INT TERM

wait_for_eve_ssh() {
    local attempts="${1:-60}"
    local delay="${2:-5}"
    local i=0

    echo "$PREFIX Waiting for base EVE SSH readiness..."
    while [ "$i" -lt "$attempts" ]; do
        if (cd "$EDEN_DIR" && ./eden eve ssh echo ssh-ready >/dev/null 2>&1); then
            echo "$PREFIX Base EVE SSH is ready."
            return 0
        fi
        sleep "$delay"
        i=$((i + 1))
    done

    echo "$PREFIX Error: base EVE SSH did not become ready after $((attempts * delay))s."
    return 1
}

ensure_sudo_keepalive() {
    if [ -n "$SUDO_KEEPALIVE_PID" ] && kill -0 "$SUDO_KEEPALIVE_PID" >/dev/null 2>&1; then
        return 0
    fi

    echo "$PREFIX Priming sudo credentials for disconnect rollback tests..."
    sudo -v

    (
        while true; do
            sleep 60
            sudo -n true >/dev/null 2>&1 || exit 0
        done
    ) &
    SUDO_KEEPALIVE_PID=$!
}

# Helper: get the actual built version from the dist/current symlink.
get_built_version() {
    local dist_current="$EVE_ROOT/dist/$EVE_ARCH/current"
    if [ -L "$dist_current" ]; then
        basename "$(readlink -f "$dist_current")"
    else
        echo "$PREFIX Warning: dist/current symlink not found, falling back to make version" >&2
        make -C "$EVE_ROOT" version
    fi
}

wait_for_next_utc_minute() {
    local now next sleep_for
    now=$(date -u +%s)
    next=$(( (now / 60 + 1) * 60 ))
    sleep_for=$(( next - now + 1 ))
    echo "$PREFIX Waiting ${sleep_for}s for the next UTC minute to get a unique dirty build version..."
    sleep "$sleep_for"
}

prepare_build_marker() {
    local label="$1"
    if [ ! -f "$RUNME_FILE" ]; then
        echo "$PREFIX Error: tracked runme file not found at $RUNME_FILE"
        exit 1
    fi
    if [ -z "$RUNME_BACKUP" ]; then
        RUNME_BACKUP=$(mktemp /tmp/split-rootfs-runme.XXXXXX)
        cp "$RUNME_FILE" "$RUNME_BACKUP"
    fi
    cp "$RUNME_BACKUP" "$RUNME_FILE"
    printf '\n# split-rootfs-%s-build-marker %s\n' "$label" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")-$$" >> "$RUNME_FILE"
}

build_split_image() {
    local label="$1"
    local with_pkgs="${2:-1}"
    local make_args=(UNIVERSAL=1)

    if [ -n "$KERNEL_TAG" ]; then
        make_args+=("KERNEL_TAG=$KERNEL_TAG")
    fi

    echo "================================================================"
    echo "$PREFIX Building split-rootfs EVE (${label})..."
    echo "================================================================"
    cd "$EVE_ROOT"

    if [ "$with_pkgs" = "1" ]; then
        make "${make_args[@]}" pkgs
    fi

    make "${make_args[@]}" eve-split

    LAST_BUILT_VERSION=$(get_built_version)
    echo "$PREFIX Built split-rootfs EVE ${label}: $LAST_BUILT_VERSION"
}

build_distinct_split_image() {
    local label="$1"
    local with_pkgs="${2:-0}"
    local previous_version="$3"

    if [[ "$previous_version" == *-dirty-* ]]; then
        wait_for_next_utc_minute
    fi

    prepare_build_marker "$label"
    build_split_image "$label" "$with_pkgs"

    if [ "$LAST_BUILT_VERSION" = "$previous_version" ]; then
        echo "$PREFIX ${label} matched ${previous_version} unexpectedly. Retrying after a minute rollover..."
        wait_for_next_utc_minute
        prepare_build_marker "${label}-retry"
        build_split_image "${label}-retry" "$with_pkgs"
    fi

    if [ "$LAST_BUILT_VERSION" = "$previous_version" ]; then
        echo "$PREFIX Error: failed to create a distinct ${label} split image version."
        exit 1
    fi
}

corrupt_split_image() {
    local ver="$1"
    local installer="$EVE_ROOT/dist/$EVE_ARCH/$ver/installer"
    local linuxkit="$EVE_ROOT/build-tools/bin/linuxkit"
    local hash first_char new_first corrupted offset

    if [ ! -f "$installer/ext-verity-roothash" ]; then
        echo "$PREFIX Error: ext-verity-roothash not found for $ver."
        exit 1
    fi

    echo "================================================================"
    echo "$PREFIX Corrupting ext-verity-roothash for broken image ($ver)..."
    echo "================================================================"

    cp "$installer/ext-verity-roothash" "$installer/ext-verity-roothash.good"

    hash=$(head -1 "$installer/ext-verity-roothash")
    first_char="${hash:0:1}"
    if [ "$first_char" = "0" ]; then
        new_first="f"
    else
        new_first="0"
    fi
    corrupted="${new_first}${hash:1}"
    offset=$(tail -1 "$installer/ext-verity-roothash")
    printf '%s\n%s\n' "$corrupted" "$offset" > "$installer/ext-verity-roothash"

    rm -f "$EVE_ROOT/dist/$EVE_ARCH/$ver/rootfs-core.tar" "$installer/rootfs-core.img"

    echo "$PREFIX Rebuilding core tar with corrupted roothash..."
    "$EVE_ROOT/tools/makerootfs.sh" tar -y "$EVE_ROOT/images/out/rootfs-kvm-core.yml" \
        -t "$EVE_ROOT/dist/$EVE_ARCH/$ver/rootfs-core.tar" \
        -d "$installer" -a "$EVE_ARCH"

    echo "$PREFIX Rebuilding core image with corrupted roothash..."
    "$EVE_ROOT/tools/makerootfs.sh" imagefromtar \
        -t "$EVE_ROOT/dist/$EVE_ARCH/$ver/rootfs-core.tar" \
        -i "$installer/rootfs-core.img" \
        -f squash -a "$EVE_ARCH"

    echo "$PREFIX Re-packaging OCI image..."
    cp -f "$installer/rootfs-core.img" "$installer/rootfs.img"
    cp "$EVE_ROOT"/images/out/*.yml "$EVE_ROOT/dist/$EVE_ARCH/$ver/"
    cp -f "$EVE_ROOT/pkg/eve/runme.sh" "$EVE_ROOT/dist/$EVE_ARCH/$ver/runme.sh"
    cp -f "$EVE_ROOT/pkg/eve/build.yml" "$EVE_ROOT/dist/$EVE_ARCH/$ver/build.yml"

    DOCKER_ARCH_TAG="$EVE_ARCH" KERNEL_TAG="${KERNEL_TAG}" PLATFORM=generic \
        "$EVE_ROOT/tools/parse-pkgs.sh" "$EVE_ROOT/pkg/eve/Dockerfile.in" > "$EVE_ROOT/dist/$EVE_ARCH/$ver/Dockerfile"
    sed -i 's|#SPLIT_ROOTFS_LABEL#|LABEL org.lfedge.eci.artifact.disk-0="/bits/rootfs-ext.img"|' "$EVE_ROOT/dist/$EVE_ARCH/$ver/Dockerfile"

    "$linuxkit" pkg build --platforms "linux/$EVE_ARCH" \
        --hash-path "$EVE_ROOT" \
        --hash "${ver}-${EVE_HV}" \
        --docker --force \
        "$EVE_ROOT/dist/$EVE_ARCH/$ver"

    rm -f "$installer/rootfs.img"
    mv "$installer/ext-verity-roothash.good" "$installer/ext-verity-roothash"
}

push_split_image() {
    local tag="$1"
    local label="$2"

    if ! docker image inspect "lfedge/eve:${tag}" > /dev/null 2>&1; then
        echo "$PREFIX Error: ${label} image lfedge/eve:${tag} not found locally."
        echo "         Build/tag it first, or run with SKIP_PUSH=1 if"
        echo "         docker.io/${EVE_REGISTRY}:${tag} already exists."
        exit 1
    fi

    echo "================================================================"
    echo "$PREFIX Pushing ${label} to docker.io/$EVE_REGISTRY:$tag"
    echo "================================================================"

    docker tag "lfedge/eve:${tag}" "docker.io/${EVE_REGISTRY}:${tag}"
    docker push "docker.io/${EVE_REGISTRY}:${tag}"
    echo "$PREFIX Pushed ${label}: docker.io/$EVE_REGISTRY:$tag"
}

choose_workflow_file() {
    if [ -n "$EVE_VERSION_2" ] && [ -n "$EVE_VERSION_BROKEN" ]; then
        echo "$WORKFLOW_FULL"
    else
        echo "$WORKFLOW_SHORT"
    fi
}

# ── Step 1: Build split-rootfs EVE images ─────────────────────
if [ -z "$SKIP_BUILD" ]; then
    build_split_image "v1" 1
    LOCAL_V1_VERSION="$LAST_BUILT_VERSION"
    EVE_VERSION="${EVE_VERSION:-$LOCAL_V1_VERSION}"
    echo "$PREFIX Using split-rootfs EVE v1: $EVE_VERSION"

    if [ "$BUILD_V2" != "0" ] && [ -z "$EVE_VERSION_2" ]; then
        build_distinct_split_image "v2" 0 "$LOCAL_V1_VERSION"
        LOCAL_V2_VERSION="$LAST_BUILT_VERSION"
        EVE_VERSION_2="$LOCAL_V2_VERSION"
        echo "$PREFIX Auto-built split-rootfs EVE v2: $EVE_VERSION_2"
    fi

    if [ "$BUILD_BROKEN" != "0" ] && [ -z "$EVE_VERSION_BROKEN" ]; then
        COMPARE_BASE="$LOCAL_V1_VERSION"
        if [ -n "$LOCAL_V2_VERSION" ]; then
            COMPARE_BASE="$LOCAL_V2_VERSION"
        elif [ -n "$EVE_VERSION_2" ]; then
            COMPARE_BASE="$EVE_VERSION_2"
        fi

        build_distinct_split_image "broken" 0 "$COMPARE_BASE"
        LOCAL_BROKEN_VERSION="$LAST_BUILT_VERSION"
        corrupt_split_image "$LOCAL_BROKEN_VERSION"
        EVE_VERSION_BROKEN="$LOCAL_BROKEN_VERSION"
        echo "$PREFIX Auto-built broken split image: $EVE_VERSION_BROKEN"
    fi

    restore_build_marker
else
    cd "$EVE_ROOT"

    if [ -z "$EVE_VERSION" ]; then
        EVE_VERSION=$(get_built_version)
    fi

    if [ "$BUILD_V2" != "0" ] && [ -z "$EVE_VERSION_2" ]; then
        echo "$PREFIX Error: BUILD_V2 requires local builds or EVE_VERSION_2 to be provided."
        exit 1
    fi

    if [ "$BUILD_BROKEN" != "0" ] && [ -z "$EVE_VERSION_BROKEN" ]; then
        echo "$PREFIX Error: BUILD_BROKEN requires local builds or EVE_VERSION_BROKEN to be provided."
        exit 1
    fi

    echo "$PREFIX Skipping build, using:"
    echo "  v1: $EVE_VERSION"
    [ -n "$EVE_VERSION_2" ] && echo "  v2: $EVE_VERSION_2"
    [ -n "$EVE_VERSION_BROKEN" ] && echo "  broken: $EVE_VERSION_BROKEN"
fi

SPLIT_TAG_V1="${EVE_VERSION}-${EVE_HV}-${EVE_ARCH}"
SPLIT_TAG_V2=""
SPLIT_TAG_BROKEN=""
[ -n "$EVE_VERSION_2" ] && SPLIT_TAG_V2="${EVE_VERSION_2}-${EVE_HV}-${EVE_ARCH}"
[ -n "$EVE_VERSION_BROKEN" ] && SPLIT_TAG_BROKEN="${EVE_VERSION_BROKEN}-${EVE_HV}-${EVE_ARCH}"

# ── Step 2: Push to registry ──────────────────────────────────
if [ -z "$SKIP_PUSH" ]; then
    push_split_image "$SPLIT_TAG_V1" "split v1"
    [ -n "$SPLIT_TAG_V2" ] && push_split_image "$SPLIT_TAG_V2" "split v2"
    [ -n "$SPLIT_TAG_BROKEN" ] && push_split_image "$SPLIT_TAG_BROKEN" "broken split"
else
    echo "$PREFIX Skipping push."
fi

# ── Step 3: Setup Eden ────────────────────────────────────────
SELECTED_WORKFLOW=$(choose_workflow_file)

if [ -z "$SKIP_EDEN_SETUP" ]; then
    echo "================================================================"
    echo "$PREFIX Setting up Eden from $EDEN_DIR"
    echo "================================================================"

    if [ ! -d "$EDEN_DIR" ]; then
        echo "$PREFIX Eden directory not found at $EDEN_DIR"
        echo "  Cloning Eden (tag $EDEN_TAG)..."
        git clone --branch "$EDEN_TAG" https://github.com/lf-edge/eden.git "$EDEN_DIR"
    fi

    if [ ! -f "$EDEN_DIR/tests/workflow/$SELECTED_WORKFLOW" ]; then
        echo "$PREFIX Warning: required workflow file $SELECTED_WORKFLOW not found in $EDEN_DIR"
        echo "         Make sure your Eden checkout has the split-rootfs workflows."
        exit 1
    fi

    cd "$EDEN_DIR"

    if [ ! -f "eden" ]; then
        echo "$PREFIX Building Eden binary..."
        make build
    else
        echo "$PREFIX Eden binary exists. Skipping build."
    fi

    if [ ! -f "dist/bin/eden.escript.test" ] || [ ! -f "dist/bin/eden.lim.test" ]; then
        echo "$PREFIX Building Eden test binaries..."
        make build-tests
    else
        echo "$PREFIX Eden test binaries exist. Skipping build-tests."
    fi

    if [ -f "eden" ]; then
        ./eden clean 2>/dev/null || true
    fi
    docker rm -f eden_adam eden_redis 2>/dev/null || true

    rm -rf dist/default-certs
    rm -rf "$HOME/.eden/certs"

    echo "$PREFIX Configuring Eden (default monolithic EVE from Docker Hub)..."
    ./eden config add default
    ./eden config set default --key=eve.accel --value=true
    ./eden config set default --key=eve.tpm --value=true

    ./dist/bin/eden+ports.sh 2223:2223 2224:2224 5912:5902 5911:5901 \
        8027:8027 8028:8028 8029:8029 8030:8030 8031:8031

    echo "$PREFIX Running eden setup (downloading monolithic EVE)..."
    ./eden setup

    echo "$PREFIX Starting Eden..."
    ./eden start

    echo "$PREFIX Onboarding EVE..."
    ./eden eve onboard
else
    echo "$PREFIX Skipping Eden setup."
    cd "$EDEN_DIR"
fi

wait_for_eve_ssh

if [ -n "$SETUP_ONLY" ]; then
    echo ""
    echo "$PREFIX Setup complete. To run tests manually:"
    echo ""
    echo "  cd $EDEN_DIR"
    echo "  EVE_VERSION=$EVE_VERSION \\"
    [ -n "$EVE_VERSION_2" ] && echo "  EVE_VERSION_2=$EVE_VERSION_2 \\"
    [ -n "$EVE_VERSION_BROKEN" ] && echo "  EVE_VERSION_BROKEN=$EVE_VERSION_BROKEN \\"
    echo "  EVE_REGISTRY=$EVE_REGISTRY \\"
    echo "    ./eden test ./tests/workflow -s $SELECTED_WORKFLOW -v debug"
    echo ""
    exit 0
fi

# ── Step 4: Run tests ─────────────────────────────────────────
if [ "$SELECTED_WORKFLOW" = "$WORKFLOW_FULL" ]; then
    ensure_sudo_keepalive
fi

echo "================================================================"
echo "$PREFIX Running split-rootfs tests"
echo "  EVE_VERSION=$EVE_VERSION"
[ -n "$EVE_VERSION_2" ] && echo "  EVE_VERSION_2=$EVE_VERSION_2"
[ -n "$EVE_VERSION_BROKEN" ] && echo "  EVE_VERSION_BROKEN=$EVE_VERSION_BROKEN"
echo "  EVE_REGISTRY=$EVE_REGISTRY"
echo "  Workflow=$SELECTED_WORKFLOW"
echo "================================================================"

cd "$EDEN_DIR"

export EVE_VERSION
export EVE_REGISTRY
[ -n "$EVE_VERSION_2" ] && export EVE_VERSION_2
[ -n "$EVE_VERSION_BROKEN" ] && export EVE_VERSION_BROKEN

if [ -n "$EVE_VERSION_2" ] && [ -n "$EVE_VERSION_BROKEN" ]; then
    ./eden test ./tests/workflow -s "$WORKFLOW_FULL" -v debug
elif [ -n "$EVE_VERSION_2" ]; then
    ./eden test ./tests/workflow -s "$WORKFLOW_SHORT" -v debug
else
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
