#!/bin/bash
#
# Build a broken split-rootfs EVE image for rollback testing.
#
# Builds a split image where the ext-verity-roothash embedded in Core is
# corrupted (one byte flipped). The Extension image itself is valid, but
# dm-verity verification will fail because the hash doesn't match.
#
# Result: Core boots fine, extsloader finds Extension, but mount fails →
# nodeagent testing window expires → automatic rollback.
#
# Prerequisites:
#   - Docker Hub login
#   - Packages already built (make UNIVERSAL=1 pkgs)
#
# Usage:
#   ./tests/eden/prepare-broken-split-image.sh
#
# Options:
#   REGISTRY_USER=<user>   Docker Hub username (default: auto-detect)
#   EVE_REGISTRY=<path>    Full registry path (default: <REGISTRY_USER>/eve)
#   SKIP_PUSH=1            Don't push, just build
#   KERNEL_TAG=<tag>       Custom kernel tag (passed to make)

set -e

PREFIX="[BROKEN-SPLIT]"

EVE_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EVE_HV="${EVE_HV:-kvm}"
EVE_ARCH="${EVE_ARCH:-amd64}"

cd "$EVE_ROOT"

# Auto-detect Docker Hub username
if [ -z "$REGISTRY_USER" ]; then
    REGISTRY_USER=$(docker info 2>/dev/null | grep "Username:" | awk '{print $2}')
fi
if [ -z "$REGISTRY_USER" ] && [ -z "$SKIP_PUSH" ] && [ -z "$EVE_REGISTRY" ]; then
    echo "$PREFIX Error: Cannot detect Docker Hub username."
    exit 1
fi
EVE_REGISTRY="${EVE_REGISTRY:-${REGISTRY_USER}/eve}"

KERNEL_OPT=""
if [ -n "$KERNEL_TAG" ]; then
    KERNEL_OPT="KERNEL_TAG=$KERNEL_TAG"
fi

# ── Step 1: Build good split image first (ext + core + OCI) ─────────
echo "================================================================"
echo "$PREFIX Building good split image first..."
echo "================================================================"
make UNIVERSAL=1 $KERNEL_OPT eve-split

VER=$(basename "$(readlink -f dist/$EVE_ARCH/current)")
INSTALLER="dist/$EVE_ARCH/$VER/installer"

echo "$PREFIX Version: $VER"
echo "$PREFIX Installer: $INSTALLER"

if [ ! -f "$INSTALLER/ext-verity-roothash" ]; then
    echo "$PREFIX Error: ext-verity-roothash not found. Build failed."
    exit 1
fi

# ── Step 2: Corrupt the roothash ────────────────────────────────────
echo "$PREFIX Original roothash:"
cat "$INSTALLER/ext-verity-roothash"

echo "$PREFIX Corrupting ext-verity-roothash (flipping first byte)..."
cp "$INSTALLER/ext-verity-roothash" "$INSTALLER/ext-verity-roothash.good"

# Read the hash, flip the first hex char
HASH=$(head -1 "$INSTALLER/ext-verity-roothash")
FIRST_CHAR="${HASH:0:1}"
if [ "$FIRST_CHAR" = "0" ]; then
    NEW_FIRST="f"
else
    NEW_FIRST="0"
fi
CORRUPTED="${NEW_FIRST}${HASH:1}"
# Keep the second line (hash offset) intact
OFFSET=$(tail -1 "$INSTALLER/ext-verity-roothash")
printf '%s\n%s\n' "$CORRUPTED" "$OFFSET" > "$INSTALLER/ext-verity-roothash"

echo "$PREFIX Corrupted roothash:"
cat "$INSTALLER/ext-verity-roothash"

# ── Step 3: Rebuild ONLY Core tar + img + OCI with corrupted roothash ──
# We cannot call `make eve-split` because it would rebuild the ext image
# (new timestamp dir, fresh roothash overwrites our corruption).
# Instead, rebuild just the core tar, core img, and OCI packaging manually.
echo "================================================================"
echo "$PREFIX Rebuilding Core + OCI with corrupted roothash..."
echo "================================================================"

# Remove core tar and img to force rebuild
rm -f "dist/$EVE_ARCH/$VER/rootfs-core.tar" "$INSTALLER/rootfs-core.img"

# Rebuild core tar (linuxkit reads ext-verity-roothash from installer dir)
echo "$PREFIX Building core tar..."
./tools/makerootfs.sh tar -y images/out/rootfs-kvm-core.yml \
    -t "dist/$EVE_ARCH/$VER/rootfs-core.tar" \
    -d "$INSTALLER" -a "$EVE_ARCH"

# Rebuild core img from tar
echo "$PREFIX Building core img..."
./tools/makerootfs.sh imagefromtar \
    -t "dist/$EVE_ARCH/$VER/rootfs-core.tar" \
    -i "$INSTALLER/rootfs-core.img" \
    -f squash -a "$EVE_ARCH"

# Package OCI
echo "$PREFIX Packaging OCI..."
cp -f "$INSTALLER/rootfs-core.img" "$INSTALLER/rootfs.img"
cp images/out/*.yml "dist/$EVE_ARCH/$VER/"
cp -f pkg/eve/runme.sh "dist/$EVE_ARCH/$VER/runme.sh"
cp -f pkg/eve/build.yml "dist/$EVE_ARCH/$VER/build.yml"

LINUXKIT="build-tools/bin/linuxkit"
DOCKER_ARCH_TAG=$EVE_ARCH KERNEL_TAG="${KERNEL_TAG}" PLATFORM=generic \
    ./tools/parse-pkgs.sh pkg/eve/Dockerfile.in > "dist/$EVE_ARCH/$VER/Dockerfile"
sed -i 's|#SPLIT_ROOTFS_LABEL#|LABEL org.lfedge.eci.artifact.disk-0="/bits/rootfs-ext.img"|' "dist/$EVE_ARCH/$VER/Dockerfile"

$LINUXKIT pkg build --platforms "linux/$EVE_ARCH" \
    --hash-path "$EVE_ROOT" \
    --hash "${VER}-${EVE_HV}" \
    --docker --force \
    "dist/$EVE_ARCH/$VER"

rm -f "$INSTALLER/rootfs.img"

# ── Step 4: Restore good roothash ───────────────────────────────────
echo "$PREFIX Restoring good roothash..."
mv "$INSTALLER/ext-verity-roothash.good" "$INSTALLER/ext-verity-roothash"

# ── Step 5: Tag and push ────────────────────────────────────────────
TAG="${VER}-${EVE_HV}-${EVE_ARCH}"

echo "$PREFIX Built broken image: lfedge/eve:$TAG"

if [ -z "$SKIP_PUSH" ]; then
    echo "$PREFIX Pushing to docker.io/$EVE_REGISTRY:$TAG"
    docker tag "lfedge/eve:$TAG" "docker.io/$EVE_REGISTRY:$TAG"
    docker push "docker.io/$EVE_REGISTRY:$TAG"
    echo "$PREFIX Pushed: docker.io/$EVE_REGISTRY:$TAG"
fi

echo ""
echo "================================================================"
echo "$PREFIX Done."
echo "  Broken image version: $VER"
echo "  The Core rootfs has a corrupted ext-verity-roothash."
echo "  Extension image is valid but dm-verity will fail on mount."
echo ""
echo "  To test rollback:"
echo "    EVE_VERSION_BROKEN=$VER EVE_REGISTRY=$EVE_REGISTRY \\"
echo "      ./eden test ./tests/update_eve_image -v debug \\"
echo "      -r TestEdenScripts/update_split_broken_rollback"
echo "================================================================"
