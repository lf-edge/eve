#!/bin/bash
#
# Test split-rootfs installer (USB install path) with Eden.
#
# This script handles the setup (build, CONFIG injection, Eden config).
# Verification is done by the verify_split_install.txt escript.
#
# Usage:
#   # Default install (KVM, 60s GRUB timeout):
#   ./tests/eden/test-split-installer.sh
#
#   # Pre-parametrized Kubevirt (simulates ZFlash, no menu):
#   INSTALL_HV=k ./tests/eden/test-split-installer.sh
#
#   # Pre-parametrized Xen:
#   INSTALL_HV=xen ./tests/eden/test-split-installer.sh
#
#   # Skip build (reuse existing installer-split.raw):
#   SKIP_BUILD=1 ./tests/eden/test-split-installer.sh
#
# Options:
#   INSTALL_HV=<kvm|k|xen>  Pre-parametrize HV in CONFIG (default: none → GRUB timeout → KVM)
#   SKIP_BUILD=1             Skip building installer-split.raw
#   SKIP_EDEN_SETUP=1        Skip Eden setup (already running from previous test)
#   EDEN_DIR=<path>          Path to Eden checkout (default: ~/projects/eden)
#   EVE_ARCH=<arch>          Architecture (default: amd64)
#   KERNEL_TAG=<tag>         Custom kernel tag

set -e

PREFIX="[INSTALLER-TEST]"
EVE_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EDEN_DIR="${EDEN_DIR:-$HOME/projects/eden}"
EVE_ARCH="${EVE_ARCH:-amd64}"
INSTALL_HV="${INSTALL_HV:-}"
EXPECTED_HV="${INSTALL_HV:-kvm}"  # if no HV injected, GRUB timeout defaults to KVM
TESTDATA_DIR="$EVE_ROOT/tests/eden/testdata"

echo "$PREFIX Configuration:"
echo "  EVE repo:     $EVE_ROOT"
echo "  Eden dir:     $EDEN_DIR"
echo "  Arch:         $EVE_ARCH"
echo "  Install HV:   ${INSTALL_HV:-<none, GRUB timeout → KVM>}"
echo "  Expected HV:  $EXPECTED_HV"
[ -n "$KERNEL_TAG" ] && echo "  Kernel tag:   $KERNEL_TAG"
echo ""

# ── Step 1: Build installer-split.raw ─────────────────────────
if [ -z "$SKIP_BUILD" ]; then
    echo "================================================================"
    echo "$PREFIX Building installer-split.raw..."
    echo "================================================================"
    cd "$EVE_ROOT"

    MAKE_ARGS=()
    [ -n "$KERNEL_TAG" ] && MAKE_ARGS+=("KERNEL_TAG=$KERNEL_TAG")

    make "${MAKE_ARGS[@]}" pkgs
    make "${MAKE_ARGS[@]}" installer-split
else
    echo "$PREFIX Skipping build."
fi

cd "$EVE_ROOT"
DIST_CURRENT="$(readlink -f "dist/$EVE_ARCH/current")"
INSTALLER_RAW="$DIST_CURRENT/installer-split.raw"

# The HV=uni delegation may create a different dist dir than `current` points to.
# Search for the most recent installer-split.raw if not found at expected path.
if [ ! -f "$INSTALLER_RAW" ]; then
    INSTALLER_RAW=$(find "dist/$EVE_ARCH" -maxdepth 2 -name 'installer-split.raw' \
        -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2)
fi

if [ -z "$INSTALLER_RAW" ] || [ ! -f "$INSTALLER_RAW" ]; then
    echo "$PREFIX Error: installer-split.raw not found under dist/$EVE_ARCH/."
    echo "         Build first: make installer-split"
    exit 1
fi

echo "$PREFIX Installer image: $INSTALLER_RAW ($(du -h "$INSTALLER_RAW" | cut -f1))"

# ── Step 2: Inject HV into CONFIG if pre-parametrized ─────────
if [ -n "$INSTALL_HV" ]; then
    echo "$PREFIX Pre-parametrizing CONFIG with eve-hv-type=$INSTALL_HV"
    CONFIG_OFFSET=$(fdisk -l "$INSTALLER_RAW" 2>/dev/null | grep 'Microsoft basic data' | head -1 | awk '{print $2}')
    if [ -n "$CONFIG_OFFSET" ]; then
        CONFIG_OFFSET_BYTES=$((CONFIG_OFFSET * 512))
        echo -n "$INSTALL_HV" | MTOOLS_SKIP_CHECK=1 mcopy -i "$INSTALLER_RAW@@$CONFIG_OFFSET_BYTES" -o - ::eve-hv-type
        echo "$PREFIX Wrote eve-hv-type=$INSTALL_HV to CONFIG at offset $CONFIG_OFFSET_BYTES"
    else
        echo "$PREFIX Error: Could not find CONFIG partition in installer image."
        exit 1
    fi
fi

# ── Step 3: Setup Eden with custom installer ──────────────────
if [ -z "$SKIP_EDEN_SETUP" ]; then
    echo "================================================================"
    echo "$PREFIX Setting up Eden with custom installer..."
    echo "================================================================"

    if [ ! -d "$EDEN_DIR" ]; then
        echo "$PREFIX Error: Eden directory not found at $EDEN_DIR"
        exit 1
    fi

    cd "$EDEN_DIR"

    if [ ! -f "eden" ]; then
        echo "$PREFIX Building Eden binary..."
        make build
    fi

    if [ ! -f "dist/bin/eden.escript.test" ]; then
        echo "$PREFIX Building Eden test binaries..."
        make build-tests
    fi

    # Symlink installer to a short path — Unix sockets have 108-byte limit
    # and Eden puts swtpm socket alongside the image file.
    INSTALLER_SHORT="$EDEN_DIR/dist/installer-split.raw"
    ln -sf "$INSTALLER_RAW" "$INSTALLER_SHORT"
    echo "$PREFIX Symlinked installer to short path: $INSTALLER_SHORT"

    # Clean previous state
    ./eden stop 2>/dev/null || true
    ./eden clean --current-context 2>/dev/null || true
    docker rm -f eden_adam eden_redis eden_registry eden_eserver 2>/dev/null || true
    if [ -f "dist/default-eve.pid" ]; then
        kill "$(cat dist/default-eve.pid)" 2>/dev/null || true
        rm -f dist/default-eve.pid
    fi
    pkill -f "swtpm socket.*eden" 2>/dev/null || true
    rm -rf dist/default-images/eve/live.img dist/default-images/eve/live.raw.qcow2
    rm -f dist/default-eve.log
    rm -rf dist/default-certs "$HOME/.eden/certs"

    echo "$PREFIX Configuring Eden..."
    ./eden config add default
    ./eden config set default --key=eve.accel --value=true
    ./eden config set default --key=eve.tpm --value=true
    ./eden config set default --key=eve.custom-installer.path --value="$INSTALLER_SHORT"
    ./eden config set default --key=eve.custom-installer.format --value=raw
    ./eden config set default --key=eve.disks --value=1

    # Use EVE-built OVMF firmware (has TPM2 support).
    EVE_FW_DIR="$(dirname "$INSTALLER_RAW")/installer/firmware"
    if [ -f "$EVE_FW_DIR/OVMF_CODE.fd" ] && [ -f "$EVE_FW_DIR/OVMF_VARS.fd" ]; then
        echo "$PREFIX Using EVE-built OVMF firmware (TPM2-enabled)"
        ./eden config set default --key=eve.firmware --value="[\"$EVE_FW_DIR/OVMF_CODE.fd\",\"$EVE_FW_DIR/OVMF_VARS.fd\"]"
    else
        echo "$PREFIX Warning: EVE firmware not found at $EVE_FW_DIR, using Eden default"
    fi

    ./dist/bin/eden+ports.sh 2223:2223 2224:2224 5912:5902 5911:5901 \
        8027:8027 8028:8028 8029:8029 8030:8030 8031:8031

    echo "$PREFIX Running eden setup..."
    ./eden setup

    echo "$PREFIX Starting Eden (installer runs in foreground)..."
    ./eden start

    echo "$PREFIX Onboarding EVE..."
    ./eden eve onboard
else
    echo "$PREFIX Skipping Eden setup."
    cd "$EDEN_DIR"
fi

# ── Step 4: Wait for EVE to come online ───────────────────────
echo "$PREFIX Waiting for EVE to become reachable..."
ATTEMPTS=90
DELAY=10
i=0
while [ "$i" -lt "$ATTEMPTS" ]; do
    if ./eden eve ssh echo ssh-ready >/dev/null 2>&1; then
        echo "$PREFIX EVE is reachable via SSH."
        break
    fi
    sleep "$DELAY"
    i=$((i + 1))
done

if [ "$i" -ge "$ATTEMPTS" ]; then
    echo "$PREFIX Error: EVE did not become reachable after $((ATTEMPTS * DELAY))s."
    echo "$PREFIX Dumping serial log (last 50 lines):"
    tail -50 dist/default-eve.log 2>/dev/null || true
    exit 1
fi

# Give extsloader time to mount Extension and start services
echo "$PREFIX Waiting 60s for Extension services to start..."
sleep 60

# ── Step 5: Run verification escript ──────────────────────────
echo "================================================================"
echo "$PREFIX Running verification escript..."
echo "================================================================"

export EXPECTED_HV
./eden test "$EVE_ROOT/tests/eden" -v debug \
    -testdata "$TESTDATA_DIR" \
    -r "TestEdenScripts/verify_split_install"

echo ""
echo "================================================================"
echo "$PREFIX INSTALLER TEST PASSED (HV=$EXPECTED_HV)"
echo "================================================================"
