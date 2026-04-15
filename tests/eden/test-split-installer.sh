#!/bin/bash
#
# Test split-rootfs installer (USB install path).
#
# This script tests the full installer flow:
#   1. Builds installer-split.raw (universal image, HV=uni)
#   2. Optionally injects a pre-defined HV type into CONFIG (simulates ZFlash)
#   3. Sets up Eden with custom-installer.path
#   4. Eden boots the installer in QEMU, installs to target disk, reboots
#   5. Verifies: CONFIG HV type, Extension mounted, services running, PCR12
#
# Usage:
#   # Default install (KVM, 60s timeout):
#   ./tests/eden/test-split-installer.sh
#
#   # Pre-parametrized Kubevirt (simulates ZFlash):
#   INSTALL_HV=k ./tests/eden/test-split-installer.sh
#
#   # Pre-parametrized Xen:
#   INSTALL_HV=xen ./tests/eden/test-split-installer.sh
#
#   # Skip build (reuse existing installer-split.raw):
#   SKIP_BUILD=1 ./tests/eden/test-split-installer.sh
#
# Options:
#   INSTALL_HV=<kvm|k|xen>  Pre-parametrize HV in CONFIG (default: none, uses GRUB timeout → KVM)
#   SKIP_BUILD=1             Skip building installer-split.raw
#   EDEN_DIR=<path>          Path to Eden checkout (default: ~/projects/eden)
#   EVE_ARCH=<arch>          Architecture (default: amd64)
#   KERNEL_TAG=<tag>         Custom kernel tag

set -e

PREFIX="[INSTALLER-TEST]"
EVE_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EDEN_DIR="${EDEN_DIR:-$HOME/projects/eden}"
EVE_ARCH="${EVE_ARCH:-amd64}"
INSTALL_HV="${INSTALL_HV:-}"  # empty = interactive (timeout → KVM)

echo "$PREFIX Configuration:"
echo "  EVE repo:     $EVE_ROOT"
echo "  Eden dir:     $EDEN_DIR"
echo "  Arch:         $EVE_ARCH"
echo "  Install HV:   ${INSTALL_HV:-<none, GRUB timeout → KVM>}"
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
INSTALLER_RAW="$DIST_CURRENT/installer/installer-split.raw"

if [ ! -f "$INSTALLER_RAW" ]; then
    echo "$PREFIX Error: $INSTALLER_RAW not found. Build first or check SKIP_BUILD."
    exit 1
fi

echo "$PREFIX Installer image: $INSTALLER_RAW ($(du -h "$INSTALLER_RAW" | cut -f1))"

# ── Step 2: Inject HV into CONFIG if pre-parametrized ─────────
if [ -n "$INSTALL_HV" ]; then
    echo "$PREFIX Pre-parametrizing CONFIG with eve-hv-type=$INSTALL_HV"

    # Find the CONFIG partition inside the installer raw image.
    # The CONFIG partition is a FAT image embedded in the GPT layout.
    # We need to extract it, modify it, and put it back.
    # Simpler approach: use mcopy directly on the installer raw image's
    # CONFIG partition. First, find the CONFIG partition offset.
    CONFIG_OFFSET=$(fdisk -l "$INSTALLER_RAW" 2>/dev/null | grep 'EBD0A0A2' | head -1 | awk '{print $2}')
    if [ -z "$CONFIG_OFFSET" ]; then
        # Fallback: look for the small FAT partition (CONFIG is ~1MB)
        CONFIG_OFFSET=$(fdisk -l "$INSTALLER_RAW" 2>/dev/null | grep 'Microsoft basic data' | head -1 | awk '{print $2}')
    fi

    if [ -n "$CONFIG_OFFSET" ]; then
        CONFIG_OFFSET_BYTES=$((CONFIG_OFFSET * 512))
        echo -n "$INSTALL_HV" | MTOOLS_SKIP_CHECK=1 mcopy -i "$INSTALLER_RAW@@$CONFIG_OFFSET_BYTES" -o - ::eve-hv-type
        echo "$PREFIX Wrote eve-hv-type=$INSTALL_HV to CONFIG at offset $CONFIG_OFFSET_BYTES"
    else
        echo "$PREFIX Warning: Could not find CONFIG partition in installer image."
        echo "         Falling back to modifying config.img and rebuilding."
        CONFIG_IMG="$DIST_CURRENT/installer/config.img"
        if [ -f "$CONFIG_IMG" ]; then
            echo -n "$INSTALL_HV" | MTOOLS_SKIP_CHECK=1 mcopy -i "$CONFIG_IMG" -o - ::eve-hv-type
            echo "$PREFIX Wrote eve-hv-type=$INSTALL_HV to config.img"
            echo "$PREFIX Warning: config.img modified but installer-split.raw not rebuilt."
            echo "         Re-run without SKIP_BUILD for a clean test."
        else
            echo "$PREFIX Error: Cannot inject HV type. No CONFIG partition found."
            exit 1
        fi
    fi
fi

# ── Step 3: Setup Eden with custom installer ──────────────────
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
./eden config set default --key=eve.custom-installer.path --value="$INSTALLER_RAW"
./eden config set default --key=eve.custom-installer.format --value=raw
./eden config set default --key=eve.disks --value=1

./dist/bin/eden+ports.sh 2223:2223 2224:2224 5912:5902 5911:5901 \
    8027:8027 8028:8028 8029:8029 8030:8030 8031:8031

echo "$PREFIX Running eden setup..."
./eden setup

echo "$PREFIX Starting Eden (installer will run in foreground)..."
./eden start

echo "$PREFIX Onboarding EVE..."
./eden eve onboard

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
    echo "$PREFIX Dumping QEMU serial log (last 100 lines):"
    tail -100 dist/default-eve.log 2>/dev/null || true
    exit 1
fi

# Give services time to start after SSH becomes available
echo "$PREFIX Waiting 120s for Extension services to start..."
sleep 120

# ── Step 5: Verify installation ───────────────────────────────
echo "================================================================"
echo "$PREFIX Verifying installation..."
echo "================================================================"

EXPECTED_HV="${INSTALL_HV:-kvm}"
PASS=0
FAIL=0

check() {
    local desc="$1"
    local cmd="$2"
    local expected="$3"

    echo -n "  $desc... "
    result=$(./eden eve ssh "$cmd" 2>/dev/null) || result="SSH_ERROR"

    if echo "$result" | grep -q "$expected"; then
        echo "OK"
        PASS=$((PASS + 1))
    else
        echo "FAIL (expected '$expected', got '$result')"
        FAIL=$((FAIL + 1))
    fi
}

# CONFIG has correct HV type
check "CONFIG eve-hv-type" \
    "cat /config/eve-hv-type" \
    "$EXPECTED_HV"

# Runtime eve-hv-type resolved correctly
check "Runtime /run/eve-hv-type" \
    "cat /run/eve-hv-type" \
    "$EXPECTED_HV"

# Extension image exists on persist
check "Extension image on persist" \
    "ls -la /persist/ext-imga.img 2>/dev/null && echo ext-exists || echo ext-missing" \
    "ext-exists"

# dm-verity device active
check "dm-verity device active" \
    "eve exec pillar dmsetup status 2>/dev/null | grep -c verity || echo 0" \
    "1"

# Extension mount point
check "Extension mounted" \
    "eve exec pillar mount | grep -c '/persist/exts' || echo 0" \
    "1"

# extsloader state
check "extsloader state ready" \
    "eve exec pillar cat /run/extsloader-state.json 2>/dev/null | grep -o '\"state\":\"[^\"]*\"' || echo state-unknown" \
    '"state":"ready"'

# Core has ext-verity-roothash
check "Core has ext-verity-roothash" \
    "test -f /hostfs/etc/ext-verity-roothash && echo has-roothash || echo no-roothash" \
    "has-roothash"

# PCR12 is non-zero (TPM measurement)
check "PCR12 non-zero" \
    "eve exec pillar tpm2_pcrread sha256:12 2>/dev/null | grep -c '0x0000000000000000000000000000000000000000000000000000000000000000' || echo non-zero" \
    "non-zero"

# EFI variable written
check "EFI variable written" \
    "ls /sys/firmware/efi/efivars/eve-hv-type-* 2>/dev/null && echo efi-var-exists || echo no-efi-var" \
    "efi-var-exists"

# Partition sizing for Kubevirt
if [ "$EXPECTED_HV" = "k" ]; then
    check "EFI partition >= 2GB (kubevirt)" \
        "lsblk -b -n -o SIZE \$(lsblk -n -o NAME,PARTLABEL | grep 'EFI System' | awk '{print \"/dev/\"\$1}' | head -1) 2>/dev/null || echo 0" \
        "214748"  # 2GB = 2147483648, check prefix

    check "ZFS persist (kubevirt)" \
        "zfs list persist 2>/dev/null && echo zfs-ok || echo no-zfs" \
        "zfs-ok"
fi

echo ""
echo "================================================================"
echo "$PREFIX Results: $PASS passed, $FAIL failed"
echo "================================================================"

if [ "$FAIL" -gt 0 ]; then
    echo "$PREFIX SOME CHECKS FAILED"
    exit 1
else
    echo "$PREFIX ALL CHECKS PASSED"
fi
