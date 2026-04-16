#!/bin/bash
#
# Test split-rootfs installer with Eden, covering all four pre-parametrized
# cases (kvm, k, k-zfs, xen) plus an optional no-predef GRUB-menu check.
#
# Per case:
#   1. Create a conf dir with eve-hv-type (no-predef: empty).
#   2. docker run lfedge/eve:<uni-tag> installer_raw  →  installer-<case>.raw.
#   3. Point Eden at the new installer, start fresh, wait for EVE.
#   4. Run verify_split_install escript with EXPECTED_HV=<hv>.
#
# Usage:
#   ./tests/eden/test-split-installer.sh                      # all 4 predefined cases
#   CASES="kvm xen"      ./tests/eden/test-split-installer.sh # subset
#   INCLUDE_MENU_CHECK=1 ./tests/eden/test-split-installer.sh # add no-predef menu case
#   SKIP_BUILD=1         ./tests/eden/test-split-installer.sh # reuse cached installer-<case>.raw
#   SKIP_REBOOT=1        ./tests/eden/test-split-installer.sh # skip post-reboot re-verify
#
# Env:
#   EVE_TAG        OCI tag to docker-run (default: latest local lfedge/eve:*-uni-amd64)
#   EDEN_DIR       Path to Eden checkout (default: ~/projects/eden)
#   EVE_ARCH       Architecture (default: amd64)
#   KERNEL_TAG     Custom kernel tag (forwarded to make when building OCI)

set -e

PREFIX="[INSTALLER-TEST]"
EVE_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EDEN_DIR="${EDEN_DIR:-$HOME/projects/eden}"
EVE_ARCH="${EVE_ARCH:-amd64}"
CASES="${CASES:-kvm k k-zfs xen}"
TESTDATA_DIR="$EDEN_DIR/tests/update_eve_image/testdata"

# Per-case HV value that ends up in CONFIG and on kernel cmdline.
hv_of() {
    case "$1" in
        kvm|xen) echo "$1" ;;
        k|k-zfs) echo "k" ;;
        menu)    echo "kvm" ;;  # no predef → GRUB timeout defaults to KVM
        *)       echo "UNKNOWN" ;;
    esac
}

# ── Step 0: discover the eve-split OCI tag ────────────────────
if [ -z "$EVE_TAG" ]; then
    EVE_TAG=$(docker images --format '{{.Repository}}:{{.Tag}}' \
        | grep -E '^lfedge/eve:.*-uni-amd64$' \
        | grep -v '<none>' \
        | head -1)
fi

if [ -z "$EVE_TAG" ] && [ -z "$SKIP_BUILD" ]; then
    echo "$PREFIX No local lfedge/eve:*-uni-amd64 image; running 'make eve-split'..."
    cd "$EVE_ROOT"
    MAKE_ARGS=()
    [ -n "$KERNEL_TAG" ] && MAKE_ARGS+=("KERNEL_TAG=$KERNEL_TAG")
    make "${MAKE_ARGS[@]}" eve-split
    EVE_TAG=$(docker images --format '{{.Repository}}:{{.Tag}}' \
        | grep -E '^lfedge/eve:.*-uni-amd64$' \
        | grep -v '<none>' \
        | head -1)
fi

if [ -z "$EVE_TAG" ]; then
    echo "$PREFIX Error: no lfedge/eve:*-uni-amd64 image found and SKIP_BUILD=1."
    exit 1
fi

[ -d "$EDEN_DIR" ] || { echo "$PREFIX Error: EDEN_DIR not found at $EDEN_DIR"; exit 1; }
[ -d "$TESTDATA_DIR" ] || { echo "$PREFIX Error: verify testdata not found at $TESTDATA_DIR"; exit 1; }

CACHE_DIR="$EVE_ROOT/dist/$EVE_ARCH/installer-cases"
mkdir -p "$CACHE_DIR"

if [ -n "$INCLUDE_MENU_CHECK" ]; then
    CASES="$CASES menu"
fi

echo "$PREFIX Configuration:"
echo "  EVE repo:    $EVE_ROOT"
echo "  Eden dir:    $EDEN_DIR"
echo "  OCI tag:     $EVE_TAG"
echo "  Cases:       $CASES"
echo "  Cache dir:   $CACHE_DIR"
echo ""

# ── Build per-case installers via docker run installer_raw ────
build_case_installer() {
    local case_name="$1"
    local out="$CACHE_DIR/installer-$case_name.raw"

    if [ -n "$SKIP_BUILD" ] && [ -f "$out" ]; then
        echo "$PREFIX [$case_name] Reusing cached $out"
        return
    fi

    local conf_dir="$CACHE_DIR/conf-$case_name"
    rm -rf "$conf_dir"; mkdir -p "$conf_dir"

    case "$case_name" in
        kvm|xen)  echo -n "$case_name" > "$conf_dir/eve-hv-type" ;;
        k|k-zfs)  echo -n "k"         > "$conf_dir/eve-hv-type" ;;
        menu)     ;;  # empty conf → GRUB menu shown
        *)        echo "$PREFIX Unknown case: $case_name"; return 1 ;;
    esac

    echo "$PREFIX [$case_name] Building installer via docker run..."
    docker run --rm -v "$conf_dir:/in" "$EVE_TAG" installer_raw > "$out"
    echo "$PREFIX [$case_name] Produced $(du -h "$out" | cut -f1) at $out"
}

# ── Run a single case through Eden ────────────────────────────
run_case() {
    local case_name="$1"
    local expected_hv; expected_hv=$(hv_of "$case_name")
    local raw="$CACHE_DIR/installer-$case_name.raw"
    local disks=1
    [ "$case_name" = "k-zfs" ] && disks=2

    echo ""
    echo "================================================================"
    echo "$PREFIX [$case_name] Expected HV=$expected_hv  disks=$disks"
    echo "================================================================"

    cd "$EDEN_DIR"
    [ -f "eden" ]                 || make build
    [ -f "dist/bin/eden.escript.test" ] || make build-tests

    # Fresh Eden state per case. Let eden stop/clean handle swtpm + certs;
    # avoid manual pkill / cert wipe which race with eden setup.
    ./eden stop 2>/dev/null || true
    ./eden clean --current-context 2>/dev/null || true
    docker rm -f eden_adam eden_redis eden_registry eden_eserver 2>/dev/null || true
    [ -f dist/default-eve.pid ] && { kill "$(cat dist/default-eve.pid)" 2>/dev/null || true; rm -f dist/default-eve.pid; }
    rm -f  dist/default-images/eve/live.img dist/default-images/eve/live.raw.qcow2 dist/default-eve.log
    # If a stale swtpm holds the socket path, only remove the socket file, not the process.
    rm -f dist/swtpm/swtpm-sock 2>/dev/null || true

    local short="$EDEN_DIR/dist/installer-current.raw"
    ln -sfn "$raw" "$short"

    ./eden config add default
    ./eden config set default --key=eve.accel --value=true
    ./eden config set default --key=eve.tpm --value=true
    ./eden config set default --key=eve.custom-installer.path --value="$short"
    ./eden config set default --key=eve.custom-installer.format --value=raw
    ./eden config set default --key=eve.disks --value="$disks"

    # Use EVE-built OVMF (TPM2-enabled).
    local fw_dir
    fw_dir="$(dirname "$raw")/../installer/firmware"
    if [ -f "$fw_dir/OVMF_CODE.fd" ] && [ -f "$fw_dir/OVMF_VARS.fd" ]; then
        ./eden config set default --key=eve.firmware \
            --value="[\"$fw_dir/OVMF_CODE.fd\",\"$fw_dir/OVMF_VARS.fd\"]"
    fi

    ./dist/bin/eden+ports.sh 2223:2223 2224:2224 5912:5902 5911:5901 \
        8027:8027 8028:8028 8029:8029 8030:8030 8031:8031

    ./eden setup

    # Wait for the cert eden setup should regenerate, to avoid onboard racing it.
    local certs_i=0
    while [ "$certs_i" -lt 30 ] && [ ! -f "$HOME/.eden/certs/root-certificate.pem" ]; do
        sleep 1; certs_i=$((certs_i+1))
    done
    if [ ! -f "$HOME/.eden/certs/root-certificate.pem" ]; then
        echo "$PREFIX [$case_name] eden setup did not produce ~/.eden/certs — aborting case"
        return 1
    fi

    ./eden start

    # Give swtpm a moment to create its socket before any QEMU-dependent step.
    local sock_i=0
    while [ "$sock_i" -lt 15 ] && [ ! -S "$EDEN_DIR/dist/swtpm/swtpm-sock" ]; do
        sleep 1; sock_i=$((sock_i+1))
    done
    if [ ! -S "$EDEN_DIR/dist/swtpm/swtpm-sock" ]; then
        echo "$PREFIX [$case_name] swtpm socket missing after 15s (eden.tpm=true) — check eden start logs"
        tail -40 dist/default-eve.log 2>/dev/null || true
        return 1
    fi

    ./eden eve onboard

    echo "$PREFIX [$case_name] Waiting for EVE SSH..."
    local i=0
    while [ "$i" -lt 90 ]; do
        ./eden eve ssh echo ssh-ready >/dev/null 2>&1 && break
        sleep 10; i=$((i+1))
    done
    if [ "$i" -ge 90 ]; then
        echo "$PREFIX [$case_name] EVE did not come online. Last serial log:"
        tail -80 dist/default-eve.log 2>/dev/null || true
        return 1
    fi

    # GRUB menu visibility: restrict to the current QEMU session (serial log
    # is append-mode, so entries from previous cases may be present).
    local menu_shown=0
    if [ -f dist/default-eve.log ] && \
       tac dist/default-eve.log | sed '/swtpm is starting/q' | tac \
         | grep -q "Boot/Install EVE (KVM)"; then
        menu_shown=1
    fi

    if [ "$case_name" = "menu" ]; then
        if [ "$menu_shown" -ne 1 ]; then
            echo "$PREFIX [menu] FAIL: GRUB menu was NOT shown (expected shown)."
            return 1
        fi
        echo "$PREFIX [menu] OK: GRUB menu shown."
    else
        if [ "$menu_shown" -ne 0 ]; then
            echo "$PREFIX [$case_name] FAIL: GRUB menu leaked (should be bypassed when predefined)."
            return 1
        fi
    fi

    echo "$PREFIX [$case_name] Waiting 60s for Extension services..."
    sleep 60

    local expected_persist_fs=""
    [ "$case_name" = "k-zfs" ] && expected_persist_fs="zfs"

    echo "$PREFIX [$case_name] First-boot verification..."
    EXPECTED_HV="$expected_hv" EXPECTED_PERSIST_FS="$expected_persist_fs" \
        ./eden test "$EDEN_DIR/tests/update_eve_image" -v debug \
        -testdata "$TESTDATA_DIR" \
        -r "TestEdenScripts/verify_split_install"

    if [ -z "$SKIP_REBOOT" ]; then
        echo "$PREFIX [$case_name] Rebooting installed system to verify second boot..."
        ./eden eve ssh 'nohup sh -c "sleep 2 && reboot" >/dev/null 2>&1 &' || true

        # Wait for the device to go down, then come back.
        local wait_i=0
        while [ "$wait_i" -lt 30 ]; do
            ./eden eve ssh echo down-probe >/dev/null 2>&1 || break
            sleep 2; wait_i=$((wait_i+1))
        done
        echo "$PREFIX [$case_name] Device went down at $((wait_i*2))s; waiting for reboot to complete..."

        wait_i=0
        while [ "$wait_i" -lt 90 ]; do
            ./eden eve ssh echo up-probe >/dev/null 2>&1 && break
            sleep 5; wait_i=$((wait_i+1))
        done
        if [ "$wait_i" -ge 90 ]; then
            echo "$PREFIX [$case_name] FAIL: device did not come back up after reboot"
            tail -60 dist/default-eve.log 2>/dev/null || true
            return 1
        fi
        echo "$PREFIX [$case_name] Device back up; waiting 45s for Extension services..."
        sleep 45

        echo "$PREFIX [$case_name] Post-reboot verification..."
        EXPECTED_HV="$expected_hv" EXPECTED_PERSIST_FS="$expected_persist_fs" \
            ./eden test "$EDEN_DIR/tests/update_eve_image" -v debug \
            -testdata "$TESTDATA_DIR" \
            -r "TestEdenScripts/verify_split_install"
    fi

    echo "$PREFIX [$case_name] PASSED"
}

# ── Main ──────────────────────────────────────────────────────
failures=()
for case_name in $CASES; do
    build_case_installer "$case_name" || { failures+=("$case_name:build"); continue; }
done

for case_name in $CASES; do
    [ -f "$CACHE_DIR/installer-$case_name.raw" ] || continue
    if ! run_case "$case_name"; then
        failures+=("$case_name:run")
    fi
done

echo ""
echo "================================================================"
if [ "${#failures[@]}" -eq 0 ]; then
    echo "$PREFIX ALL CASES PASSED ($CASES)"
    exit 0
else
    echo "$PREFIX FAILURES: ${failures[*]}"
    exit 1
fi
