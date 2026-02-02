#!/bin/bash
#
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
set -e

# This assumes the script is run from the root of the EVE repository
EVE_ROOT=$(pwd)
EDEN_DEBUG_OPT=""
PREFIX="[EDEN_TEST]"
EDEN_TAG=${EDEN_TAG:-1.0.13}
EVE_FLAVOR=${EVE_FLAVOR:-kvm}
EVE_ARCH=${EVE_ARCH:-amd64}
USE_TPM=${USE_TPM:-true}
ACCEL=${ACCEL:-true}
DIST_DIR="$EVE_ROOT/dist/$EVE_ARCH/current"
EDEN_DIR="$DIST_DIR/eden"
EVE_TAG_BASE=$(basename "$(readlink -f "$DIST_DIR")")
EVE_TAG="${EVE_TAG_BASE}-${EVE_FLAVOR}-${EVE_ARCH}"

if ! docker image inspect "lfedge/eve:$EVE_TAG" > /dev/null 2>&1; then
   echo "$PREFIX Error: EVE image lfedge/eve:$EVE_TAG not found."
   echo "               Build EVE first : make eve"
   exit 1
fi

cleanup_stale_processes() {
    # Cleanup stale swtpm
    SWTPM_PID_FILE="$DIST_DIR/swtpm/swtpm.pid"
    if [ -f "$SWTPM_PID_FILE" ]; then
        echo "$PREFIX Checking for stale SWTPM process..."
        PID=$(cat "$SWTPM_PID_FILE")
        if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
            echo "$PREFIX Killing stale SWTPM process $PID..."
            kill "$PID" || true
        fi
        rm -f "$SWTPM_PID_FILE"
    fi

    # Cleanup stale QEMU
    EVE_PID_FILE="$EDEN_DIR/dist/default-eve.pid"
    if [ -f "$EVE_PID_FILE" ]; then
        echo "$PREFIX Checking for stale EVE (QEMU) process..."
        PID=$(cat "$EVE_PID_FILE")
        if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
            echo "$PREFIX Killing stale EVE (QEMU) process $PID..."
            kill "$PID" || true
        fi
        rm -f "$EVE_PID_FILE"
    fi
}

cleanup_eden() {
    if [ -f "$EDEN_DIR/eden" ]; then
        (cd "$EDEN_DIR" && ./eden clean 2>/dev/null) || true
    fi
    docker rm -f eden_adam eden_redis 2>/dev/null || true
    rm -rf "$EDEN_DIR" || true
}

# Cleanup stale Eden states (fix redis errors)
if [ -n "$EDEN_CLEANUP" ]; then
    echo "$PREFIX Cleaning up stale Eden containers and state..."
    cleanup_stale_processes
    cleanup_eden
fi

# Clone Eden
if [ -d "$EDEN_DIR" ]; then
    echo "$PREFIX Eden directory already exists."
else
    echo "$PREFIX Cloning Eden (tag $EDEN_TAG) into $EDEN_DIR..."
    if ! git clone --branch "$EDEN_TAG" https://github.com/lf-edge/eden.git "$EDEN_DIR"; then
        echo "$PREFIX Error: git clone failed."
        exit 1
    fi
fi

cd "$EDEN_DIR"
mkdir -p runlogs

# Build Eden and tests
if [ ! -f "eden" ]; then
    echo "$PREFIX Building Eden..."
    if ! make build > runlogs/build.log 2>&1; then
        echo "$PREFIX Error: make build failed. Read logs at $PWD/runlogs/build.log"
        exit 1
    fi
    if ! make build-tests > runlogs/build-tests.log 2>&1; then
        echo "$PREFIX Error: make build-tests failed. Read logs at $PWD/runlogs/build-tests.log"
        exit 1
    fi
else
    echo "$PREFIX Eden binary exists. Skipping build."
fi

# Set firmware location
if [ -f "$DIST_DIR/installer/firmware/OVMF_CODE.fd" ]; then
    FIRMWARE_Code="$DIST_DIR/installer/firmware/OVMF_CODE.fd"
    FIRMWARE_Vars="$DIST_DIR/installer/firmware/OVMF_VARS.fd"
elif [ -f "$DIST_DIR/firmware/OVMF_CODE.fd" ]; then
    FIRMWARE_Code="$DIST_DIR/firmware/OVMF_CODE.fd"
    FIRMWARE_Vars="$DIST_DIR/firmware/OVMF_VARS.fd"
else
    echo "$PREFIX Error: Firmware files not found in expected locations."
    exit 1
fi

if [ -n "$EDEN_DEBUG" ]; then
    EDEN_DEBUG_OPT="-v debug"
fi

# Configure Eden
echo "$PREFIX Configuring Eden..."
if ! {
    ./eden config add default
    ./eden config set default --key=eve.accel --value="$ACCEL"
    ./eden config set default --key=eve.tpm --value="$USE_TPM"
    ./eden config set default --key=eve.firmware --value="$FIRMWARE_Code $FIRMWARE_Vars"
    ./eden config set default --key=eve.tag --value="$EVE_TAG_BASE"
} > runlogs/config.log 2>&1; then
    echo "$PREFIX Error: eden config failed. Read logs at $PWD/runlogs/config.log"
    exit 1
fi

if ! ./dist/bin/eden+ports.sh 2223:2223 2224:2224 5912:5902 5911:5901 8027:8027 8028:8028 8029:8029 8030:8030 8031:8031 > runlogs/ports.log 2>&1; then
    echo "$PREFIX Error: eden ports mapping failed. Read logs at $PWD/runlogs/ports.log"
    exit 1
fi

# Cleanup stale processes before starting
cleanup_stale_processes

# Setup and Start EVE
echo "$PREFIX Setting up Eden..."
if ! ./eden setup "$EDEN_DEBUG_OPT" > runlogs/setup.log 2>&1; then
    echo "$PREFIX Error: eden setup failed."
    echo "        Try with EDEN_CLEANUP=1 to clean up stale state."
    echo "        Read logs at $PWD/runlogs/setup.log"
    exit 1
fi

echo "$PREFIX Starting Eden..."
if ! ./eden start "$EDEN_DEBUG_OPT" > runlogs/start.log 2>&1; then
    echo "$PREFIX Error: eden start failed"
    echo "        Try with EDEN_CLEANUP=1 to clean up stale state."
    echo "        Read logs at $PWD/runlogs/start.log"
    exit 1
fi

echo "$PREFIX Onboarding EVE..."
if ! ./eden eve onboard "$EDEN_DEBUG_OPT" 2>&1 | tee runlogs/onboard.log; then
    echo "$PREFIX Error: eden eve onboard failed."
    echo "        Try with EDEN_CLEANUP=1 to clean up stale state."
    echo "        Read logs at $PWD/runlogs/onboard.log"
    exit 1
fi

if [ -n "$SETUP_ONLY" ]; then
    echo "$PREFIX SETUP_ONLY is set. Skipping tests."
    exit 0
fi

############################################
#                Tests                     #
############################################
declare -A TEST_FILES
TEST_FILES[1]="smoke.tests.txt"
TEST_FILES[2]="networking.tests.txt"
TEST_FILES[3]="lps-loc.tests.txt"
TEST_FILES[4]="eve-upgrade.tests.txt"
TEST_FILES[5]="user-apps.tests.txt"
TEST_FILES[6]="virtualization.tests.txt"
TEST_FILES[7]="storage.tests.txt"

declare -A TEST_NAMES
TEST_NAMES[1]="Smoke Tests"
TEST_NAMES[2]="Networking Tests"
TEST_NAMES[3]="LPS/LOC Tests"
TEST_NAMES[4]="EVE Upgrade Tests"
TEST_NAMES[5]="User Application Tests"
TEST_NAMES[6]="Virtualization Tests"
TEST_NAMES[7]="Storage Tests"

TESTS_TO_RUN=""

if [ -n "$TEST_ALL" ]; then
    TESTS_TO_RUN="1 2 3 4 5 6 7"
else
    [ -n "$TEST_SMOKE" ] && TESTS_TO_RUN="$TESTS_TO_RUN 1"
    [ -n "$TEST_NET" ] && TESTS_TO_RUN="$TESTS_TO_RUN 2"
    [ -n "$TEST_LOC" ] && TESTS_TO_RUN="$TESTS_TO_RUN 3"
    [ -n "$TEST_UPGRADE" ] && TESTS_TO_RUN="$TESTS_TO_RUN 4"
    [ -n "$TEST_UAPP" ] && TESTS_TO_RUN="$TESTS_TO_RUN 5"
    [ -n "$TEST_VIRT" ] && TESTS_TO_RUN="$TESTS_TO_RUN 6"
    [ -n "$TEST_STORAGE" ] && TESTS_TO_RUN="$TESTS_TO_RUN 7"
fi

# If no tests selected via env vars, prompt user
if [ -z "$TESTS_TO_RUN" ]; then
    echo "================================================================"
    echo "Select tests to run (space-separated, e.g., '1 3 4'):"
    for i in {1..7}; do
        echo "$i - ${TEST_NAMES[$i]}"
    done
    echo "8 - All Tests"
    echo "Press Enter to run default (Smoke Tests only)"
    echo "================================================================"
    read -r -p "Selection: " USER_SELECTION

    if [ -z "$USER_SELECTION" ]; then
        TESTS_TO_RUN="1"
    elif [[ "$USER_SELECTION" == *"8"* ]]; then
        TESTS_TO_RUN="1 2 3 4 5 6 7"
    else
        TESTS_TO_RUN="$USER_SELECTION"
    fi
fi

# Run selected tests
for id in $TESTS_TO_RUN; do
    TEST_FILE="${TEST_FILES[$id]}"
    TEST_NAME="${TEST_NAMES[$id]}"
    if [ -n "$TEST_FILE" ]; then
        echo "================================================================"
        echo "$PREFIX Running $TEST_NAME ($TEST_FILE)..."
        LOG_NAME=$(echo "$TEST_NAME" | tr '[:upper:]' '[:lower:]' | tr ' ' '_')
        LOG_FILE="runlogs/${LOG_NAME}.log"
        # shellcheck disable=SC2086
        if ./eden test ./tests/workflow -s "$TEST_FILE" -v debug 2>&1 | tee "$LOG_FILE"; then
            echo "$PREFIX $TEST_NAME completed successfully."
        else
            echo "$PREFIX $TEST_NAME failed. logs at $PWD/$LOG_FILE"
        fi
        echo "================================================================"
    else
        echo "$PREFIX Warning: Invalid test ID selected: $id"
    fi
done
