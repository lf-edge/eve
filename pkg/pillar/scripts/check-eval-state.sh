#!/bin/sh
#
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# check-eval-state.sh - Verification script for EVE-OS Evaluation Platform
#
# This script checks partition states and evaluation progress on hardware.
# Run it at any point during evaluation to see current state.

set -e

ESC=$(printf '\033')
RED="${ESC}[0;31m"
GREEN="${ESC}[0;32m"
YELLOW="${ESC}[1;33m"
BLUE="${ESC}[0;34m"
NC="${ESC}[0m"

echo "${BLUE}=====================================${NC}"
echo "${BLUE}EVE-OS Evaluation State Check${NC}"
echo "${BLUE}=====================================${NC}"
echo ""

# Detect platform
if [ -f /hostfs/etc/eve-platform ]; then
    PLATFORM=$(cat /hostfs/etc/eve-platform)
    echo "Platform: ${GREEN}${PLATFORM}${NC}"
else
    echo "Platform: ${RED}unknown (file missing)${NC}"
    PLATFORM="unknown"
fi

if [ "$PLATFORM" != "evaluation" ]; then
    echo ""
    echo "${YELLOW}WARNING: Not an evaluation platform!${NC}"
    echo "Evaluation features will not be active."
    echo ""
fi

# Find root disk
if [ -L /hostfs/dev/root ]; then
    ROOT_DEV=$(readlink -f /dev/root)
else
    ROOT_DEV=$(grep -m 1 / < /hostfs/proc/mounts | cut -d ' ' -f 1)
fi

# Get parent disk
DISK=$(lsblk -no pkname "$ROOT_DEV" 2>/dev/null | head -1)
if [ -z "$DISK" ]; then
    echo "${RED}ERROR: Cannot determine root disk${NC}"
    exit 1
fi
DISK_DEV="/dev/$DISK"

echo "Root disk: ${GREEN}${DISK_DEV}${NC}"
echo ""

# Function to decode partition attributes
decode_attr() {
    attr=$1
    # Convert to decimal if hex
    if echo "$attr" | grep -q "^0x"; then
        attr=$(printf "%d" "$attr")
    fi

    priority=$((attr & 0xF))
    tries=$(( (attr >> 4) & 0xF ))
    successful=$(( (attr >> 8) & 0x1 ))

    # Determine state name
    case "$attr" in
        0) state="bad" ;;
        19|0x13) state="scheduled" ;;
        3|0x3) state="inprogress" ;;
        258|0x102) state="good" ;;
        259|0x103) state="best" ;;
        *) state="unknown" ;;
    esac

    printf "0x%03x (p=%d t=%d s=%d) = %-10s" "$attr" "$priority" "$tries" "$successful" "$state"
}

# Find partition numbers for IMGA, IMGB, IMGC
echo "${BLUE}Partition States:${NC}"
echo "-----------------------------------"

for label in IMGA IMGB IMGC; do
    part_num=$(cgpt find -l "$label" -n "$DISK_DEV" 2>/dev/null || echo "")

    if [ -z "$part_num" ]; then
        echo "${label}: ${RED}NOT FOUND${NC}"
        continue
    fi

    attr=$(cgpt show -i "$part_num" -A "$DISK_DEV" 2>/dev/null || echo "0")
    decoded=$(decode_attr "$attr")

    # Color based on state
    if echo "$decoded" | grep -q "bad"; then
        color=$RED
    elif echo "$decoded" | grep -q "best"; then
        color=$GREEN
    elif echo "$decoded" | grep -q "good"; then
        color=$GREEN
    elif echo "$decoded" | grep -q "scheduled"; then
        color=$YELLOW
    elif echo "$decoded" | grep -q "inprogress"; then
        color=$YELLOW
    else
        color=$NC
    fi

    echo "${label} (part ${part_num}): ${color}${decoded}${NC}"
done

echo ""

# Check evalmgr status
echo "${BLUE}Evaluation Manager Status:${NC}"
echo "-----------------------------------"

if pgrep -x evalmgr > /dev/null; then
    echo "Process: ${GREEN}RUNNING${NC}"
    pid=$(pgrep -x evalmgr)
    echo "PID: $pid"
else
    echo "Process: ${RED}NOT RUNNING${NC}"
fi

# Check persistent state
if [ -f /persist/eval/state.json ]; then
    echo ""
    echo "${BLUE}Persistent State:${NC}"
    echo "-----------------------------------"

    if command -v jq >/dev/null 2>&1; then
        phase=$(jq -r '.phase // "unknown"' /persist/eval/state.json 2>/dev/null || echo "error")
        current_slot=$(jq -r '.current_slot // "unknown"' /persist/eval/state.json 2>/dev/null || echo "error")
        all_tried=$(jq -r '.all_tried // false' /persist/eval/state.json 2>/dev/null || echo "error")

        echo "Phase: ${YELLOW}${phase}${NC}"
        echo "Current Slot: ${YELLOW}${current_slot}${NC}"
        echo "All Tried: ${YELLOW}${all_tried}${NC}"

        echo ""
        echo "Slots:"
        for slot in IMGA IMGB IMGC; do
            tried=$(jq -r ".slots.\"$slot\".tried // false" /persist/eval/state.json 2>/dev/null || echo "false")
            successful=$(jq -r ".slots.\"$slot\".success // false" /persist/eval/state.json 2>/dev/null || echo "false")
            note=$(jq -r ".slots.\"$slot\".note // \"\"" /persist/eval/state.json 2>/dev/null || echo "")
            if [ -n "$note" ]; then
                echo "  $slot: tried=$tried successful=$successful ($note)"
            else
                echo "  $slot: tried=$tried successful=$successful"
            fi
        done
    else
        echo "${YELLOW}(jq not available, showing raw state)${NC}"
        cat /persist/eval/state.json
    fi
else
    echo ""
    echo "Persistent State: ${YELLOW}NOT FOUND${NC}"
    echo "(Normal on first boot)"
fi

# Check override file
echo ""
echo "${BLUE}Override Status:${NC}"
echo "-----------------------------------"

if [ -f /persist/eval/allow_onboard ]; then
    override=$(cat /persist/eval/allow_onboard)
    echo "Override file: ${YELLOW}EXISTS${NC} (value: $override)"
    if [ "$override" = "1" ] || [ "$override" = "true" ]; then
        echo "Effect: ${GREEN}Onboarding ALLOWED${NC}"
    else
        echo "Effect: ${RED}Onboarding BLOCKED${NC}"
    fi
else
    echo "Override file: ${GREEN}NOT SET${NC}"
fi

echo ""
echo "${BLUE}Expected State Based on Partitions:${NC}"
echo "-----------------------------------"

# Count partition states
scheduled_count=0
good_count=0
bad_count=0
best_count=0

for label in IMGA IMGB IMGC; do
    part_num=$(cgpt find -l "$label" -n "$DISK_DEV" 2>/dev/null || echo "")
    if [ -n "$part_num" ]; then
        attr=$(cgpt show -i "$part_num" -A "$DISK_DEV" 2>/dev/null || echo "0")
        attr_dec=$(printf "%d" "$attr" 2>/dev/null || echo "0")

        case "$attr_dec" in
            19) scheduled_count=$((scheduled_count + 1)) ;;
            258) good_count=$((good_count + 1)) ;;
            259) best_count=$((best_count + 1)) ;;
            0) bad_count=$((bad_count + 1)) ;;
        esac
    fi
done

echo "Scheduled: $scheduled_count"
echo "Good: $good_count"
echo "Best: $best_count"
echo "Bad: $bad_count"

echo ""
if [ "$scheduled_count" -eq 3 ]; then
    echo "${YELLOW}⚠ Initial state - evaluation not started yet${NC}"
    echo "   Next: Boot IMGA, test for 15 minutes"
elif [ "$best_count" -eq 1 ]; then
    echo "${GREEN}✓ Evaluation COMPLETE - finalized${NC}"
    echo "   Onboarding should be allowed"
elif [ "$good_count" -eq 3 ]; then
    echo "${YELLOW}⚠ All partitions tested, waiting for finalization${NC}"
    echo "   Next: Select best partition and finalize"
elif [ "$scheduled_count" -gt 0 ]; then
    tested=$((3 - scheduled_count))
    echo "${YELLOW}⚠ Evaluation IN PROGRESS ($tested/3 tested)${NC}"
    echo "   Next: Test remaining scheduled partitions"
else
    echo "${YELLOW}⚠ Unexpected state - check logs${NC}"
fi

echo ""
echo "${BLUE}=====================================${NC}"
echo "Tip: Run 'diag' for live status"
echo "     Check logs: tail -f /persist/newlog/devUpload/pillar.log | grep -i eval"
echo "${BLUE}=====================================${NC}"
