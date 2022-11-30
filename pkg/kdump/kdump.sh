#!/bin/sh
#
# SPDX-License-Identifier: Apache-2.0

if test -f /proc/vmcore; then
    #
    # We are in dump capture kernel, nice.
    #
    MAX=5
    DIR=/persist/kcrashes

    # Create a folder
    mkdir $DIR > /dev/null 2<&1

    # Keep $MAX-1 fresh dumps
    # shellcheck disable=SC2012
    ls -t $DIR | tail -n +$MAX | xargs --no-run-if-empty -I '{}' rm $DIR/{}

    # Get kernel panic from the dmesg of a crashed kernel
    makedumpfile --dump-dmesg /proc/vmcore /tmp/dmesg > /dev/null
    sed -n -e '/Kernel panic - not syncing/,$p' /tmp/dmesg > /tmp/backtrace

    # Show backtrace from the dmesg of a crashed kernel
    echo ">>>>>>>>>> Crashed kernel dmesg BEGIN <<<<<<<<<<" > /dev/kmsg
    while read -r line; do echo "$line" > /dev/kmsg; done < /tmp/backtrace
    echo ">>>>>>>>>> Crashed kernel dmesg END <<<<<<<<<<" > /dev/kmsg

    TS=$(date +%Y-%m-%d-%H-%M-%S)

    # Collect a minimal kernel dump for security reasons
    KDUMP_PATH="$DIR/kdump-$TS.dump"
    makedumpfile -d 31 /proc/vmcore "$KDUMP_PATH" > /dev/null 2>&1
    echo "kdump collected: $KDUMP_PATH" > /dev/kmsg

    # Collect dmesg
    DMESG_PATH="$DIR/dmesg-$TS.log"
    cp /tmp/dmesg "$DMESG_PATH"
    echo "dmesg collected: $DMESG_PATH" > /dev/kmsg

    # Prepare reboot-reason, reboot-stack and boot-reason
    echo "kernel panic, kdump collected: $KDUMP_PATH" > /persist/reboot-reason
    cat /tmp/backtrace > /persist/reboot-stack
    echo "BootReasonKernel" > /persist/boot-reason

    # Simulate the default reboot after panic kernel behaviour
    TIMEOUT=$(cat /proc/sys/kernel/panic)
    if [ "$TIMEOUT" -gt 0 ]; then
        echo "Rebooting in $TIMEOUT seconds..." > /dev/kmsg
        sleep "$TIMEOUT"
    elif [ "$TIMEOUT" -eq 0 ]; then
        # Wait forever
        while true; do sleep 1; done
    fi

    # Reboot immediately
    umount /persist
    echo b > /proc/sysrq-trigger

    # Unreachable line
fi
