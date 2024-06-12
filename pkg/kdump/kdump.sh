#!/bin/sh
#
# SPDX-License-Identifier: Apache-2.0

if test -f /proc/vmcore; then
    #
    # We are in dump capture kernel, nice.
    #

    # Maximum number of kernel dmesgs we keep in the folder.
    MAX=10
    # Number of generated files
    N=1
    DIR=/persist/kcrashes

    # Create a folder
    mkdir $DIR > /dev/null 2<&1

    # Keep $MAX-$N fresh dumps, $N files will be generated
    # shellcheck disable=SC2012
    ls -t $DIR | tail -n +$((MAX+1-N)) | xargs --no-run-if-empty -I '{}' rm $DIR/{}

    # Get kernel panic from the dmesg of a crashed kernel
    makedumpfile --dump-dmesg /proc/vmcore /tmp/dmesg > /dev/null
    sed -n -e '/Kernel panic - not syncing/,$p' /tmp/dmesg > /tmp/backtrace

    # Show backtrace from the dmesg of a crashed kernel. Print line by
    # line with some reasonable sleep in-between lines to slow down the
    # output on the console and give a chance to record the stack
    # properly. Typical use case is BMC which records with very low
    # frame rate so the video contains the bottom of the long stack
    # only, but the top is missing.
    echo ">>>>>>>>>> Crashed kernel dmesg BEGIN <<<<<<<<<<" > /dev/kmsg
    while read -r line; do echo "$line" > /dev/kmsg; sleep 0.2; done < /tmp/backtrace
    echo ">>>>>>>>>> Crashed kernel dmesg END <<<<<<<<<<" > /dev/kmsg

    TS=$(date -Is)

    # Collect dmesg
    DMESG_PATH="$DIR/dmesg-$TS.log"
    cp /tmp/dmesg "$DMESG_PATH"
    echo "dmesg collected: $DMESG_PATH" > /dev/kmsg

    # Prepare reboot-reason, reboot-stack and boot-reason
    echo "kernel panic, dmesg collected: $DMESG_PATH" > /persist/reboot-reason
    cat /tmp/dmesg > /persist/reboot-stack
    echo "BootReasonKernel" > /persist/boot-reason

    # Umount and flush block buffers
    umount /persist
    sync

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
    echo b > /proc/sysrq-trigger

    # Unreachable line
fi
