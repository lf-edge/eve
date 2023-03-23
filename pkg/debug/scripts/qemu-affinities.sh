#!/bin/sh
#
# Output affinities for each QEMU thread
#

# We need GNU version of the 'ps' tool
apk=$(apk add procps 2>&1)
if [ $? -ne 0 ]; then
    echo "$apk"
    exit 1
fi

for pid in $(pgrep qemu-system); do
    echo "======= QEMU $pid threads: ======="
    for spid in $(ps -T -o spid= -p "$pid" ); do
        taskset -pc "$spid"
    done
    echo
done
