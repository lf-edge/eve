#!/bin/sh
#
# Output affinities for each QEMU thread
#

# We need GNU version of the 'ps' tool and taskset
if ! command -v taskset >/dev/null 2>&1 || ! ps -T -o spid= -p 1 >/dev/null 2>&1; then
    echo "procps (GNU ps) and util-linux (taskset) are required"
    exit 1
fi

for pid in $(pgrep qemu-system); do
    echo "======= QEMU $pid threads: ======="
    for spid in $(ps -T -o spid= -p "$pid" ); do
        taskset -pc "$spid"
    done
    echo
done
