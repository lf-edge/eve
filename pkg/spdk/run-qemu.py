#!/usr/bin/python3

import sys, subprocess, time

def run_process(args) :
    print(args)
    subprocess.run(args)

start = sys.argv.index("-disks")

for i in range(start, len(sys.argv), 2) :
    location = sys.argv[i + 1]
    id = sys.argv[i + 2]
    run_process(["/usr/share/spdk/scripts/rpc.py", "bdev_aio_create", location, "bdev_{}".format(id), "512"])
    run_process(["/usr/share/spdk/scripts/rpc.py", "vhost_create_blk_controller", "--cpumask", "0x1", "vhost.{}".format(id), "bdev_{}".format(id)])

run_process(["/usr/bin/qemu-system-x86_64"] + sys.argv[1 : start])

while True :
    time.sleep(60.0)