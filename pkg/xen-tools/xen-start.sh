#!/bin/sh

mount -t xenfs xenfs /proc/xen/
xenconsoled &
xenstored &
xenstore-write /local/domain/0/domid 0
xenstore-write /local/domain/0/name dom0
