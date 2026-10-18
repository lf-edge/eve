# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544 AS build
ENV PKGS="bash libglib2.0-0t64 squashfs-tools util-linux mount e2fsprogs keyutils dosfstools coreutils gdisk smartmontools parted procps busybox-static"
RUN eve-ubuntu-deploy.sh
# storage-resize.sh reboots the device after it recorded a failed resize
RUN for a in reboot poweroff halt; do ln -s ../bin/busybox /out/usr/sbin/$a; done

# storage-resizer drives the EVE-kvm<->EVE-k boot-disk repartition; storage-init
# execs it for the offline shrink/grow and the post-mount restore/cleanup. The
# filesystem/partition tools it shells out to (resize2fs, e2fsck, fsck.fat,
# sgdisk, partx) are in the PKGS above.
FROM lfedge/eve-storage-resizer:ad51054ea6af2262b6442ef482e509e1b1f884a2 AS storage-resizer

FROM scratch
COPY --from=build /out/ /
COPY --from=storage-resizer /usr/bin/storage-resizer /usr/bin/storage-resizer
COPY storage-init.sh /
COPY storage-resize.sh /

WORKDIR /
ENTRYPOINT []
CMD ["/storage-init.sh"]
