# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2023-2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# runx-initrd, the initrd of the VMs that container apps run in. pillar
# boots them with the host kernel and this initrd, which mounts the app's
# root filesystem (over 9p under KVM) and starts the app. The image is an init image: it
# puts /boot/runx-initrd into the host rootfs, next to /boot/kernel.

FROM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544 AS build
ENV BUILD_PKGS="gcc libc6-dev e2fsprogs chrony util-linux busybox-static pax-utils cpio gzip"
RUN eve-ubuntu-deploy.sh

RUN rm -f /sbin/poweroff
COPY initrd/base.files /initrd-base.files
COPY initrd/init-initrd initrd/mount_disk.sh initrd/udhcpc_script.sh /
COPY initrd/poweroff /sbin/poweroff
COPY initrd/chroot2.c initrd/hacf.c /tmp/
COPY initrd/00000080 /etc/acpi/PWRF/
COPY initrd/eve-enter-container /bin/
COPY initrd/dotprofile /root/.profile
RUN gcc -s -o /chroot2 /tmp/chroot2.c -Wall -Werror
RUN gcc -s -o /hacf /tmp/hacf.c -Wall -Werror
# the initrd of the shim VM: busybox, a getty, mke2fs and chronyd with the
# libraries they need, plus the scripts above; see initrd/base.files
# hadolint ignore=SC2046
RUN mkdir -p /var/lib/chrony && touch /var/lib/chrony/chrony.drift && \
    eve-mkinitramfs.sh -i /init-initrd -o /runx-initrd $(grep -v '^#' /initrd-base.files)

FROM scratch
COPY --from=build /runx-initrd /boot/runx-initrd
