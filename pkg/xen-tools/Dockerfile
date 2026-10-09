# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2023-2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# runx-initrd, the initrd of the VMs that container apps run in. pillar
# boots them with the host kernel and this initrd, which mounts the app's
# root filesystem (over 9p under KVM) and starts the app. The image is an init image: it
# puts /boot/runx-initrd into the host rootfs, next to /boot/kernel.

FROM lfedge/eve-alpine:080e2b4c683508649d72d2ae9b166153d819ca5d AS build
ENV BUILD_PKGS="mkinitfs gcc musl-dev e2fsprogs chrony agetty"
RUN eve-alpine-deploy.sh

RUN rm -f /sbin/poweroff /etc/mkinitfs/features.d/base.files
COPY initrd/base.files /etc/mkinitfs/features.d/base.files
COPY initrd/init-initrd initrd/mount_disk.sh initrd/udhcpc_script.sh /
COPY initrd/poweroff /sbin/poweroff
COPY initrd/chroot2.c initrd/hacf.c /tmp/
COPY initrd/00000080 /etc/acpi/PWRF/
COPY initrd/eve-enter-container /bin/
COPY initrd/dotprofile /root/.profile
RUN gcc -s -o /chroot2 /tmp/chroot2.c -Wall -Werror
RUN gcc -s -o /hacf /tmp/hacf.c -Wall -Werror
RUN mkinitfs -n -F base -i /init-initrd -o /runx-initrd

FROM scratch
COPY --from=build /runx-initrd /boot/runx-initrd
