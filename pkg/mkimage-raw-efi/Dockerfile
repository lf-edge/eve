# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs
# This mkimage-raw-efi produces the raw EFI partition for EVE,
# including the files in efi-files in the image.  This includes:
#
#   /EFI/BOOT/grub.cfg - Chainloads main bootloader
#   /UsbInvocationScript.txt - Enables USB boot on Dell 3000 series
#
FROM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544 AS build
SHELL ["/bin/bash", "-eo", "pipefail", "-c"]
ENV BUILD_PKGS="grep patch git make gcc linux-libc-dev libc6-dev pkg-config libkmod-dev libblkid-dev libcryptsetup-dev pax-utils busybox-static cpio gzip"
ENV PKGS="mtools dosfstools libarchive-tools gdisk fdisk e2fsprogs util-linux mount squashfs-tools coreutils tar dmidecode \
    kpartx parted qemu-utils gzip cpio xz-utils"
RUN eve-ubuntu-deploy.sh

# mkinitfs provides nlplug-findfs, which locates the root device from inside
# the initrd, and initramfs-init, the init script of the live and installer
# initrd. The initrd itself is assembled by eve-mkinitramfs.sh from the
# static busybox of this build stage.
WORKDIR /tmp/mkinitfs
ADD https://github.com/alpinelinux/mkinitfs.git#3.8.1 /tmp/mkinitfs
# mkinitfs builds with -Werror; Ubuntu's gcc defaults add warnings it does not expect
RUN CFLAGS="-Wall -g" make nlplug-findfs/nlplug-findfs initramfs-init && \
    install -m 755 nlplug-findfs/nlplug-findfs /sbin/nlplug-findfs && \
    install -D -m 755 initramfs-init /usr/share/mkinitfs/initramfs-init
WORKDIR /

# Register mkinitfs in the dpkg status area, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n mkinitfs -v 3.8.1 -l GPL-2.0-only -u https://github.com/alpinelinux/mkinitfs

WORKDIR /out
RUN echo "mtools_skip_check=1" >> etc/mtools.conf
RUN mkdir -p efifs parts root bits config persist opt/pillar opt/debug lib/modules run sys
COPY make-raw UsbInvocationScript.txt ./

# bootstrap Alpine's initrd
WORKDIR /
COPY initramfs-init.patch /tmp/
RUN patch -p1 < /tmp/initramfs-init.patch
RUN eve-mkinitramfs.sh -i /usr/share/mkinitfs/initramfs-init -o /out/initrd.img /sbin/nlplug-findfs

FROM scratch
SHELL ["/bin/sh", "-c"]

COPY --from=build /out/ /

# glibc's bsdtar needs a UTF-8 locale for the non-ASCII file names in the rootfs
# (ca-certificates), the built-in C.UTF-8 does without locale files
ENV LC_ALL=C.UTF-8
ENTRYPOINT [ "/make-raw" ]
