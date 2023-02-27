# This mkimage-raw-efi produces the raw EFI partition for EVE,
# including the files in efi-files in the image.  This includes:
#
#   /EFI/BOOT/grub.cfg - Chainloads main bootloader
#   /UsbInvocationScript.txt - Enables USB boot on Dell 3000 series
#
FROM lfedge/eve-alpine:9fb9b9cbf7d90066a70e4704d04a6fe248ff52bb AS build
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
ENV BUILD_PKGS mkinitfs grep patch
ENV PKGS mtools dosfstools libarchive-tools sgdisk e2fsprogs util-linux squashfs-tools coreutils tar dmidecode
RUN eve-alpine-deploy.sh

WORKDIR /out
RUN echo "mtools_skip_check=1" >> etc/mtools.conf
RUN mkdir -p efifs parts root bits config persist opt/pillar opt/debug lib/modules run sys
COPY make-raw install grub.cfg.in UsbInvocationScript.txt ./

# Before changing something here please take a look into the
# images/rootfs.yml.in onboot section: the installer should
# precede the storage-init container.
#
# now lets create an edge container
# FIXME: 003-installer? why not linuxkit build?
WORKDIR /eco/media/root-rw/root/containers/onboot/003-installer
COPY runtime.json config.json ./
RUN mv /out rootfs
# hadolint ignore=DL3003
RUN (cd /eco && find . -xdev | grep -v installer.img | sort | cpio --quiet -o -H newc) | gzip > rootfs/installer.img
RUN mv rootfs /out

# bootstrap Alpine's initrd
WORKDIR /
COPY initramfs-init.patch /tmp/
RUN patch -p1 < /tmp/initramfs-init.patch
RUN echo /bin/grep >> /etc/mkinitfs/features.d/base.files
RUN mkinitfs -n -o /out/initrd.img

FROM scratch
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

COPY --from=build /out/ /

ENTRYPOINT [ "/make-raw" ]
