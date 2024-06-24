# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs
# This mkimage-raw-efi produces the raw EFI partition for EVE,
# including the files in efi-files in the image.  This includes:
#
#   /EFI/BOOT/grub.cfg - Chainloads main bootloader
#   /UsbInvocationScript.txt - Enables USB boot on Dell 3000 series
#
FROM lfedge/eve-alpine:1f7685f95a475c6bbe682f0b976f12180b6c8726 AS build
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
ENV BUILD_PKGS grep patch git make gcc linux-headers musl-dev autoconf automake pkgconfig kmod-dev util-linux-dev cryptsetup-dev lddtree libgcc mkinitfs
ENV PKGS mtools dosfstools libarchive-tools sgdisk e2fsprogs util-linux squashfs-tools coreutils tar dmidecode \
    kmod-libs cryptsetup-libs libblkid curl
RUN eve-alpine-deploy.sh

# get mkinitfs source from git and build it locally
# it depends on mod-libs cryptsetup-libs libblkid at runtime and lddtree to run mkinitfs itself
# we could build APK file ourselves but 'apk add' would failed because networking is disabled for almost all linuxkit images
WORKDIR /tmp/mkinitfs
ADD https://github.com/alpinelinux/mkinitfs.git#3.8.1 /tmp/mkinitfs
RUN make -j "$(getconf _NPROCESSORS_ONLN)"
WORKDIR /
RUN make -C /tmp/mkinitfs install

WORKDIR /out
RUN echo "mtools_skip_check=1" >> etc/mtools.conf
RUN mkdir -p efifs parts root bits config persist opt/pillar opt/debug lib/modules run sys
COPY make-raw install grub.cfg.in UsbInvocationScript.txt ./

# Before changing something here please take a look into the
# images/rootfs.yml.in onboot section: the installer should
# precede the storage-init container.
#
# now lets create an edge container
# FIXME: 002-installer? why not linuxkit build?
WORKDIR /eco/media/root-rw/root/containers/onboot/002-installer
COPY runtime.json config.json ./
RUN mv /out rootfs
# hadolint ignore=DL3003
RUN (cd /eco && find . -xdev | grep -v installer.img | sort | cpio --quiet -o -H newc) | gzip > rootfs/installer.img
RUN mv rootfs /out

# bootstrap Alpine's initrd
WORKDIR /
COPY initramfs-init.patch /tmp/
RUN patch -p1 < /tmp/initramfs-init.patch

# from https://git.alpinelinux.org/aports/tree/main/mkinitfs/mkinitfs.post-install?id=7b64ec6e904040bd75ea21529b4fce61c908a553
# we need to simulate mkinitfs.post-install from the original APK file
# --- Quote ---
# safety. if nlplug-findfs is missing in the initramfs image we may end up
# with an unbootable system.
RUN if ! grep -q -w /sbin/nlplug-findfs  /etc/mkinitfs/features.d/base.files; then \
        echo "/sbin/nlplug-findfs" >> /etc/mkinitfs/features.d/base.files; \
    fi

RUN echo /bin/grep >> /etc/mkinitfs/features.d/base.files
RUN mkinitfs -n -o /out/initrd.img

FROM scratch
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

COPY --from=build /out/ /

ENTRYPOINT [ "/make-raw" ]
