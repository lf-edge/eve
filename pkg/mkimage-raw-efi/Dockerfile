# This mkimage-raw-efi produces the raw EFI partition for EVE,
# including the files in efi-files in the image.  This includes:
#
#   /EFI/BOOT/grub.cfg - Chainloads main bootloader
#   /UsbInvocationScript.txt - Enables USB boot on Dell 3000 series
#
ARG BUILDER=lfedge/eve-alpine:ac1dc159510afa61334222cedf085c7730e4583c
FROM ${BUILDER} as initrd
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

COPY nlplug-findfs.c initramfs-init /tmp/
RUN apk add --no-cache         \
      mkinitfs=3.4.1-r1        \
      gcc=8.3.0-r0             \
      musl-dev=1.1.20-r5       \
      linux-headers=4.18.13-r1 \
      kmod-dev=24-r1           \
      util-linux-dev=2.33-r0   \
      cryptsetup1-dev=1.7.5-r4
RUN cc -Wall -Werror -g -D_GNU_SOURCE -DDEBUG -I/usr/include/blkid -I/usr/include/uuid /tmp/nlplug-findfs.c -lblkid  -lkmod  -L/lib -lcryptsetup -o /sbin/nlplug-findfs
RUN mkinitfs -n -i /tmp/initramfs-init -o /initrd.gz

FROM ${BUILDER} as build
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

WORKDIR /out

RUN mkdir -p /out/etc/apk /out/boot && cp -r /etc/apk/* /out/etc/apk/
RUN apk add --no-cache --initdb -p /out \
  busybox=1.29.3-r10        \
  mtools=4.0.23-r0          \
  dosfstools=4.1-r1         \
  libarchive-tools=3.3.3-r1 \
  sgdisk=1.0.4-r0           \
  e2fsprogs=~1.44.5         \
  util-linux=2.33-r0        \
  squashfs-tools=4.3-r5     \
  coreutils=8.30-r0         \
  tar=1.32-r0

COPY make-raw install grub.cfg.in UsbInvocationScript.txt /out/

RUN echo "mtools_skip_check=1" >> etc/mtools.conf

FROM scratch
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

COPY --from=build /out/ /
COPY --from=initrd /initrd.gz /
COPY grub.stage1 /usr/lib/grub/i386-pc/boot.img
RUN gzip -d < /initrd.gz | cpio -id && \
    rm /etc/mtab /dev/null && \
    find . -xdev | grep -v initrd.gz | sort | cpio --quiet -o -H newc | gzip > /initrd.gz && \
    mv /initrd.gz /initrd.img

COPY grub.cfg /EFI/BOOT/

ENTRYPOINT [ "/make-raw" ]
