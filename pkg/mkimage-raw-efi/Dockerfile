# This mkimage-raw-efi produces the raw EFI partition for EVE,
# including the files in efi-files in the image.  This includes:
#
#   /EFI/BOOT/grub.cfg - Chainloads main bootloader
#   /UsbInvocationScript.txt - Enables USB boot on Dell 3000 series
#
FROM alpine:3.10 as initrd
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

COPY nlplug-findfs.c initramfs-init /tmp/
RUN apk add --no-cache         \
      mkinitfs=3.4.3-r0        \
      gcc=8.3.0-r0             \
      musl-dev=1.1.22-r3       \
      linux-headers=4.19.36-r0 \
      kmod-dev=24-r1           \
      util-linux-dev=2.33.2-r0 \
      cryptsetup1-dev=1.7.5-r4
RUN cc -Wall -Werror -g -D_GNU_SOURCE -DDEBUG -I/usr/include/blkid -I/usr/include/uuid /tmp/nlplug-findfs.c -lblkid  -lkmod  -L/lib -lcryptsetup -o /sbin/nlplug-findfs
RUN mkinitfs -n -i /tmp/initramfs-init -o /initrd.gz

FROM alpine:3.10 as build
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

WORKDIR /out

RUN mkdir -p /out/etc/apk /out/boot && cp -r /etc/apk/* /out/etc/apk/
RUN apk add --no-cache --initdb -p /out \
  mtools=4.0.23-r0          \
  dosfstools=4.1-r1         \
  libarchive-tools=3.3.3-r1 \
  sgdisk=1.0.4-r0           \
  e2fsprogs=1.45.2-r1       \
  util-linux=2.33.2-r0      \
  squashfs-tools=4.3-r5     \
  coreutils=8.31-r0

COPY /efi-files /out/efifs
COPY make-raw install /out/

RUN echo "mtools_skip_check=1" >> etc/mtools.conf
RUN find . -print -depth | cpio -o -H newc | gzip > /installer.gz

FROM alpine:3.10
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

COPY --from=build /installer.gz /
COPY --from=initrd /initrd.gz /
RUN gzip -d < /installer.gz | cpio -id 2>/dev/null
RUN mkdir /tmp/r ; cd /tmp/r ;\
    for i in initrd.gz installer.gz ; do gzip -d < /$i | cpio -id ; done ;\
    find . | sort | cpio --quiet -o -H newc | gzip > /initrd.img

COPY grub.cfg /EFI/BOOT/

ENTRYPOINT [ "/make-raw" ]
