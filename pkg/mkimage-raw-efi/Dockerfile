# This mkimage-raw-efi produces the raw EFI partition for EVE,
# including the files in efi-files in the image.  This includes:
#
#   /EFI/BOOT/grub.cfg - Chainloads main bootloader
#   /UsbInvocationScript.txt - Enables USB boot on Dell 3000 series
#
FROM alpine:3.7

RUN apk add --no-cache \
  mtools \
  dosfstools \
  libarchive-tools \
  sgdisk \
  e2fsprogs \
  util-linux \
  squashfs-tools \
  coreutils

WORKDIR /
COPY make-raw install /
COPY /efi-files /efifs

RUN echo "mtools_skip_check=1" >> /etc/mtools.conf

ENTRYPOINT [ "/make-raw" ]
