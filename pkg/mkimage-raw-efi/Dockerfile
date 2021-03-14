# This mkimage-raw-efi produces the raw EFI partition for EVE,
# including the files in efi-files in the image.  This includes:
#
#   /EFI/BOOT/grub.cfg - Chainloads main bootloader
#   /UsbInvocationScript.txt - Enables USB boot on Dell 3000 series
#
FROM lfedge/eve-alpine:99db0c3af59a9656315c9d7a0ad8a24f631134b0 as build
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
ENV BUILD_PKGS mkinitfs gcc musl-dev linux-headers kmod-dev util-linux-dev cryptsetup-dev
ENV PKGS mtools dosfstools libarchive-tools sgdisk e2fsprogs util-linux squashfs-tools coreutils tar
RUN eve-alpine-deploy.sh

COPY nlplug-findfs.c initramfs-init /tmp/
RUN cc -Wall -Werror -g -D_GNU_SOURCE -DDEBUG -I/usr/include/blkid -I/usr/include/uuid /tmp/nlplug-findfs.c -lblkid  -lkmod  -L/lib -lcryptsetup -o /sbin/nlplug-findfs
RUN mkinitfs -n -i /tmp/initramfs-init -o /initrd.gz

WORKDIR /out
RUN mkdir -p boot
RUN echo "mtools_skip_check=1" >> etc/mtools.conf
COPY make-raw install grub.cfg.in UsbInvocationScript.txt ./

FROM scratch
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

COPY --from=build /out/ /
COPY --from=build /initrd.gz /
COPY grub.stage1 /usr/lib/grub/i386-pc/boot.img
RUN gzip -d < /initrd.gz | cpio -id && \
    rm -f /etc/mtab /dev/null && \
    find . -xdev | grep -v initrd.gz | sort | cpio --quiet -o -H newc | gzip > /initrd.gz && \
    mv /initrd.gz /initrd.img

COPY grub.cfg /EFI/BOOT/

ENTRYPOINT [ "/make-raw" ]
