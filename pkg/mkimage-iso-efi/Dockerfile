FROM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544 AS build

ENV PKGS="dosfstools libarchive-tools binutils mtools xorriso squashfs-tools coreutils util-linux mount \
          busybox-static pax-utils cpio gzip"
RUN eve-ubuntu-deploy.sh

RUN echo "mtools_skip_check=1" >> /out/etc/mtools.conf

# make-efi assembles the initrd of the ISO at run time out of this image's own
# busybox and blkid, see eve-mkinitramfs.sh
RUN cp /bin/eve-mkinitramfs.sh /bin/copy-with-libs.sh /bin/merge-sbom-db.sh /out/usr/bin/

FROM scratch
COPY --from=build /out /
COPY . /
WORKDIR /
# glibc's bsdtar needs a UTF-8 locale for the non-ASCII file names in the rootfs
# (ca-certificates), the built-in C.UTF-8 does without locale files
ENV LC_ALL=C.UTF-8
ENTRYPOINT [ "/make-efi" ]
