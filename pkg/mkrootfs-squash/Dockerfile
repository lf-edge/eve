FROM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544 AS build

ENV PKGS="dosfstools libarchive-tools binutils mtools fdisk gdisk \
    xfsprogs e2fsprogs util-linux mount coreutils kpartx squashfs-tools xz-utils"
RUN eve-ubuntu-deploy.sh

COPY . /out/

FROM scratch
COPY --from=build /out/ /
# glibc's bsdtar needs a UTF-8 locale for the non-ASCII file names in the rootfs
# (ca-certificates), the built-in C.UTF-8 does without locale files
ENV LC_ALL=C.UTF-8
ENTRYPOINT [ "/make-rootfs" ]
