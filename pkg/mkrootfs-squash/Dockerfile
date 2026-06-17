FROM lfedge/eve-alpine:d1cee9f3e9b1a2f336a61ec1178121a968b4710d AS build

ENV PKGS dosfstools libarchive-tools binutils mtools sfdisk sgdisk \
    xfsprogs e2fsprogs util-linux coreutils multipath-tools squashfs-tools
RUN eve-alpine-deploy.sh

COPY . /out/

FROM scratch
COPY --from=build /out/ /
ENTRYPOINT [ "/make-rootfs" ]
