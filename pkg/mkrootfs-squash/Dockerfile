FROM lfedge/eve-alpine:145f062a40639b6c65efa36bed1c5614b873be52 AS build

ENV PKGS dosfstools libarchive-tools binutils mtools sfdisk sgdisk \
    xfsprogs e2fsprogs util-linux coreutils multipath-tools squashfs-tools
RUN eve-alpine-deploy.sh

COPY . /out/

FROM scratch
COPY --from=build /out/ /
ENTRYPOINT [ "/make-rootfs" ]
