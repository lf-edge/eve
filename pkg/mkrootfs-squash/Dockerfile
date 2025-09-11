ARG REL_HASH_LFEDGE_EVE_ALPINE

FROM ${REL_HASH_LFEDGE_EVE_ALPINE} AS build

ENV PKGS dosfstools libarchive-tools binutils mtools sfdisk sgdisk \
    xfsprogs e2fsprogs util-linux coreutils multipath-tools squashfs-tools
RUN eve-alpine-deploy.sh

COPY . /out/

FROM scratch
COPY --from=build /out/ /
ENTRYPOINT [ "/make-rootfs" ]
