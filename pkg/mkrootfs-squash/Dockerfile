FROM lfedge/eve-alpine:5f1c625e658308db22e936e3e5498167ed7b9081 AS build

ENV PKGS dosfstools libarchive-tools binutils mtools sfdisk sgdisk \
    xfsprogs e2fsprogs util-linux coreutils multipath-tools squashfs-tools
RUN eve-alpine-deploy.sh

COPY . /out/

FROM scratch
COPY --from=build /out/ /
ENTRYPOINT [ "/make-rootfs" ]
