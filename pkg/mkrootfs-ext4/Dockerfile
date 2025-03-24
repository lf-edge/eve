FROM lfedge/eve-alpine:0f2e0da38e30753c68410727a6cc269e57ff74f2 AS build

ENV PKGS dosfstools libarchive-tools binutils mtools sfdisk sgdisk xfsprogs \
         e2fsprogs util-linux coreutils multipath-tools squashfs-tools
RUN eve-alpine-deploy.sh

COPY . /out/

FROM scratch
COPY --from=build /out/ /
ENTRYPOINT [ "/make-rootfs" ]
