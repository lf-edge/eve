FROM lfedge/eve-alpine:fde32dd3438dc67aecdc8320814d642a438f4aae AS build

ENV PKGS dosfstools libarchive-tools binutils mtools sfdisk sgdisk xfsprogs \
         e2fsprogs util-linux coreutils multipath-tools squashfs-tools
RUN eve-alpine-deploy.sh

COPY . /out/

FROM scratch
COPY --from=build /out/ /
ENTRYPOINT [ "/make-rootfs" ]
