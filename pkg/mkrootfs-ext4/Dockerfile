FROM lfedge/eve-alpine:cfcc44432b107927b6a12da994750fe37ca3fc3b AS build

ENV PKGS dosfstools libarchive-tools binutils mtools sfdisk sgdisk xfsprogs \
         e2fsprogs util-linux coreutils multipath-tools squashfs-tools
RUN eve-alpine-deploy.sh

COPY . /out/

FROM scratch
COPY --from=build /out/ /
ENTRYPOINT [ "/make-rootfs" ]
