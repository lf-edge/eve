ARG EVE_BUILDER_IMAGE=lfedge/eve-alpine:6.7.0
# hadolint ignore=DL3006
FROM ${EVE_BUILDER_IMAGE} as build
ENV PKGS alpine-baselayout musl-utils bash glib squashfs-tools util-linux e2fsprogs e2fsprogs-extra keyutils dosfstools coreutils sgdisk smartmontools
RUN eve-alpine-deploy.sh

FROM scratch
COPY --from=build /out/ /
COPY storage-init.sh /

WORKDIR /
ENTRYPOINT []
CMD ["/storage-init.sh"]
