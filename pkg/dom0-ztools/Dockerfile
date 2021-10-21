ARG EVE_BUILDER_IMAGE=lfedge/eve-alpine:7.2.0

# hadolint ignore=DL3006
FROM ${EVE_BUILDER_IMAGE} as zfs
ENV PKGS lvm2 zfs zfs-udev ca-certificates util-linux
RUN eve-alpine-deploy.sh

FROM scratch
COPY --from=zfs /out/ /
ADD rootfs/ /
