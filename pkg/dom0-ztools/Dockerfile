ARG EVE_BUILDER_IMAGE=lfedge/eve-alpine:81e6520f4f1554789eb1ac299168e72ac37d88e2
# hadolint ignore=DL3006
FROM ${EVE_BUILDER_IMAGE} as zfs
ENV PKGS zfs zfs-udev ca-certificates util-linux
RUN eve-alpine-deploy.sh

FROM scratch
COPY --from=zfs /out/ /
ADD rootfs/ /
