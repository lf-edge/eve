ARG EVE_BUILDER_IMAGE=lfedge/eve-alpine:6.2.0
# hadolint ignore=DL3006
FROM ${EVE_BUILDER_IMAGE} as zfs
ENV PKGS zfs ca-certificates util-linux
RUN eve-alpine-deploy.sh

FROM scratch
COPY --from=zfs /out/ /
ADD rootfs/ /
