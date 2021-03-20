FROM lfedge/eve-alpine:6.2.0 as zfs
ENV PKGS zfs ca-certificates util-linux
RUN eve-alpine-deploy.sh

FROM scratch
COPY --from=zfs /out/ /
ADD rootfs/ /
