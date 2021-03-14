FROM lfedge/eve-alpine:99db0c3af59a9656315c9d7a0ad8a24f631134b0 as zfs
ENV PKGS zfs
RUN eve-alpine-deploy.sh

FROM scratch
COPY --from=zfs /out/ /
ADD rootfs/ /
