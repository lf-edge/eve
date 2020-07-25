FROM alpine:3.12 as zfs
RUN mkdir -p /out/etc/apk /out/boot && cp -r /etc/apk/* /out/etc/apk/
RUN apk add --no-cache --initdb -p /out \
    zfs=0.8.4-r0

FROM scratch
COPY --from=zfs /out/ /
ADD rootfs/ /
