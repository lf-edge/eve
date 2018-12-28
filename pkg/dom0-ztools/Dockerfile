FROM alpine:3.8 as build
ADD hikey-bugs.sh rngd /rootfs/bin/
ADD libsysfs.so.2 /rootfs/lib/libsysfs.so.2
ADD 000-workarounds /rootfs/etc/init.d/
RUN [ `uname -m` = aarch64 ] || rm -rf /rootfs/*

ADD zen /rootfs/bin/zen

FROM scratch
COPY --from=build /rootfs /
