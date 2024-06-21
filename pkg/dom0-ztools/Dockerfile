# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs
FROM lfedge/eve-alpine:1f7685f95a475c6bbe682f0b976f12180b6c8726 as zfs
ENV BUILD_PKGS git patch ca-certificates util-linux build-base gettext-dev libtirpc-dev automake autoconf \
    libtool linux-headers attr-dev e2fsprogs-dev glib-dev openssl-dev util-linux-dev coreutils
ENV PKGS ca-certificates util-linux libintl libuuid libtirpc libblkid libcrypto1.1 zlib
RUN eve-alpine-deploy.sh

# should be aligned with kernel
#  * ZFS on Linux
ENV ZFS_VERSION=2.2.2
ENV ZFS_COMMIT=zfs-${ZFS_VERSION}
ENV ZFS_REPO=https://github.com/openzfs/zfs.git

WORKDIR /tmp/zfs
ADD ${ZFS_REPO}#${ZFS_COMMIT} /tmp/zfs

RUN ./autogen.sh && \
    ./configure \
    --prefix=/usr \
    --with-tirpc \
    --sysconfdir=/etc \
    --mandir=/usr/share/man \
    --infodir=/usr/share/info \
    --localstatedir=/var \
    --with-config=user \
    --with-udevdir=/lib/udev \
    --disable-systemd \
    --disable-static && \
    ./scripts/make_gitrev.sh && \
    make -j "$(getconf _NPROCESSORS_ONLN)" && \
    make DESTDIR=/tmp/zfs-out install-strip

# cleanup
RUN rm -rf /tmp/zfs-out/usr/share && rm -rf /tmp/zfs-out/usr/src && \
    rm -rf /tmp/zfs-out/etc/init.d && rm -rf /tmp/zfs-out/etc/conf.d

# make the list of files built from zfs to reuse later
# hadolint ignore=DL4006
RUN find /tmp/zfs-out -mindepth 1|sed 's@/tmp/zfs-out@@'>/out/etc/zfs-files
RUN cp -r /tmp/zfs-out/* /out

FROM scratch
COPY --from=zfs /out/ /
# hadolint ignore=DL3020
ADD rootfs/ /
### Create system-wide groups and users ###
# add initial root user
RUN touch /etc/group && touch /etc/passwd
RUN addgroup -g 0 root
RUN adduser -D -H -h /root -s /bin/sh -g "root" -G root -u 0 root
# add nobody user and group
RUN addgroup -g 65534 nogroup
RUN adduser -D -H -h /nonexistent -s /bin/false -g "nobody" -u 65534 -G nogroup nobody
# add tpms group so /dev/tpm* is accessible to non-root users via tpms group,
# the group is set for /dev/tpm* in the mdev.conf file
RUN addgroup -g 100 tpms
# setup user and group for vtpm container and allow TPM access via tpms group
RUN addgroup -g 101 vtpm
RUN adduser -D -H -h /nonexistent -s /bin/false -g "vtpm" -G vtpm -u 101 vtpm
RUN addgroup vtpm tpms
