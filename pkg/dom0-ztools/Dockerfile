ARG EVE_BUILDER_IMAGE=lfedge/eve-alpine:81e6520f4f1554789eb1ac299168e72ac37d88e2
# hadolint ignore=DL3006
FROM ${EVE_BUILDER_IMAGE} as zfs
ENV BUILD_PKGS git patch ca-certificates util-linux build-base gettext-dev libtirpc-dev automake autoconf \
    libtool linux-headers attr-dev e2fsprogs-dev glib-dev openssl-dev util-linux-dev
ENV PKGS ca-certificates util-linux libintl libuuid libtirpc libblkid libcrypto1.1 zlib
RUN eve-alpine-deploy.sh

COPY /patches /

# should be aligned with kernel
#  * ZFS on Linux
ENV ZFS_VERSION=2.1.2
ENV ZFS_COMMIT=zfs-${ZFS_VERSION}
ENV ZFS_REPO=https://github.com/openzfs/zfs.git
ENV ZFS_PATCH_DIR=/patches-zfs-"${ZFS_VERSION}"

WORKDIR /tmp/zfs

RUN git clone --depth 1 -b ${ZFS_COMMIT} ${ZFS_REPO} .
RUN set -e; \
    if [ ! -d "${ZFS_PATCH_DIR}" ]; then \
        echo "No such dir ${ZFS_PATCH_DIR}"; \
    else \
        for patch in "${ZFS_PATCH_DIR}"/*.patch; do \
            echo "Applying $patch"; \
            patch -p1 < "$patch"; \
        done \
    fi
RUN ./autogen.sh && \
    ./configure --with-linux=/linux \
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
ADD rootfs/ /
