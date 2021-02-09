# Build watchdogd for alpine

# derived from Alpine 3.8
FROM linuxkit/alpine:4d13c6209a679fc7c4e850f144b7aef879914d01 AS watchdog-build
RUN apk add \
    build-base \
    file \
    libtirpc-dev \
    linux-headers \
    tar

# Version 5.15
ENV WATCHDOGD_VERSION 5.15
ENV WATCHDOGD_SRC_DIR watchdog-${WATCHDOGD_VERSION}
ENV WATCHDOGD_SRC_TAR ${WATCHDOGD_SRC_DIR}.tar
ENV WATCHDOGD_SRC_TGZ ${WATCHDOGD_SRC_TAR}.gz
ENV WATCHDOGD_MIRROR_URL https://jaist.dl.sourceforge.net/project/watchdog/watchdog/
ENV WATCHDOGD_SRC_URL ${WATCHDOGD_MIRROR_URL}/${WATCHDOGD_VERSION}/${WATCHDOGD_SRC_TGZ}

WORKDIR /
COPY ${WATCHDOGD_SRC_TGZ} /
RUN tar --absolute-names -zxf /${WATCHDOGD_SRC_TGZ}

# Apply local patches
COPY patches-${WATCHDOGD_SRC_DIR} /patches

WORKDIR /${WATCHDOGD_SRC_DIR}

RUN \
    echo "Applying local patches." ; \
    set -e && for patch in /patches/*.diff; do \
        echo "Applying patch from file $patch"; \
        patch -p1 < "$patch"; \
    done

# XXX: NFS 'support' is a right pain on alpine, and of unclear benefit.
ENV CONFIGURE_OPTS "--disable-nfs"

RUN \
    CPPFLAGS=-I/usr/include/tirpc ./configure ${CONFIGURE_OPTS} && make && make install DESTDIR=/out

FROM alpine:3.13.1
WORKDIR /
COPY --from=watchdog-build /out/etc /etc
COPY --from=watchdog-build /out/usr/sbin /usr/sbin
COPY --from=watchdog-build /out/usr/share /usr/share
COPY init.sh /
COPY watchdog.conf.seed /etc/
COPY watchdog-report.sh /sbin/

ENTRYPOINT []
CMD ["/init.sh"]
