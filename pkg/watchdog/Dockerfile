# Build watchdogd for alpine

FROM linuxkit/alpine:d307c8a386fa3f32cddda9409b9687e191cdd6f1 AS watchdog-build
RUN apk add \
    build-base \
    file \
    libtirpc-dev \
    linux-headers \
    curl \
    tar

# Version 5.15
ENV WATCHDOGD_VERSION 5.15
ENV WATCHDOGD_SRC_DIR watchdog-${WATCHDOGD_VERSION}
ENV WATCHDOGD_SRC_TAR ${WATCHDOGD_SRC_DIR}.tar
ENV WATCHDOGD_SRC_TGZ ${WATCHDOGD_SRC_TAR}.gz
ENV WATCHDOGD_MIRROR_URL https://jaist.dl.sourceforge.net/project/watchdog/watchdog/
ENV WATCHDOGD_SRC_URL ${WATCHDOGD_MIRROR_URL}/${WATCHDOGD_VERSION}/${WATCHDOGD_SRC_TGZ}

RUN \
    [ -f ${WATCHDOGD_SRC_TGZ} ] || \
    echo "Downloading ${WATCHDOGD_SRC_TGZ}" && curl -#fSLO ${WATCHDOGD_SRC_URL}

RUN \
    echo "Extracting ${WATCHDOGD_SRC_TGZ} -> /${WATCHDOGD_SRC_DIR}" && \
    gzip -d ${WATCHDOGD_SRC_TGZ} && \
    cat ${WATCHDOGD_SRC_TAR} | tar --absolute-names -x && mv /${WATCHDOGD_SRC_DIR} /

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

FROM scratch
ENTRYPOINT []
CMD []
WORKDIR /
COPY --from=watchdog-build /out/etc /etc
COPY --from=watchdog-build /out/usr/sbin /usr/sbin
COPY --from=watchdog-build /out/usr/share /usr/share

