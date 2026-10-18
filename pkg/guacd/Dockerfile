# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
FROM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544 AS build
ENV BUILD_PKGS="libcairo2-dev libjpeg-turbo8-dev libpng-dev gcc make libc6-dev libssl-dev libvncserver-dev libossp-uuid-dev file patch pkg-config"
ENV PKGS="libcairo2 libjpeg-turbo8 libpng16-16t64 libvncserver1 libossp-uuid16 libssl3t64"
RUN eve-ubuntu-deploy.sh

ENV GUACD_VERSION=1.0.0

ADD http://apache.org/dyn/closer.cgi?action=download&filename=guacamole/${GUACD_VERSION}/source/guacamole-server-${GUACD_VERSION}.tar.gz /${GUACD_VERSION}.tar.gz
COPY patches /patches

RUN tar xzvf ${GUACD_VERSION}.tar.gz ;\
    cd /guacamole-server-${GUACD_VERSION} ;\
    # -Wno-error: config.h redefines the _XOPEN_SOURCE that glibc 2.43 sets
    [ -d /patches/guacd-"${GUACD_VERSION}" ] && for patch in /patches/guacd-"${GUACD_VERSION}"/*.patch; do \
            echo "Applying $patch"; \
            patch -p1 < "$patch"; \
        done;\
    ./configure CFLAGS="-g -O2 -Wno-error" --prefix=/usr/ --with-vnc --disable-guacenc --disable-dependency-tracking && \
     make -j "$(getconf _NPROCESSORS_ONLN)" && make install

# Register guacamole-server in the dpkg status area, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n guacamole-server -v "${GUACD_VERSION}" -l Apache-2.0 -u https://guacamole.apache.org

FROM scratch

COPY --from=build /out/ /
COPY --from=build /usr/sbin/guacd /usr/sbin/guacd
COPY --from=build /usr/lib/libguac.so.* /usr/lib/libguac-client-vnc* /usr/lib/

ENTRYPOINT []
CMD ["/usr/sbin/guacd", "-l", "4822", "-b", "0.0.0.0", "-L", "info", "-f"]
