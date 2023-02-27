FROM lfedge/eve-alpine:9fb9b9cbf7d90066a70e4704d04a6fe248ff52bb as build
ENV BUILD_PKGS cairo-dev jpeg-dev libpng-dev gcc make libc-dev openssl-dev libvncserver-dev file patch
ENV PKGS alpine-baselayout musl-utils libtasn1-progs p11-kit cairo jpeg libpng libvncserver
RUN eve-alpine-deploy.sh

ENV GUACD_VERSION=1.0.0

ADD http://apache.org/dyn/closer.cgi?action=download&filename=guacamole/${GUACD_VERSION}/source/guacamole-server-${GUACD_VERSION}.tar.gz /${GUACD_VERSION}.tar.gz
ADD uuid-1.6.2.tar.gz /
COPY patches /patches

RUN cd /uuid-1.6.2 ; ./configure --prefix=/usr/ && make -j "$(getconf _NPROCESSORS_ONLN)" && make install

RUN tar xzvf ${GUACD_VERSION}.tar.gz ;\
    cd /guacamole-server-${GUACD_VERSION} ;\
    [ -d /patches/guacd-"${GUACD_VERSION}" ] && for patch in /patches/guacd-"${GUACD_VERSION}"/*.patch; do \
            echo "Applying $patch"; \
            patch -p1 < "$patch"; \
        done;\
    ./configure --prefix=/usr/ --with-vnc --disable-guacenc --disable-dependency-tracking && \
     make -j "$(getconf _NPROCESSORS_ONLN)" && make install

FROM scratch

COPY --from=build /out/ /
COPY --from=build /usr/sbin/guacd /usr/sbin/guacd
COPY --from=build /usr/lib/libguac.so.* /usr/lib/libuuid.so.* /usr/lib/libguac-client-vnc* /usr/lib/

ENTRYPOINT []
CMD ["/usr/sbin/guacd", "-l", "4822", "-b", "0.0.0.0", "-L", "info", "-f"]
