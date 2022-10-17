FROM lfedge/eve-alpine:145f062a40639b6c65efa36bed1c5614b873be52 as build
ENV BUILD_PKGS cairo-dev jpeg-dev libpng-dev gcc make libc-dev openssl-dev libvncserver-dev file patch
ENV PKGS alpine-baselayout musl-utils libtasn1-progs p11-kit cairo jpeg libpng libvncserver
RUN eve-alpine-deploy.sh

ENV GUACD_VERSION=1.0.0

ADD https://apache.org/dyn/closer.cgi?action=download&filename=guacamole/${GUACD_VERSION}/source/guacamole-server-${GUACD_VERSION}.tar.gz /${GUACD_VERSION}.tar.gz
RUN echo https://apache.org/dyn/closer.cgi?action=download&filename=guacamole/${GUACD_VERSION}/source/guacamole-server-${GUACD_VERSION}.tar.gz >>/out/source-info
# XXX download uuid pkg? source-info?
ADD uuid-1.6.2.tar.gz /
COPY patches /patches

RUN cd /uuid-1.6.2 ; ./configure --prefix=/usr/ && make && make install

RUN tar xzvf ${GUACD_VERSION}.tar.gz ;\
    cd /guacamole-server-${GUACD_VERSION} ;\
    [ -d /patches/guacd-"${GUACD_VERSION}" ] && for patch in /patches/guacd-"${GUACD_VERSION}"/*.patch; do \
            echo "Applying $patch"; \
            patch -p1 < "$patch"; \
        done;\
    ./configure --prefix=/usr/ --with-vnc --disable-guacenc --disable-dependency-tracking && \
     make && make install

FROM scratch

COPY --from=build /out/ /
COPY --from=build /usr/sbin/guacd /usr/sbin/guacd
COPY --from=build /usr/lib/libguac.so.* /usr/lib/libuuid.so.* /usr/lib/libguac-client-vnc* /usr/lib/

ENTRYPOINT []
CMD ["/usr/sbin/guacd", "-l", "4822", "-b", "0.0.0.0", "-L", "info", "-f"]
