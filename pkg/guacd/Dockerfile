FROM alpine:3.13.1 as build

ENV GUACD_VERSION=1.0.0

ADD http://apache.org/dyn/closer.cgi?action=download&filename=guacamole/1.0.0/source/guacamole-server-${GUACD_VERSION}.tar.gz /${GUACD_VERSION}.tar.gz 
ADD 0001-alpine-stacksize-fix.patch /
ADD uuid-1.6.2.tar.gz /

RUN apk add cairo-dev jpeg-dev libpng-dev gcc make libc-dev openssl-dev libvncserver-dev file

RUN cd /uuid-1.6.2 ; ./configure --prefix=/usr/ && make && make install

RUN tar xzvf ${GUACD_VERSION}.tar.gz ;\
    patch -p0 < /0001-alpine-stacksize-fix.patch ;\
    cd /guacamole-server-${GUACD_VERSION} ;\
    ./configure --prefix=/usr/ --with-vnc --disable-guacenc --disable-dependency-tracking && \
     make && make install

FROM alpine:3.13.1

RUN apk add cairo jpeg libpng openssl libvncserver
COPY --from=build /usr/sbin/guacd /usr/sbin/guacd
COPY --from=build /usr/lib/libguac.so.* /usr/lib/libuuid.so.* /usr/lib/libguac-client-vnc* /usr/lib/

ENTRYPOINT []
CMD ["/usr/sbin/guacd", "-l", "4822", "-b", "0.0.0.0", "-L", "info", "-f"]
