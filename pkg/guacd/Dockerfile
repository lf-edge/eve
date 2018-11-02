FROM alpine:latest as build

ADD guacamole-server-0.9.14.tar.gz / 
ADD uuid-1.6.2.tar.gz /

RUN apk add cairo-dev jpeg-dev libpng-dev gcc make libc-dev openssl-dev file

RUN cd /uuid-1.6.2 ; ./configure --prefix=/usr/ && make && make install

RUN cd /guacamole-server-0.9.14 ; ./configure --prefix=/usr/ --disable-guacenc --disable-dependency-tracking && make && make install

FROM alpine:latest

RUN apk add cairo jpeg libpng openssl
COPY --from=build /usr/sbin/guacd /usr/sbin/guacd
COPY --from=build /usr/lib/libguac.so.* /usr/lib/libuuid.so.* /usr/lib/

ENTRYPOINT []
CMD ["/usr/sbin/guacd", "-l", "4822", "-b", "0.0.0.0", "-L", "trace", "-f"]
