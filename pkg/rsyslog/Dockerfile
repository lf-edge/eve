FROM lfedge/eve-alpine:0ad716589cb431841da89051a2bcfa92246a238f as build
WORKDIR /
RUN apk add --no-cache \
        git=2.20.2-r0 \
        build-base=0.5-r1 \
        automake=1.16.1-r0 \
        libtool=2.4.6-r5 \
        autoconf=2.69-r2 \
        py-docutils=0.14-r1 \
        zlib-dev=1.2.11-r1 \
        curl-dev=7.64.0-r3 \
        libuuid=2.33-r0 \
        util-linux-dev=2.33-r0 \
        flex=2.6.4-r1 \
        bison=3.0.5-r0 \
        bsd-compat-headers=0.7.1-r0 \
        linux-headers=4.18.13-r1 \
        libestr-dev=0.1.10-r0 \
        libfastjson-dev=0.99.8-r1 \
        librelp-dev=1.3.0-r0 \
        liblogging-dev=1.0.6-r0
ENV SUDO=""
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig \
     LD_LIBRARY_PATH=/usr/local/lib \
     CFLAGS="-Os -fomit-frame-pointer"
ENV RSYSLOG_CONFIGURE_OPTIONS --enable-generate-man-pages=no --enable-mmjsonparse --enable-mmutf8fix --disable-omudpspoof --enable-relp --disable-snmp --disable-mmsnmptrapd --enable-usertools=no --enable-libgcrypt=no --enable-imemlogd
COPY build-rsyslog.sh /build-rsyslog.sh
COPY imemlogd.diff /imemlogd.diff
RUN ./build-rsyslog.sh

From alpine:3.10.3
COPY rsyslog.conf /etc/rsyslog.conf
COPY init.sh /init.sh
COPY rotate.sh /rotate.sh
COPY monitor-rsyslog.sh /monitor-rsyslog.sh
COPY --from=build /usr/local/sbin/rsyslogd /usr/sbin/rsyslogd
COPY --from=build /usr/local/lib/rsyslog/ /usr/local/lib/rsyslog/
COPY --from=build /usr/lib/libestr.so.0 /usr/lib/libestr.so.0
COPY --from=build /usr/lib/libfastjson.so.4 /usr/lib/libfastjson.so.4
COPY --from=build /lib/libuuid.so.1 /lib/libuuid.so.1
COPY --from=build /usr/lib/liblogging-stdlog.so.0 /usr/lib/liblogging-stdlog.so.0

ENTRYPOINT []
CMD ["/init.sh"]
