FROM alpine:3.10.3 as build
WORKDIR /
RUN apk add --no-cache \
        git=2.22.2-r0 \
        build-base=0.5-r1 \
        automake=1.16.1-r0 \
        libtool=2.4.6-r6 \
        autoconf=2.69-r2 \
        py-docutils=0.14-r2 \
        gnutls=3.6.8-r0 \
        gnutls-dev=3.6.8-r0 \
        zlib-dev=1.2.11-r1 \
        curl-dev=7.66.0-r0 \
        mysql-dev=10.3.20-r0 \
        libdbi-dev=0.9.0-r0 \
        libuuid=2.33.2-r0 \
        util-linux-dev=2.33.2-r0 \
        libgcrypt-dev=1.8.5-r0 \
        flex=2.6.4-r2 \
        bison=3.3.2-r0 \
        bsd-compat-headers=0.7.1-r0 \
        linux-headers=4.19.36-r0 \
        valgrind=3.15.0-r0 \
        librdkafka-dev=1.0.1-r1 \
        autoconf-archive=2019.01.06-r0 \
        libestr-dev=0.1.11-r0 \
        libfastjson-dev=0.99.8-r2 \
        liblognorm-dev=2.0.6-r1 \
        librelp-dev=1.3.0-r0 \
        liblogging-dev=1.0.6-r0
RUN apk add --no-cache \
        man=1.14.3-r3 \
        man-pages=5.01-r0 \
        gcc-doc=8.3.0-r0
ENV SUDO=""
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig \
     LD_LIBRARY_PATH=/usr/local/lib \
     CFLAGS="-Os -fomit-frame-pointer"
ENV RSYSLOG_CONFIGURE_OPTIONS -enable-testbench --enable-imdiag --enable-imfile --enable-impstats --enable-imptcp --enable-mmanon --enable-mmaudit --enable-mmfields --enable-mmjsonparse --enable-mmpstrucdata --enable-mmsequence --enable-mmutf8fix --enable-mail --enable-omprog --enable-omruleset --enable-omstdout --enable-omuxsock --enable-pmaixforwardedfrom --enable-pmciscoios --enable-pmcisconames --enable-pmlastmsg --enable-pmsnare --enable-libgcrypt --enable-mmnormalize --disable-omudpspoof --enable-relp --disable-snmp --disable-mmsnmptrapd --enable-gnutls --enable-mysql --enable-mysql-tests --enable-usertools=no --enable-libdbi --enable-omhttpfs --enable-elasticsearch --enable-valgrind --enable-ommongodb=no --enable-imkafka --enable-omkafka --enable-pmnull --enable-imemlogd
COPY setup-rsyslog.sh /setup-rsyslog.sh
COPY imemlogd.c /imemlogd.c
COPY Makefile.am /Makefile.am
COPY Makefile.am.imemlogd /Makefile.am.imemlogd
COPY Makefile.am.tests /Makefile.am.tests
COPY configure.ac /configure.ac
RUN ./setup-rsyslog.sh

From alpine:3.10.3
RUN apk add --no-cache \
        libuuid=2.33.2-r0 \
        libfastjson-dev=0.99.8-r2 \
        libestr-dev=0.1.11-r0 \
        liblogging-dev=1.0.6-r0
COPY rsyslog.conf /etc/rsyslog.conf
COPY init.sh /init.sh
COPY rotate.sh /rotate.sh
COPY monitor-rsyslog.sh /monitor-rsyslog.sh
COPY --from=build /usr/local/sbin/rsyslogd /usr/sbin/rsyslogd
COPY --from=build /usr/local/lib/rsyslog/ /usr/local/lib/rsyslog/
COPY --from=build /usr/lib/libestr.so.0 /usr/lib/libestr.so.0
COPY --from=build /usr/lib/libfastjson.so.4 /usr/lib/libfastjson.so.4
COPY --from=build /lib/libuuid.so.1 /lib/libuuid.so.1

ENTRYPOINT []
CMD ["/init.sh"]
