#
# StrongSwan VPN + Alpine Linux
#

FROM lfedge/eve-alpine:145f062a40639b6c65efa36bed1c5614b873be52 as build
ENV BUILD_PKGS gcc make patch libc-dev linux-headers tar build-base ca-certificates iptables iproute2 openssl openssl-dev
RUN eve-alpine-deploy.sh

ENV STRONGSWAN_VERSION 5.6.3
ENV STRONGSWAN_FILE strongswan-${STRONGSWAN_VERSION}.tar.bz2
ENV STRONGSWAN_RELEASE https://download.strongswan.org/${STRONGSWAN_FILE}
ENV CONFIGURE_OPTS_x86_64 --enable-aesni
ENV CONFIGURE_OPTS --prefix=/usr \
            --sysconfdir=/etc \
            --libexecdir=/usr/lib \
            --with-ipsecdir=/usr/lib/strongswan \
            --enable-chapoly \
            --enable-cmd \
            --enable-curl \
            --disable-dhcp \
            --enable-eap-dynamic \
            --enable-eap-identity \
            --enable-eap-md5 \
            --enable-eap-mschapv2 \
            --enable-eap-radius \
            --enable-eap-tls \
            --disable-farp \
            --enable-files \
            --enable-gcm \
            --enable-md4 \
            --enable-newhope \
            --enable-ntru \
            --enable-openssl \
            --enable-sha3 \
            --enable-shared \
            --enable-aes \
            --disable-des \
            --disable-gmp \
            --disable-hmac \
            --enable-ikev1 \
            --disable-md5 \
            --disable-rc2 \
            --enable-sha1 \
            --enable-sha2 \
            --disable-static

WORKDIR /tmp/strongswan
RUN rm -rf /out && mkdir /out

# FIXME: two reasons to build it instead of using the
# stock one:
#    1. alpine 3.6+ now has a conflict with libressl for curl-dev
#    2. linuxkit alpine image doesn't have curl-dev (because of #1?)
COPY curl-7.61.1.tar.bz2 /tmp/curl-7.61.1.tar.bz2
RUN tar -C /tmp -xjvf /tmp/curl-7.61.1.tar.bz2 ; cd /tmp/curl-7.61.1 ; ./configure --prefix=/usr ; make  -j "$(getconf _NPROCESSORS_ONLN)" install

COPY ${STRONGSWAN_FILE} /tmp/strongswan/strongswan.tar.bz2
RUN  tar --strip-components=1 -C /tmp/strongswan -xjf /tmp/strongswan/strongswan.tar.bz2
RUN  eval ./configure $CONFIGURE_OPTS \$CONFIGURE_OPTS_`uname -m`
RUN    make  -j "$(getconf _NPROCESSORS_ONLN)"
RUN    make install DESTDIR=/out

FROM scratch
ENTRYPOINT []
CMD []
WORKDIR /

COPY --from=build /out ./
