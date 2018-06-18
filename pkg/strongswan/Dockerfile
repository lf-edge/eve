#
# StrongSwan VPN + Alpine Linux
#

FROM alpine:3.6 as build

ENV STRONGSWAN_RELEASE https://download.strongswan.org/strongswan.tar.bz2
ENV CONFIGURE_OPTS_x86_64 --enable-aesni
ENV CONFIGURE_OPTS --prefix=/usr \
            --sysconfdir=/etc \
            --libexecdir=/usr/lib \
            --with-ipsecdir=/usr/lib/strongswan \
            --enable-chapoly \
            --enable-cmd \
            --enable-curl \
            --enable-dhcp \
            --enable-eap-dynamic \
            --enable-eap-identity \
            --enable-eap-md5 \
            --enable-eap-mschapv2 \
            --enable-eap-radius \
            --enable-eap-tls \
            --enable-farp \
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

RUN apk add --no-cache \
    gcc \
    make \
    patch \
    libc-dev \
    linux-headers \
    tar

WORKDIR /tmp/strongswan
RUN mkdir -p /tmp/strongswan
RUN mkdir -p /out

RUN apk --update add build-base \
            ca-certificates \
            iptables \
            iproute2 \
			openssl \
			openssl-dev \
            curl\
            curl-dev

RUN  curl -Lo /tmp/strongswan/strongswan.tar.bz2 $STRONGSWAN_RELEASE 
RUN  tar --strip-components=1 -C /tmp/strongswan -xjf /tmp/strongswan/strongswan.tar.bz2
RUN  eval ./configure $CONFIGURE_OPTS \$CONFIGURE_OPTS_`uname -m`
RUN    make 
RUN    make install DESTDIR=/out

FROM scratch
ENTRYPOINT []
CMD []
WORKDIR /

COPY --from=build /out ./
