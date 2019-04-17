# derived from Alpine 3.8
FROM linuxkit/alpine:4d13c6209a679fc7c4e850f144b7aef879914d01 as build

ENV DNSMASQ_VERSION 2.78

RUN apk add --no-cache \
    gcc \
    make \
    patch \
    libc-dev \
    linux-headers \
    tar

RUN mkdir -p /dnsmasq/patches

COPY dnsmasq-${DNSMASQ_VERSION}.tar.gz /dnsmasq
COPY patches/* /dnsmasq/patches/

WORKDIR /dnsmasq
RUN tar xvzf dnsmasq-${DNSMASQ_VERSION}.tar.gz

WORKDIR /dnsmasq/dnsmasq-${DNSMASQ_VERSION}
RUN set -e && for patch in ../patches/*.patch; do \
        echo "Applying $patch"; \
        patch -p1 < "$patch"; \
    done

RUN make
RUN make install DESTDIR=/out PREFIX=/usr

FROM scratch
ENTRYPOINT []
CMD []
WORKDIR /
COPY --from=build /out ./

