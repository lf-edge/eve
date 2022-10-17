FROM lfedge/eve-alpine:145f062a40639b6c65efa36bed1c5614b873be52 as build
ENV BUILD_PKGS gcc make patch libc-dev linux-headers tar
RUN eve-alpine-deploy.sh

ENV DNSMASQ_VERSION 2.84
# XXX Download dnsmasq?
# From https://thekelleys.org.uk/dnsmasq/dnsmasq-${DNSMASQ_VERSION}.tar.gz

RUN mkdir -p /dnsmasq/patches

COPY dnsmasq-${DNSMASQ_VERSION}.tar.gz /dnsmasq
COPY patches/* /dnsmasq/patches/

WORKDIR /dnsmasq
RUN tar xvzf dnsmasq-${DNSMASQ_VERSION}.tar.gz && \
    echo "https://thekelleys.org.uk/dnsmasq/dnsmasq-${DNSMASQ_VERSION}.tar.gz" >>/source-info

WORKDIR /dnsmasq/dnsmasq-${DNSMASQ_VERSION}
RUN set -e && for patch in ../patches/*.patch; do \
        echo "Applying $patch"; \
        patch -p1 < "$patch"; \
    done

RUN rm -rf /out
RUN make  -j "$(getconf _NPROCESSORS_ONLN)"
RUN make install DESTDIR=/out PREFIX=/usr

FROM scratch
ENTRYPOINT []
CMD []
WORKDIR /
COPY --from=build /out ./
COPY --from=build /source-info ./

