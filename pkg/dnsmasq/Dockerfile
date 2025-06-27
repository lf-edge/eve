# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-alpine:523254c1b0728948a16a02115eb817f27c00977f as build
ENV BUILD_PKGS gcc make patch libc-dev linux-headers tar xz coreutils
RUN eve-alpine-deploy.sh

ENV DNSMASQ_VERSION 2.91

RUN mkdir -p /dnsmasq/patches

COPY dnsmasq-${DNSMASQ_VERSION}.tar.xz /dnsmasq
COPY patches/* /dnsmasq/patches/

WORKDIR /dnsmasq
RUN tar xvf dnsmasq-${DNSMASQ_VERSION}.tar.xz

WORKDIR /dnsmasq/dnsmasq-${DNSMASQ_VERSION}
RUN set -e && for patch in ../patches/*.patch; do \
        echo "Applying $patch"; \
        patch -p1 < "$patch"; \
    done

RUN rm -rf /out
RUN make  -j "$(getconf _NPROCESSORS_ONLN)"
RUN make install DESTDIR=/out PREFIX=/usr

FROM build AS test
ENV BUILD_PKGS go
RUN eve-alpine-deploy.sh

COPY dnstest /dnstest
WORKDIR /dnstest

FROM scratch
ENTRYPOINT []
CMD []
WORKDIR /
COPY --from=build /out ./

