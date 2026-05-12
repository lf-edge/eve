# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-alpine:41f3648ded073c351d0dcd3432322f5816c9c7b1 AS build
ENV BUILD_PKGS gcc make patch libc-dev linux-headers tar xz coreutils
RUN eve-alpine-deploy.sh

ENV DNSMASQ_VERSION 2.92rel2

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

# Register dnsmasq in the APK DB, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n dnsmasq -v "${DNSMASQ_VERSION}" -l GPL-2.0-only -u https://thekelleys.org.uk/dnsmasq

FROM build AS test

COPY dnstest /dnstest
WORKDIR /dnstest

FROM scratch
ENTRYPOINT []
CMD []
WORKDIR /
COPY --from=build /out ./

