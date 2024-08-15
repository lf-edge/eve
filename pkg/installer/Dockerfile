# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# Dockerfile to build installer img initrd
FROM lfedge/eve-alpine:1f7685f95a475c6bbe682f0b976f12180b6c8726 AS build
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
ENV BUILD_PKGS grep patch go git make gcc linux-headers musl-dev autoconf automake pkgconfig kmod-dev util-linux-dev cryptsetup-dev lddtree libgcc
ENV PKGS mtools dosfstools libarchive-tools sgdisk e2fsprogs util-linux squashfs-tools coreutils tar dmidecode \
    kmod-libs cryptsetup-libs libblkid
RUN eve-alpine-deploy.sh

COPY . .
RUN go build -o /out/tpmmgr .

FROM scratch
COPY --from=build /out/ /

WORKDIR /
RUN echo "mtools_skip_check=1" >> etc/mtools.conf
RUN mkdir -p parts bits config persist opt/pillar opt/debug lib/modules run sys

COPY install ./

ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# hadolint ignore=DL3002
USER 0:0

ENTRYPOINT [ "/install" ]