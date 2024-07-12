# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
FROM lfedge/eve-alpine:1f7685f95a475c6bbe682f0b976f12180b6c8726 AS build

ENV BUILD_PKGS patch curl make gcc perl util-linux-dev git mtools linux-headers musl-dev xz-dev elfutils-dev libbz2
ENV PKGS xz-libs elfutils-dev libbz2

RUN eve-alpine-deploy.sh

# Build makedumpfile
WORKDIR /tmp/makedumpfile/makedumpfile-1.7.1
ADD https://github.com/makedumpfile/makedumpfile/archive/refs/tags/1.7.1.tar.gz 1.7.1.tar.gz
RUN tar -C .. -xzvf 1.7.1.tar.gz
RUN ln -s /usr/lib/libbz2.so.1 /usr/lib/libbz2.so && \
    make LINKTYPE=dynamic && \
    make DESTDIR=/out install

FROM scratch
COPY --from=build /out /
COPY kdump.sh /

WORKDIR /
ENTRYPOINT []
CMD ["/kdump.sh"]
