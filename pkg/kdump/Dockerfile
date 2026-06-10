# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
FROM lfedge/eve-alpine:956e170f3908aa5148b0ddb130e60fd862c7988b AS build

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

# Register makedumpfile in the APK DB, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n makedumpfile -v 1.7.1 -l GPL-2.0-only -u https://github.com/makedumpfile/makedumpfile

FROM scratch
COPY --from=build /out /
COPY kdump.sh /

WORKDIR /
ENTRYPOINT []
CMD ["/kdump.sh"]
