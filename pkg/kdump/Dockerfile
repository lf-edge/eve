# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
FROM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544 AS build

ENV BUILD_PKGS="patch curl make gcc perl uuid-dev git mtools linux-libc-dev libc6-dev liblzma-dev libelf-dev libdw-dev libbz2-dev zlib1g-dev"
ENV PKGS="liblzma5 libelf1t64 libdw1t64 libbz2-1.0 zlib1g util-linux mount coreutils"

RUN eve-ubuntu-deploy.sh

# Build makedumpfile
WORKDIR /tmp/makedumpfile/makedumpfile-1.7.1
ADD https://github.com/makedumpfile/makedumpfile/archive/refs/tags/1.7.1.tar.gz 1.7.1.tar.gz
RUN tar -C .. -xzvf 1.7.1.tar.gz
# makedumpfile declares functions without prototypes, which C23 (gcc 15's default) rejects
RUN make LINKTYPE=dynamic CC="gcc -std=gnu17" && \
    make DESTDIR=/out install

# Register makedumpfile in the dpkg status area, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n makedumpfile -v 1.7.1 -l GPL-2.0-only -u https://github.com/makedumpfile/makedumpfile

FROM scratch
COPY --from=build /out /
COPY kdump.sh /

WORKDIR /
ENTRYPOINT []
CMD ["/kdump.sh"]
