# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-alpine:956e170f3908aa5148b0ddb130e60fd862c7988b AS build
ENV PKGS="alpine-baselayout musl-utils bash glib squashfs-tools util-linux e2fsprogs e2fsprogs-extra keyutils dosfstools coreutils sgdisk smartmontools"
RUN eve-alpine-deploy.sh

FROM scratch
COPY --from=build /out/ /
COPY storage-init.sh /

WORKDIR /
ENTRYPOINT []
CMD ["/storage-init.sh"]
