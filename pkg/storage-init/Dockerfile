# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

ARG REL_HASH_LFEDGE_EVE_ALPINE

FROM ${REL_HASH_LFEDGE_EVE_ALPINE} AS build
ENV PKGS="alpine-baselayout musl-utils bash glib squashfs-tools util-linux e2fsprogs e2fsprogs-extra keyutils dosfstools coreutils sgdisk smartmontools"
RUN eve-alpine-deploy.sh

FROM scratch
COPY --from=build /out/ /
COPY storage-init.sh /

WORKDIR /
ENTRYPOINT []
CMD ["/storage-init.sh"]
