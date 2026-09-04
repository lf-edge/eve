# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-alpine:d075dd224fa7a7540817d224cc28d3cd998ad04c AS build
ENV PKGS="alpine-baselayout musl-utils bash glib squashfs-tools util-linux e2fsprogs e2fsprogs-extra keyutils dosfstools coreutils sgdisk smartmontools"
RUN eve-alpine-deploy.sh

# storage-resizer drives the EVE-kvm<->EVE-k boot-disk repartition; storage-init
# execs it for the offline shrink/grow and the post-mount restore/cleanup. The
# filesystem/partition tools it shells out to (resize2fs, e2fsck, fsck.fat,
# sgdisk, partx) are in the PKGS above.
FROM lfedge/eve-storage-resizer:7676796214b5d9f2ed6321b644c06a8e9747e22b AS storage-resizer

FROM scratch
COPY --from=build /out/ /
COPY --from=storage-resizer /usr/bin/storage-resizer /usr/bin/storage-resizer
COPY storage-init.sh /
COPY storage-resize.sh /

WORKDIR /
ENTRYPOINT []
CMD ["/storage-init.sh"]
