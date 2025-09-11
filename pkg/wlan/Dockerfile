# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

ARG REL_HASH_LFEDGE_EVE_ALPINE

FROM ${REL_HASH_LFEDGE_EVE_ALPINE} AS build
ENV PKGS alpine-baselayout musl-utils wireless-tools wpa_supplicant
RUN eve-alpine-deploy.sh

FROM scratch
COPY --from=build /out/ /
COPY init.sh /init.sh

ENTRYPOINT []
CMD ["/init.sh"]
