# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
FROM lfedge/eve-alpine:fdd203cfda43dadd2b363ce843e073e9d7d89ea8 AS build
ENV PKGS alpine-baselayout musl-utils wireless-tools wpa_supplicant
RUN eve-alpine-deploy.sh

FROM scratch
COPY --from=build /out/ /
COPY init.sh /init.sh

ENTRYPOINT []
CMD ["/init.sh"]
