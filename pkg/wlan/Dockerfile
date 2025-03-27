# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
FROM lfedge/eve-alpine:0f2e0da38e30753c68410727a6cc269e57ff74f2 AS build
ENV PKGS alpine-baselayout musl-utils wireless-tools wpa_supplicant
RUN eve-alpine-deploy.sh

FROM scratch
COPY --from=build /out/ /
COPY init.sh /init.sh

ENTRYPOINT []
CMD ["/init.sh"]
