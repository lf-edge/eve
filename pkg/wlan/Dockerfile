# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
FROM lfedge/eve-alpine:cda433a7600c2486a9011c2de8b7e676483e25ac AS build
ENV PKGS alpine-baselayout musl-utils wireless-tools wpa_supplicant
RUN eve-alpine-deploy.sh

FROM scratch
COPY --from=build /out/ /
COPY init.sh /init.sh

ENTRYPOINT []
CMD ["/init.sh"]
