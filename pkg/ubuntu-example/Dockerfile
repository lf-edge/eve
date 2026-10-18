# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544 AS build

ENV PKGS="curl"
ENV BUILD_PKGS="gcc openssh-client"

RUN eve-ubuntu-deploy.sh

FROM scratch
COPY --from=build /out/ /
