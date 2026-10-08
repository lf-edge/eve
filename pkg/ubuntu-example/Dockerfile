# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-ubuntu:9a6ebfad80ca4d18950553f8bf2c01a068869805 AS ubuntu
FROM ubuntu AS build

ENV PKGS="curl"
ENV BUILD_PKGS="gcc openssh-client"

RUN --mount=type=bind,from=ubuntu,source=/mirror,target=/out/mirror sh -x /bin/eve-ubuntu-deploy.sh

FROM scratch
COPY --from=build /out/ /
