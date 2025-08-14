# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
FROM lfedge/eve-alpine:cce89c6b13294f2ddaffe8ba7120833a2802a4d5 AS build
ENV BUILD_PKGS git go
ENV PKGS coreutils
RUN eve-alpine-deploy.sh

COPY ./  /newlog/.
WORKDIR /newlog
ARG GOPKGVERSION

RUN GO111MODULE=on CGO_ENABLED=0 go build -ldflags "-s -w -X=main.Version=${GOPKGVERSION}" -mod=vendor -o /out/usr/bin/newlogd ./cmd

# required for pubsub
RUN rm -rf /out/var/run && mkdir -p /out/run /out/var && ln -s /run /out/var

FROM scratch
COPY --from=build /out/ /
COPY newlogd-init.sh /newlogd-init.sh

WORKDIR /newlog
ENTRYPOINT []
CMD ["/newlogd-init.sh"]
