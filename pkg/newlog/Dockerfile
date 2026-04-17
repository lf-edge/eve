# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# hadolint ignore=DL3006
FROM lfedge/eve-alpine:1f744180283ffb4eabcc3862531aeacf1de886b3 AS runtime
ENV PKGS coreutils
RUN eve-alpine-deploy.sh

# hadolint ignore=DL3029
FROM --platform=$BUILDPLATFORM lfedge/eve-alpine:1f744180283ffb4eabcc3862531aeacf1de886b3 AS build
ARG TARGETARCH

COPY go.mod /newlog/
COPY go.sum /newlog/
COPY cmd /newlog/cmd
COPY vendor /newlog/vendor

WORKDIR /newlog
ARG GOPKGVERSION

RUN GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags "-s -w -X=main.Version=${GOPKGVERSION}" -mod=vendor -o /out/usr/bin/newlogd ./cmd

# required for pubsub
RUN rm -rf /out/var/run && mkdir -p /out/run /out/var && ln -s /run /out/var

FROM scratch
COPY --from=runtime /out/ /
COPY --from=build /out/ /
COPY newlogd-init.sh /newlogd-init.sh

WORKDIR /newlog
ENTRYPOINT []
CMD ["/newlogd-init.sh"]
