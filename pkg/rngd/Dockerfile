# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
FROM lfedge/eve-alpine:0f2e0da38e30753c68410727a6cc269e57ff74f2 as build
ENV BUILD_PKGS go gcc musl-dev linux-headers
RUN eve-alpine-deploy.sh

ENV GOPATH=/go PATH=$PATH:/go/bin

# see https://github.com/golang/go/issues/23672
ENV CGO_CFLAGS_ALLOW=(-mrdrnd|-mrdseed)
ARG GOPKGVERSION

COPY cmd/rngd/ /go/src/rngd/
RUN GO111MODULE=auto REQUIRE_CGO=1 ldflags="-X main.Version=${GOPKGVERSION}" go-compile.sh /go/src/rngd

FROM scratch
ENTRYPOINT []
WORKDIR /
COPY --from=build /go/bin/rngd /sbin/rngd
CMD ["/sbin/rngd"]
