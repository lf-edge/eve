# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
# hadolint ignore=DL3029
FROM --platform=$BUILDPLATFORM lfedge/eve-alpine:47d267f35e4832f639bf65bbe8a2e7b2f31e3e36 AS build
ARG TARGETARCH

COPY src/  /measure-config/.
COPY go.mod /measure-config/.
COPY go.sum /measure-config/.
COPY vendor /measure-config/vendor
ARG GOPKGVERSION

WORKDIR /measure-config

ENV CGO_ENABLED=0
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
# hadolint ignore=SC2046
RUN echo "Running go vet" && GOARCH=${TARGETARCH} go vet ./... && echo "Running go fmt" && \
    ERR=$(gofmt -e -l -s $(find . -name \*.go | grep -v /vendor/)) && \
    if [ -n "$ERR" ] ; then echo "go fmt Failed - ERR: $ERR"; exit 1 ; fi

RUN GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags "-s -w -X=main.Version=${GOPKGVERSION}" -mod=vendor -o /out/usr/bin/measure-config .

FROM scratch
COPY --from=build /out/ /

WORKDIR /
ENTRYPOINT ["/usr/bin/measure-config"]
CMD []
