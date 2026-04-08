# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# hadolint ignore=DL3006
FROM lfedge/eve-alpine:47d267f35e4832f639bf65bbe8a2e7b2f31e3e36 AS runtime
ENV PKGS alpine-baselayout musl-utils iproute2 iptables
RUN eve-alpine-deploy.sh

# hadolint ignore=DL3029
FROM --platform=$BUILDPLATFORM lfedge/eve-alpine:47d267f35e4832f639bf65bbe8a2e7b2f31e3e36 AS build
ARG TARGETARCH

COPY src/  /edge-view/.
COPY go.mod /edge-view/.
COPY go.sum /edge-view/.
COPY vendor /edge-view/vendor
ARG GOPKGVERSION
WORKDIR /edge-view

ENV CGO_ENABLED=0
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
# hadolint ignore=SC2046
RUN echo "Running go vet" && GOARCH=${TARGETARCH} go vet ./... && echo "Running go fmt" && \
    ERR=$(gofmt -e -l -s $(find . -name \*.go | grep -v /vendor/)) && \
    if [ -n "$ERR" ] ; then echo "go fmt Failed - ERR: $ERR"; exit 1 ; fi

RUN GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags "-s -w -X=main.Version=${GOPKGVERSION}" -mod=vendor -o /out/usr/bin/edge-view . && cp edge-view-init.sh /out/usr/bin

FROM scratch
COPY --from=runtime /out/ /
COPY --from=build /out/ /
RUN mkdir -p /tmp && echo "hosts: files dns" > /etc/nsswitch.conf

ENV PATH="/run/debug/usr/bin:${PATH}"

WORKDIR /
ENTRYPOINT ["/usr/bin/edge-view-init.sh"]
CMD []
