# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
FROM lfedge/eve-alpine:1f7685f95a475c6bbe682f0b976f12180b6c8726 as build
ENV BUILD_PKGS git go
ENV PKGS alpine-baselayout musl-utils iproute2 iptables
RUN eve-alpine-deploy.sh

COPY src/  /edge-view/.
COPY go.mod /edge-view/.
COPY go.sum /edge-view/.
COPY vendor /edge-view/vendor
ARG GOPKGVERSION
WORKDIR /edge-view

ENV CGO_ENABLED=0
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
# hadolint ignore=SC2046
RUN echo "Running go vet" && go vet ./... && echo "Running go fmt" && \
    ERR=$(gofmt -e -l -s $(find . -name \*.go | grep -v /vendor/)) && \
    if [ -n "$ERR" ] ; then echo "go fmt Failed - ERR: $ERR"; exit 1 ; fi

RUN GO111MODULE=on CGO_ENABLED=0 go build -ldflags "-s -w -X=main.Version=${GOPKGVERSION}" -mod=vendor -o /out/usr/bin/edge-view . && cp edge-view-init.sh /out/usr/bin

FROM scratch
COPY --from=build /out/ /
RUN mkdir -p /tmp && echo "hosts: files dns" > /etc/nsswitch.conf

ENV PATH="/run/debug/usr/bin:${PATH}"

WORKDIR /
ENTRYPOINT ["/usr/bin/edge-view-init.sh"]
CMD []
