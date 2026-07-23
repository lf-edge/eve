# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
# hadolint ignore=DL3029
FROM --platform=$BUILDPLATFORM lfedge/eve-alpine:39f46094f640424c345164420ed789afd8a4088b AS build
ARG TARGETARCH

COPY *.go     /storage-resizer/
COPY go.mod   /storage-resizer/
COPY go.sum   /storage-resizer/
COPY vendor   /storage-resizer/vendor
ARG GOPKGVERSION

WORKDIR /storage-resizer

ENV CGO_ENABLED=0
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
# hadolint ignore=SC2046
RUN echo "Running go vet" && GOARCH=${TARGETARCH} go vet -mod=vendor ./... && echo "Running go fmt" && \
    ERR=$(gofmt -e -l -s $(find . -name \*.go | grep -v /vendor/)) && \
    if [ -n "$ERR" ] ; then echo "go fmt Failed - ERR: $ERR"; exit 1 ; fi

RUN GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags "-s -w" -mod=vendor -o /out/usr/bin/storage-resizer .

# The binary is static and self-contained; the filesystem/partition tools it
# shells out to (resize2fs, e2fsck, fsck.fat, sgdisk, partx) are provided by the
# container it runs inside (storage-init / pillar), not bundled here.
FROM scratch
COPY --from=build /out/ /

WORKDIR /
ENTRYPOINT ["/usr/bin/storage-resizer"]
CMD []
