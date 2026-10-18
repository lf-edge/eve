# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# hadolint ignore=DL3029
FROM --platform=$BUILDPLATFORM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544 AS build
ARG TARGETARCH

# build the tpm-recovery tool
WORKDIR /
COPY src/ recover-tpm/

WORKDIR /recover-tpm
SHELL ["/bin/bash", "-eo", "pipefail", "-c"]
# hadolint ignore=SC2046
RUN echo "Running go vet" && GOARCH=${TARGETARCH} go vet ./... && echo "Running go fmt" && \
    ERR=$(gofmt -e -l -s $(find . -name \*.go | grep -v /vendor/)) && \
    if [ -n "$ERR" ] ; then echo "go fmt Failed - ERR: $ERR"; exit 1 ; fi
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags "-s -w" -o recovertpm .

FROM scratch
WORKDIR /

COPY --from=build /recover-tpm/recovertpm /usr/bin/recovertpm
