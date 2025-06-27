# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-alpine:523254c1b0728948a16a02115eb817f27c00977f as build
ENV BUILD_PKGS go
RUN eve-alpine-deploy.sh

# build the tpm-recovery tool
WORKDIR /
COPY src/ recover-tpm/

WORKDIR /recover-tpm
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
# hadolint ignore=SC2046
RUN echo "Running go vet" && go vet ./... && echo "Running go fmt" && \
    ERR=$(gofmt -e -l -s $(find . -name \*.go | grep -v /vendor/)) && \
    if [ -n "$ERR" ] ; then echo "go fmt Failed - ERR: $ERR"; exit 1 ; fi
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o recovertpm .

FROM scratch
WORKDIR /

COPY --from=build /recover-tpm/recovertpm /usr/bin/recovertpm
