# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

ARG GOLANG_VERSION=1.25

# hadolint ignore=DL3029
FROM --platform=$BUILDPLATFORM golang:${GOLANG_VERSION} AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /out/volverify ./cmd/volverify && \
    cp scripts/devside-verify.sh /out/devside-verify.sh

FROM ubuntu:24.04

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends openssh-server e2fsprogs && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir /run/sshd

RUN echo 'root:testpassword' | chpasswd
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
EXPOSE 22

# The verdict script and the binary it runs arrive in ONE layer, because they
# have to be siblings on disk: EVE's dom0 runs the script straight out of
# containerd's unpacked image to judge a volume the conversion carried over, and
# the script resolves the binary next to itself. Separate COPY instructions put
# them in separate overlayfs layers, where that lookup finds nothing. Inside the
# app both are on $PATH for a by-hand check during a stuck upgrade.
COPY --from=build /out/ /usr/local/bin/
COPY init.sh /

CMD ["/bin/bash", "/init.sh"]
