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
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /volverify ./cmd/volverify

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

COPY --from=build /volverify /usr/local/bin/volverify
# Alongside the binary: EVE's dom0 runs it out of the unpacked image to judge a
# volume the conversion carried over, and it is on $PATH inside the app for a
# by-hand check during a stuck upgrade.
COPY scripts/devside-verify.sh /usr/local/bin/devside-verify.sh
COPY init.sh /

CMD ["/bin/bash", "/init.sh"]
