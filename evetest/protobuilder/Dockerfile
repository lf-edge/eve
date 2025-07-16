# syntax=docker/dockerfile:1.6.0

# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
FROM golang:1.24-alpine as builder

ARG TARGETOS=linux
ARG TARGETARCH
ARG PROTOC_VERSION=31.1
ARG PROTOC_GEN_GO_VERSION=1.36.6
ARG PROTOC_GEN_GO_GRPC_VERSION=1.5.1

# hadolint ignore=DL3018
RUN apk add --no-cache bash curl git go make graphviz ttf-freefont

RUN arch="$(uname -m)"; \
  # Insert underscore before the last 2 chars if not already present (e.g. aarch64 -> aarch_64)
  case "$arch" in \
    *_*) ;; \
    *) arch="${arch%??}_${arch#"${arch%??}"}" ;; \
  esac; \
  curl -fsSL -o protobuf.zip "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-${TARGETOS}-${arch}.zip"; \
  unzip protobuf.zip -d /usr/local; \
  rm -f protobuf.zip

RUN git clone https://github.com/seamia/protodot.git /protodot
RUN go build -C /protodot -o /usr/local/bin/protodot .

RUN mkdir -p "$(go env GOPATH)"
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v${PROTOC_GEN_GO_VERSION} && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v${PROTOC_GEN_GO_GRPC_VERSION} && \
    mv /go/bin/protoc-gen-go /usr/local/bin/ && \
    mv /go/bin/protoc-gen-go-grpc /usr/local/bin/
