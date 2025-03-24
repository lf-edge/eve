# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

ARG EVE_KERNEL
# hadolint ignore=DL3006
FROM ${EVE_KERNEL} AS kernel

FROM lfedge/eve-bpftrace:64f87b9dfce42524b0364159a6cc3b88ae3445b2 AS eve-bpftrace

FROM lfedge/eve-alpine:0f2e0da38e30753c68410727a6cc269e57ff74f2 AS bpftrace

# hadolint ignore=DL3018
RUN apk add --no-cache --initdb make gcc g++ git perl musl-dev cmake zlib-dev bcc-dev libbpf-dev cereal flex bison llvm13-libs llvm13-dev llvm13-static clang-dev clang-static pahole gtest-dev bash
WORKDIR /
COPY copy-out.sh /
RUN mkdir /out
RUN mkdir /out/bin
RUN mkdir /out/mnt

COPY --from=kernel /kernel-headers.tar /
WORKDIR /out
RUN tar xvf /kernel-headers.tar

COPY --from=eve-bpftrace /bpftrace/usr/bin/bpftrace /out/usr/bin/bpftrace
COPY --from=eve-bpftrace /bpftrace-aotrt/ /out
RUN /copy-out.sh /out/usr/bin/bpftrace /out

FROM alpine:3.16 AS bpftrace-helper-compile
# hadolint ignore=DL3018
RUN apk add --no-cache --initdb go
RUN mkdir -p /usr/src/bpftrace-helper
COPY bpftrace-helper /usr/src/bpftrace-helper
WORKDIR /usr/src/bpftrace-helper
RUN CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -o /bpftrace-helper

FROM scratch
WORKDIR /
COPY --from=bpftrace /out /
# init
COPY --from=bpftrace-helper-compile /bpftrace-helper /sbin/init
COPY --from=alpine:3.16 /bin/busybox /usr/bin/busybox
