# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

ARG EVE_KERNEL
# hadolint ignore=DL3006
FROM ${EVE_KERNEL} AS kernel

FROM lfedge/eve-bpftrace:7c4d9eff6f2d72e6da23ff7e31f78e45752306e8 AS eve-bpftrace

FROM lfedge/eve-alpine:a5885b38222df4ba5add4acca2d219c85741bf79 AS bpftrace

# hadolint ignore=DL3018
RUN apk add --no-cache --initdb make gcc g++ git perl musl-dev cmake zlib-dev bcc-dev libbpf-dev cereal flex bison llvm20-libs llvm20-dev llvm20-static clang20-dev clang20-static clang20-libclang pahole gtest-dev bash binutils libpcap
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

RUN mkdir -p /usr/src/bpftrace-helper
COPY bpftrace-helper /usr/src/bpftrace-helper
WORKDIR /usr/src/bpftrace-helper
RUN CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -o /bpftrace-helper

FROM scratch
WORKDIR /
COPY --from=bpftrace /out /
# init
COPY --from=bpftrace /bpftrace-helper /sbin/init
COPY --from=alpine:3.21 /bin/busybox /usr/bin/busybox
