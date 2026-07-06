# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

ARG EVE_KERNEL
# hadolint ignore=DL3006
FROM ${EVE_KERNEL} AS kernel

FROM lfedge/eve-bpftrace:44a21d005fa06c52d34e5f0e5073db3268d5e212 AS eve-bpftrace

FROM lfedge/eve-alpine:f9b45a5a3b3a18a8503cbe6d1258a1025450fe0e AS bpftrace

# hadolint ignore=DL3018
RUN apk add --no-cache --initdb binutils make gcc g++ git perl musl-dev cmake zlib-dev bcc-dev libbpf-dev cereal flex bison llvm17-libs llvm17-dev llvm17-static clang17-dev clang17-static pahole gtest-dev bash
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

RUN touch /bpftrace-aotrt # bpftrace wants to call this binary, but does not care about outcome
RUN chmod a+x /bpftrace-aotrt

FROM scratch
WORKDIR /
COPY --from=bpftrace /out /
# init
COPY --from=bpftrace /bpftrace-helper /sbin/init
COPY --from=bpftrace /bpftrace-aotrt /usr/bin/bpftrace-aotrt
COPY --from=alpine:3.21 /bin/busybox /usr/bin/busybox
