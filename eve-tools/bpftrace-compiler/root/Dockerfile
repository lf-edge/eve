# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

ARG EVE_KERNEL
# hadolint ignore=DL3006
FROM ${EVE_KERNEL} AS kernel

FROM lfedge/eve-bpftrace:bc625d6870b12ba0255555d5f14acd3d3ab7e123 AS eve-bpftrace

FROM lfedge/eve-alpine:fdd203cfda43dadd2b363ce843e073e9d7d89ea8 AS bpftrace

# Runtime libraries of the bpftrace 0.23.3 build in pkg/bpftrace (LLVM 20),
# copied into the compile VM by copy-out.sh (which needs ldd from musl-utils).
# hadolint ignore=DL3018
RUN apk add --no-cache --initdb musl-utils llvm20-libs clang20-libs clang20-libclang bcc libbpf libpcap binutils libelf zlib libstdc++ libgcc
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
