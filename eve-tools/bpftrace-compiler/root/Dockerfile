# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

ARG EVE_KERNEL
# hadolint ignore=DL3006
FROM ${EVE_KERNEL} AS kernel

FROM lfedge/eve-bpftrace:545e3bbafb752d756923c8e2ec2d4869b0f7cd8c AS eve-bpftrace

FROM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544 AS bpftrace

# The tracer root is assembled from scratch in /tracer, as the Alpine one was:
# linuxkit merges it with the kernel's /lib/modules, which does not go together
# with the usr-merge links (lib -> usr/lib, ...) of the base's container rootfs.
# bpftrace, bpftrace-aotrt and every library they need come complete from the
# eve-bpftrace image; busybox has to be the static one, there is no musl loader.
ENV BUILD_PKGS="busybox-static"
RUN eve-ubuntu-deploy.sh
RUN mkdir -p /tracer/bin /tracer/mnt /tracer/usr/bin && cp /usr/bin/busybox /tracer/usr/bin/

COPY --from=kernel /kernel-headers.tar /
WORKDIR /tracer
RUN tar xvf /kernel-headers.tar

COPY --from=eve-bpftrace /bpftrace/ /tracer/
COPY --from=eve-bpftrace /bpftrace-aotrt/ /tracer/
# the dynamic loader under its canonical path (/lib64/ld-linux-x86-64.so.2, /lib/ld-linux-aarch64.so.1)
RUN for l in usr/lib64/ld-*.so* usr/lib/ld-*.so*; do [ -e "$l" ] || continue; d=${l%/*}; d=${d#usr/}; mkdir -p "$d" && ln -s "../$l" "$d/${l##*/}"; done

RUN mkdir -p /usr/src/bpftrace-helper
COPY bpftrace-helper /usr/src/bpftrace-helper
WORKDIR /usr/src/bpftrace-helper
RUN CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -o /bpftrace-helper

RUN touch /bpftrace-aotrt # bpftrace wants to call this binary, but does not care about outcome
RUN chmod a+x /bpftrace-aotrt

FROM scratch
WORKDIR /
COPY --from=bpftrace /tracer /
# init
COPY --from=bpftrace /bpftrace-helper /sbin/init
COPY --from=bpftrace /bpftrace-aotrt /usr/bin/bpftrace-aotrt
