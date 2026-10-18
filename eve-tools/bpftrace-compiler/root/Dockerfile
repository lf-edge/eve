# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

ARG EVE_KERNEL
# hadolint ignore=DL3006
FROM ${EVE_KERNEL} AS kernel

FROM lfedge/eve-bpftrace:12b393f966ce2fb81d10e80f487b7b179d6a86b3 AS eve-bpftrace

FROM lfedge/eve-ubuntu:ce501daedafe54c66d1d2561e0cd215d49ea1f60 AS bpftrace

# the headers libclang needs to parse the kernel headers at run time come
# with clang; bpftrace itself and its libraries come from the eve-bpftrace image
ENV PKGS="binutils make gcc g++ git perl libc6-dev cmake zlib1g-dev libbpf-dev libcereal-dev flex bison llvm-17-dev libclang-17-dev clang-17 pahole libgtest-dev bash"
RUN eve-ubuntu-deploy.sh
WORKDIR /
COPY copy-out.sh /
RUN mkdir /out/bin /out/mnt

COPY --from=kernel /kernel-headers.tar /
WORKDIR /out
RUN tar xvf /kernel-headers.tar

COPY --from=eve-bpftrace /bpftrace/ /out/
COPY --from=eve-bpftrace /bpftrace-aotrt/ /out/
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
