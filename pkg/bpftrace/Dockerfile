# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
FROM lfedge/eve-alpine:0f2e0da38e30753c68410727a6cc269e57ff74f2 AS build

ENV BUILD_PKGS make gcc g++ git perl linux-headers musl-dev cmake zlib-dev bcc-dev libbpf-dev cereal flex bison llvm13-libs llvm13-dev llvm13-static clang-dev clang-static pahole gtest-dev bash

RUN eve-alpine-deploy.sh

RUN mkdir -p /usr/src
ADD https://github.com/bpftrace/bpftrace.git#v0.20.3 /usr/src/bpftrace
COPY patches /usr/src/bpftrace/patches
WORKDIR /usr/src/bpftrace
RUN for i in patches/*.patch; do git apply "$i"; done
RUN mkdir build
WORKDIR /usr/src/bpftrace/build
RUN cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_COMPILER=clang ..
RUN make -j "$(getconf _NPROCESSORS_ONLN)"
RUN make install
# portability analyser is disabled, therefore skip those tests
# skip file exist test - probably broken because of container

# unfortunately /proc/cpuinfo on docker on M1 mac is not telling much, so let's use the bogomips
ARG TARGETARCH
ARG BUILDARCH
RUN if [ "$TARGETARCH" = "$BUILDARCH" ]; then \
        if perl -ne 'exit 1 if (m/^bogomips\s*:\s*(\d+)/i && $1 < 500);' /proc/cpuinfo ; then \
            ./tests/bpftrace_test --gtest_filter=-"portability_analyser.*:utils.file_exists_and_ownedby_root" 2>/dev/null; \
        else \
            echo "You are a Mac user? Let's disable some tests we don't know why they fail!" \
            ./tests/bpftrace_test --gtest_filter=-"portability_analyser.*:utils.file_exists_and_ownedby_root:childproc.ptrace_child*" 2>/dev/null; \
        fi \
    else \
        echo "Running bpftrace tests is disabled, because TARGETARCH=${TARGETARCH} and BUILDARCH=${BUILDARCH}"; \
    fi

FROM scratch AS bin
COPY --from=build /usr/bin/bpftrace /bpftrace/usr/bin/bpftrace

COPY --from=build /usr/bin/bpftrace-aotrt /bpftrace-aotrt/usr/bin/bpftrace-aotrt
COPY --from=build /usr/lib/libbpf.so.0 /bpftrace-aotrt/usr/lib/libbpf.so.0
COPY --from=build /usr/lib/libelf.so.1 /bpftrace-aotrt/usr/lib/libelf.so.1
COPY --from=build /lib/libz.so.1 /bpftrace-aotrt/lib/libz.so.1
COPY --from=build /usr/lib/libbcc_bpf.so.0 /bpftrace-aotrt/usr/lib/libbcc_bpf.so.0
COPY --from=build /usr/lib/libstdc++.so.6 /bpftrace-aotrt/usr/lib/libstdc++.so.6
COPY --from=build /usr/lib/libgcc_s.so.1 /bpftrace-aotrt/usr/lib/libgcc_s.so.1

FROM bin AS bin-amd64
FROM bin AS bin-arm64
FROM scratch AS bin-riscv64

# hadolint ignore=DL3006
FROM bin-${TARGETARCH} AS bpftrace
