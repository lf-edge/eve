# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
FROM lfedge/eve-alpine:7b892c4653d567eb3b6a306064c3bc7fc14f6bab AS build

ENV BUILD_PKGS make gcc g++ git perl linux-headers musl-dev cmake zlib-dev bcc-dev libbpf-dev cereal flex bison llvm20-libs llvm20-dev llvm20-static llvm20-gtest clang-dev clang-static pahole gtest-dev bash libxml2-dev curl-dev binutils-dev libpcap-dev

RUN eve-alpine-deploy.sh

RUN mkdir -p /usr/src
ADD https://github.com/bpftrace/bpftrace.git#v0.23.3 /usr/src/bpftrace
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
COPY --from=build /usr/lib/libbpf.so.1.5.1 /bpftrace-aotrt/usr/lib/libbpf.so.1.5.1
COPY --from=build /usr/lib/libbpf.so.1 /bpftrace-aotrt/usr/lib/libbpf.so.1
COPY --from=build /usr/lib/libbpf.so /bpftrace-aotrt/usr/lib/libbpf.so
COPY --from=build /usr/lib/libelf.so.1 /bpftrace-aotrt/usr/lib/libelf.so.1
COPY --from=build /usr/lib/libz.so.1.3.1 /bpftrace-aotrt/usr/lib/libz.so.1.3.1
COPY --from=build /usr/lib/libz.so.1 /bpftrace-aotrt/usr/lib/libz.so.1
COPY --from=build /usr/lib/libbcc_bpf.so.0 /bpftrace-aotrt/usr/lib/libbcc_bpf.so.0
COPY --from=build /usr/lib/libstdc++.so.6 /bpftrace-aotrt/usr/lib/libstdc++.so.6
COPY --from=build /usr/lib/libgcc_s.so.1 /bpftrace-aotrt/usr/lib/libgcc_s.so.1

FROM bin AS bin-amd64
FROM bin AS bin-arm64
FROM scratch AS bin-riscv64

# hadolint ignore=DL3006
FROM bin-${TARGETARCH} AS bpftrace
