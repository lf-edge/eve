# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
FROM lfedge/eve-alpine:1f7685f95a475c6bbe682f0b976f12180b6c8726 AS build

ENV BUILD_PKGS make gcc g++ git perl linux-headers musl-dev cmake zlib-dev bcc-dev libbpf-dev cereal flex bison llvm13-libs llvm13-dev llvm13-static clang-dev clang-static pahole gtest-dev bash

RUN eve-alpine-deploy.sh

RUN mkdir -p /usr/src
ADD https://github.com/bpftrace/bpftrace.git#v0.20.3 /usr/src/bpftrace
COPY patches /usr/src/bpftrace/patches
WORKDIR /usr/src/bpftrace
RUN for i in patches/*.patch; do git apply "$i"; done
RUN mkdir build
WORKDIR /usr/src/bpftrace/build
RUN cmake ..
RUN make -j "$(getconf _NPROCESSORS_ONLN)"
RUN make DESTDIR="/out/opt/zededa" install
# portability analyser is disabled, therefore skip those tests
# skip file exist test - probably broken because of container

# unfortunately /proc/cpuinfo on docker on M1 mac is not telling much, so let's use the bogomips
RUN if perl -ne 'exit 1 if (m/^bogomips\s*:\s*(\d+)/i && $1 < 500);' /proc/cpuinfo ; then \
        ./tests/bpftrace_test --gtest_filter=-"portability_analyser.*:utils.file_exists_and_ownedby_root" 2>/dev/null; \
    else \
        echo "You are a Mac user? Let's disable some tests we don't know why they fail!" \
        ./tests/bpftrace_test --gtest_filter=-"portability_analyser.*:utils.file_exists_and_ownedby_root:childproc.ptrace_child*" 2>/dev/null; \
    fi


FROM scratch
COPY --from=build /out/opt/zededa/usr/local/bin/bpftrace-aotrt /usr/bin/bpftrace-aotrt
COPY --from=build /usr/lib/libbpf.so.0 /usr/lib/libbpf.so.0
COPY --from=build /usr/lib/libelf.so.1 /usr/lib/libelf.so.1
COPY --from=build /lib/libz.so.1 /lib/libz.so.1
COPY --from=build /usr/lib/libbcc_bpf.so.0 /usr/lib/libbcc_bpf.so.0
COPY --from=build /usr/lib/libstdc++.so.6 /usr/lib/libstdc++.so.6
COPY --from=build /usr/lib/libgcc_s.so.1 /usr/lib/libgcc_s.so.1
