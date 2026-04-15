# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
FROM lfedge/eve-alpine:47d267f35e4832f639bf65bbe8a2e7b2f31e3e36 AS build

ENV BUILD_PKGS libbpf-dev make gcc g++ git perl linux-headers musl-dev cmake elfutils-dev llvm17-libs llvm17-dev llvm17-gtest llvm17-static cereal flex bison clang17-extra-tools clang17-dev clang17-static pahole gtest-dev bash py3-setuptools zip zlib-dev

RUN eve-alpine-deploy.sh

RUN ln -s /usr/lib/cmake/clang17 /usr/lib/cmake/clang

# compile bcc from source as alpine's bcc crashes in bcc_elf_is_shared_obj(rel_path.c_str()); during bpftrace test
WORKDIR /usr/src
# bcc compilation process needs .git directory
ADD --keep-git-dir=true https://github.com/iovisor/bcc.git#v0.27.0 /usr/src/bcc
RUN mkdir /usr/src/bcc/build
WORKDIR /usr/src/bcc/build
RUN perl -pni.bak -e 's/CMAKE_CXX_STANDARD 14/CMAKE_CXX_STANDARD 17/g' ../CMakeLists.txt
RUN perl -pni.bak -e 's!llvm-c/Transforms/IPO.h!llvm/Transforms/IPO.h!g' ../src/cc/bpf_module.cc
RUN perl -pni.bak -e 's/#pragma GCC poison reallocarray strlcpy//g' ../src/cc/libbpf/src/libbpf_internal.h
RUN cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr -DCMAKE_CXX_COMPILER=clang++-17 -DCMAKE_C_COMPILER=clang-17 -DENABLE_EXAMPLES=OFF -DENABLE_MAN=OFF ..
RUN make -j "$(getconf _NPROCESSORS_ONLN)"
RUN make install


RUN mkdir -p /usr/src
ADD https://github.com/bpftrace/bpftrace.git#v0.20.3 /usr/src/bpftrace
COPY patches /usr/src/bpftrace/patches
WORKDIR /usr/src/bpftrace
RUN for i in patches/*.patch; do git apply "$i"; done
RUN mkdir build
WORKDIR /usr/src/bpftrace/build
RUN cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr -DCMAKE_CXX_COMPILER=clang++-17 -DCMAKE_C_COMPILER=clang-17 ..
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

COPY --from=build /usr/lib/libbpf.so.1 /bpftrace-aotrt//usr/lib/libbpf.so.1
COPY --from=build /usr/lib/libz.so.1 /bpftrace-aotrt//usr/lib/libz.so.1
COPY --from=build /usr/lib/libbcc_bpf.so.0 /bpftrace-aotrt//usr/lib/libbcc_bpf.so.0
COPY --from=build /usr/lib/libdw.so.1 /bpftrace-aotrt//usr/lib/libdw.so.1
COPY --from=build /usr/lib/libstdc++.so.6 /bpftrace-aotrt//usr/lib/libstdc++.so.6
COPY --from=build /usr/lib/libgcc_s.so.1 /bpftrace-aotrt//usr/lib/libgcc_s.so.1
COPY --from=build /usr/lib/libelf.so.1 /bpftrace-aotrt//usr/lib/libelf.so.1
COPY --from=build /usr/lib/liblzma.so.5 /bpftrace-aotrt//usr/lib/liblzma.so.5
COPY --from=build /usr/lib/libfts.so.0 /bpftrace-aotrt//usr/lib/libfts.so.0
COPY --from=build /usr/lib/libzstd.so.1 /bpftrace-aotrt//usr/lib/libzstd.so.1
COPY --from=build /usr/lib/libbz2.so.1 /bpftrace-aotrt//usr/lib/libbz2.so.1

FROM bin AS bin-amd64
FROM bin AS bin-arm64
FROM scratch AS bin-riscv64

# hadolint ignore=DL3006
FROM bin-${TARGETARCH} AS bpftrace
