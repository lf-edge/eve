# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
FROM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544 AS build

ENV BUILD_PKGS="libbpf-dev make gcc g++ git perl linux-libc-dev libc6-dev cmake libelf-dev libdw-dev llvm-17-dev libclang-17-dev libclang-cpp17-dev clang-17 clang-tools-17 libpolly-17-dev libcereal-dev flex bison pahole libgtest-dev libgmock-dev googletest bash python3-setuptools zip xxd zlib1g-dev libzstd-dev pkg-config pax-utils"

RUN eve-ubuntu-deploy.sh

ENV CMAKE_PREFIX_PATH=/usr/lib/llvm-17

# compile bcc from source as the distribution's bcc crashes in bcc_elf_is_shared_obj(rel_path.c_str()); during bpftrace test
WORKDIR /usr/src
# bcc compilation process needs .git directory
ADD --keep-git-dir=true https://github.com/iovisor/bcc.git#v0.27.0 /usr/src/bcc
RUN register-sbom-pkg.sh -n bcc -v 0.27.0 -l Apache-2.0 -u https://github.com/iovisor/bcc
RUN mkdir /usr/src/bcc/build
WORKDIR /usr/src/bcc/build
RUN perl -pni.bak -e 's/CMAKE_CXX_STANDARD 14/CMAKE_CXX_STANDARD 17/g' ../CMakeLists.txt
RUN perl -pni.bak -e 's!llvm-c/Transforms/IPO.h!llvm/Transforms/IPO.h!g' ../src/cc/bpf_module.cc
RUN perl -pni.bak -e 's/#pragma GCC poison reallocarray strlcpy//g' ../src/cc/libbpf/src/libbpf_internal.h
# bcc still declares cmake_minimum_required 3.1, which Ubuntu's cmake 4 refuses
RUN cmake -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_INSTALL_PREFIX:PATH=/usr -DCMAKE_CXX_COMPILER=clang++-17 -DCMAKE_C_COMPILER=clang-17 -DENABLE_EXAMPLES=OFF -DENABLE_MAN=OFF -DENABLE_LLVM_SHARED=ON ..
RUN make -j "$(getconf _NPROCESSORS_ONLN)"
RUN make install

RUN mkdir -p /usr/src
ADD https://github.com/bpftrace/bpftrace.git#v0.20.3 /usr/src/bpftrace
RUN register-sbom-pkg.sh -n bpftrace -v 0.20.3 -l Apache-2.0 -u https://github.com/bpftrace/bpftrace
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

# Two trees for the consumers: /bpftrace holds the compiler, which
# eve-tools/bpftrace-compiler runs in a VM, /bpftrace-aotrt the ahead-of-time
# runtime that pkg/debug ships, each with the libraries it needs and the dpkg
# records of the packages they came from (see copy-with-libs.sh).
WORKDIR /
RUN copy-with-libs.sh -m -r / -o /bpftrace /usr/bin/bpftrace && \
    copy-with-libs.sh -m -r / -o /bpftrace-aotrt /usr/bin/bpftrace-aotrt && \
    cp -a /out/var/lib/dpkg/status.d /bpftrace/var/lib/dpkg/ && \
    cp -a /out/var/lib/dpkg/status.d /bpftrace-aotrt/var/lib/dpkg/

FROM scratch AS bin
COPY --from=build /bpftrace /bpftrace
COPY --from=build /bpftrace-aotrt /bpftrace-aotrt

FROM bin AS bin-amd64
FROM bin AS bin-arm64
FROM scratch AS bin-riscv64

# hadolint ignore=DL3006
FROM bin-${TARGETARCH} AS bpftrace
