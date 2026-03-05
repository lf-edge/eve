# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-alpine:1f744180283ffb4eabcc3862531aeacf1de886b3 AS build-arm64

ARG BUILD_PKGS="bash binutils-dev bsd-compat-headers build-base bc bison \
  cmake flex openssl-dev util-linux-dev linux-headers swig git gnutls-dev \
  perl python3 python3-dev py3-setuptools py3-pycryptodome py3-elftools pkgconfig"

# hadolint ignore=DL3006
RUN eve-alpine-deploy.sh

COPY patches /patches

ENV OPTEE_CLIENT_VERSION=4.9.0
ADD --keep-git-dir=true https://github.com/OP-TEE/optee_client.git#${OPTEE_CLIENT_VERSION} /optee_client

WORKDIR /optee_client

# Apply patches
RUN git config --global user.name 'Project EVE' && \
    git config --global user.email 'builder@projecteve.dev' && \
    for x in /patches/*.patch; do \
      git am $x; \
    done

# Build tee-supplicant
RUN cmake -DCMAKE_INSTALL_PREFIX=/out/usr && \
      make -j "$(getconf _NPROCESSORS_ONLN)" && \
      make install

FROM scratch AS output-amd64
FROM scratch AS output-riscv64

FROM scratch AS output-arm64
ENTRYPOINT []
CMD []
ADD rootfs/ /
COPY --from=build-arm64 /out /

ARG TARGETARCH
FROM output-${TARGETARCH}
ENTRYPOINT []
CMD []
