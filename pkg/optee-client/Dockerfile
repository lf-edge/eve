# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544 AS build-arm64

ARG BUILD_PKGS="bash binutils-dev build-essential bc bison \
  cmake flex libssl-dev uuid-dev linux-libc-dev swig git libgnutls28-dev \
  perl python3 python3-dev python3-setuptools python3-pycryptodome python3-pyelftools pkg-config"

# hadolint ignore=DL3006
RUN eve-ubuntu-deploy.sh

ENV OPTEE_CLIENT_VERSION=4.9.0
ADD --keep-git-dir=true https://github.com/OP-TEE/optee_client.git#${OPTEE_CLIENT_VERSION} /optee_client

WORKDIR /optee_client

# Build tee-supplicant
RUN cmake -DCMAKE_INSTALL_PREFIX=/build/usr && \
      make -j "$(getconf _NPROCESSORS_ONLN)" && \
      make install

# Register optee_client in the dpkg status area, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n optee_client -v "${OPTEE_CLIENT_VERSION}" -l BSD-2-Clause -u https://github.com/OP-TEE/optee_client

FROM scratch AS output-amd64
FROM scratch AS output-riscv64

FROM scratch AS output-arm64
ENTRYPOINT []
CMD []
ADD rootfs/ /
COPY --from=build-arm64 /build/usr/etc/* /etc/
COPY --from=build-arm64 /build/usr/lib/* /usr/lib/
COPY --from=build-arm64 /build/usr/sbin/* /usr/sbin/
COPY --from=build-arm64 /out/var/lib/dpkg/status.d /var/lib/dpkg/status.d

ARG TARGETARCH
FROM output-${TARGETARCH}
ENTRYPOINT []
CMD []
