# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2023-2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM --platform=${BUILDPLATFORM} lfedge/eve-alpine:0f2e0da38e30753c68410727a6cc269e57ff74f2 as builder-native-base
ENV BUILD_PKGS="linux-headers musl-dev musl-utils musl-libintl git gcc g++ \
               autoconf automake libtool make flex bison bash sed gettext"
ENV PKGS alpine-baselayout
RUN eve-alpine-deploy.sh

FROM --platform=${BUILDPLATFORM} lfedge/eve-cross-compilers:fb809cfb1909752acb563e0b77cd3799534bce64 AS cross-compilers

FROM builder-native-base as builder-cross-base
COPY --from=cross-compilers /packages /packages

FROM builder-cross-base as builder-target-arm64
ARG COMPILER_TARGET_ARCH=aarch64

FROM builder-cross-base as builder-target-amd64
ARG COMPILER_TARGET_ARCH=x86_64

FROM --platform=${TARGETPLATFORM} lfedge/eve-alpine:0f2e0da38e30753c68410727a6cc269e57ff74f2 as target-sysroot
# Install the target sysroot
ENV BUILD_PKGS="musl-dev libgcc musl-libintl libintl  linux-headers"
RUN eve-alpine-deploy.sh

#hadolint ignore=DL3006
FROM builder-target-${TARGETARCH} as builder-target
# install cross compiler
#hadolint ignore=DL3006,DL3018
RUN apk add --no-cache --allow-untrusted -X /packages "build-base-${COMPILER_TARGET_ARCH}"

FROM builder-target as builder-amd64-arm64
ENV CONFIGURE_TARGETS="--build=aarch64-alpine-linux-musl --host=x86_64-alpine-linux-musl"
# copy libraries from target-sysroot
COPY --from=target-sysroot /usr/lib/ /usr/x86_64-alpine-linux-musl/lib/
COPY --from=target-sysroot /usr/include/ /usr/x86_64-alpine-linux-musl/include/
ENV CXX=x86_64-alpine-linux-musl-g++


FROM builder-target as builder-arm64-amd64
ENV CONFIGURE_TARGETS="--host=aarch64-alpine-linux-musl --build=x86_64-alpine-linux-musl"
# copy libraries from target-sysroot
COPY --from=target-sysroot /usr/lib/ /usr/aarch64-alpine-linux-musl/lib/
COPY --from=target-sysroot /usr/include/ /usr/aarch64-alpine-linux-musl/include/
ENV CXX=aarch64-alpine-linux-musl-g++


FROM builder-native-base as builder-amd64-amd64
ENV CONFIGURE_TARGETS=

FROM builder-native-base as builder-arm64-arm64
ENV CONFIGURE_TARGETS=

#hadolint ignore=DL3006
FROM builder-${TARGETARCH}-${BUILDARCH} as builder

ADD https://gitlab.com/apparmor/apparmor.git#v3.1.4 /apparmor
WORKDIR /apparmor/libraries/libapparmor
# hadolint ignore=SC2086
RUN ./autogen.sh && \
    (./configure ${CONFIGURE_TARGETS} || cat ./config.log) && \
    make -j"$(nproc)"

WORKDIR /apparmor/parser
RUN ../common/list_af_names.sh > base_af_names.h && \
    make -j"$(nproc)"

#Pull a selected set of artifacts into the final stage.
FROM scratch
COPY --from=builder /out/ /
COPY --from=builder /apparmor/parser/apparmor_parser /usr/bin/
COPY /etc/ /etc
COPY /profiles/* /etc/apparmor.d
COPY aa-init.sh /

WORKDIR /
ENTRYPOINT []
CMD ["/aa-init.sh"]
