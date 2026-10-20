# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2023-2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# apparmor_parser, with libapparmor linked in statically, is compiled on the
# build platform, with EVE's cross compilers when it differs from the target,
# never under emulation: only the package installs and the final profile
# check run as the target.

# Tools that run on the build platform. The parser generates its address
# family and capability tables from the build platform's <sys/socket.h> and
# <linux/capability.h>, whose values are the same on every architecture.
ARG BUILD_PKGS_BASE="linux-headers musl-dev musl-utils git gcc g++ \
    autoconf autoconf-archive automake libtool make flex bison bash sed gettext"
# Headers and libraries of the target that libapparmor and the parser build
# against.
ARG TARGET_DEV_PKGS="musl-dev musl-libintl libgcc linux-headers"
ARG EVE_ALPINE_IMAGE=lfedge/eve-alpine:080e2b4c683508649d72d2ae9b166153d819ca5d
ARG APPARMOR_VERSION=4.1.3

# The base the parser runs on.
# hadolint ignore=DL3006
FROM ${EVE_ALPINE_IMAGE} AS runtime
ARG APPARMOR_VERSION
ENV PKGS=alpine-baselayout
RUN eve-alpine-deploy.sh
# Register apparmor in the APK DB, mandatory for it to be included in the
# SBOM. It is registered here, as the target, for the record to carry the
# target's architecture.
RUN register-sbom-pkg.sh -n apparmor -v "${APPARMOR_VERSION}" -l GPL-2.0-only \
        -u https://gitlab.com/apparmor/apparmor.git

# hadolint ignore=DL3006
FROM ${EVE_ALPINE_IMAGE} AS build-native
ARG BUILD_PKGS_BASE
ARG TARGET_DEV_PKGS
RUN BUILD_PKGS="${BUILD_PKGS_BASE} ${TARGET_DEV_PKGS}" eve-alpine-deploy.sh

# hadolint ignore=DL3006,DL3029
FROM --platform=${BUILDPLATFORM} ${EVE_ALPINE_IMAGE} AS build-cross
ARG BUILD_PKGS_BASE
RUN BUILD_PKGS="${BUILD_PKGS_BASE}" eve-alpine-deploy.sh

# hadolint ignore=DL3029
FROM --platform=${BUILDPLATFORM} lfedge/eve-cross-compilers:d794c049baf50389be1dd48da056fb2472574c3e AS cross-compilers

# The target's headers and libraries, for the cross compiler's sysroot.
# hadolint ignore=DL3006
FROM ${EVE_ALPINE_IMAGE} AS cross-compile-libs
ARG TARGET_DEV_PKGS
ENV PKGS=${TARGET_DEV_PKGS}
RUN eve-alpine-deploy.sh

FROM build-cross AS build-cross-target-arm64
ENV EVE_TARGET_ARCH=aarch64
FROM build-cross AS build-cross-target-amd64
ENV EVE_TARGET_ARCH=x86_64
FROM build-cross AS build-cross-target-riscv64
ENV EVE_TARGET_ARCH=riscv64

# hadolint ignore=DL3006
FROM build-cross-target-${TARGETARCH} AS build-cross-target
ENV CROSS_COMPILE_ENV="${EVE_TARGET_ARCH}"-alpine-linux-musl-
ENV SYSROOT=/usr/"${EVE_TARGET_ARCH}"-alpine-linux-musl
COPY --from=cross-compilers /packages /packages
# hadolint ignore=DL3018
RUN apk add --no-cache --allow-untrusted -X /packages build-base-"${EVE_TARGET_ARCH}"
COPY --from=cross-compile-libs /out/ ${SYSROOT}/
# The cross compilers find the target's headers and libraries only when told
# the sysroot. It goes in CC and CXX, not CFLAGS: libapparmor and the parser
# also run the compiler without their CFLAGS, to generate their errno and
# protocol tables from the target's headers.
ENV CC="${CROSS_COMPILE_ENV}gcc --sysroot=${SYSROOT}"
ENV CXX="${CROSS_COMPILE_ENV}g++ --sysroot=${SYSROOT}"
ENV AR="${CROSS_COMPILE_ENV}ar"

# pkg/cross-compilers has compilers for every other target on amd64 and arm64
# build platforms, and none on riscv64, which builds only for itself.
FROM build-cross-target AS target-arm64-build-amd64
FROM build-cross-target AS target-riscv64-build-amd64
FROM build-cross-target AS target-amd64-build-arm64
FROM build-cross-target AS target-riscv64-build-arm64
FROM build-native AS target-amd64-build-amd64
FROM build-native AS target-arm64-build-arm64
FROM build-native AS target-riscv64-build-riscv64

# hadolint ignore=DL3006
FROM target-${TARGETARCH}-build-${BUILDARCH} AS build
ARG APPARMOR_VERSION

ADD https://gitlab.com/apparmor/apparmor.git#v${APPARMOR_VERSION} /apparmor
WORKDIR /apparmor/libraries/libapparmor
RUN ./autogen.sh
# --host only when cross compiling: it names the target's triplet, which is
# CROSS_COMPILE_ENV without the trailing dash.
# hadolint ignore=SC2086
RUN ./configure ${CROSS_COMPILE_ENV:+--host="${CROSS_COMPILE_ENV%-}"}
RUN make -j "$(getconf _NPROCESSORS_ONLN)"

WORKDIR /apparmor/parser
RUN ../common/list_af_names.sh > base_af_names.h
RUN make CFLAGS="-Os"

#Pull a selected set of artifacts into the final stage.
FROM scratch
COPY --from=runtime /out/ /
COPY --from=build /apparmor/parser/apparmor_parser /usr/bin/
COPY /etc/ /etc
COPY /profiles/* /etc/apparmor.d
COPY aa-init.sh /

RUN for i in /etc/apparmor.d/*.*; do echo "-- $i --"; /usr/bin/apparmor_parser -Q "$i"; done

WORKDIR /
ENTRYPOINT []
CMD ["/aa-init.sh"]
