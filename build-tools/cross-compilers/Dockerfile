# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Musl cross-compilation toolchains built from musl-cross-make.
#
# Built once per host architecture, pushed to DockerHub, and reused by
# consumers (pillar, optee-os, bsp-imx). Only needs rebuilding when
# upgrading toolchain versions or changing the base Alpine image.
#
# Replaces the previous Alpine aports bootstrap which was slower and
# harder to maintain.
#
# Targets per host:
#   amd64:   aarch64, x86_64, riscv64, armhf
#   arm64:   aarch64, x86_64, riscv64, armhf
#   riscv64: not supported (native builds only)

ARG ALPINE_VERSION=3.22

# Pinned toolchain versions (must be supported by musl-cross-make hashes/)
ARG MUSL_CROSS_MAKE_TAG=e5147dde912478dd32ad42a25003e82d4f5733aa
ARG GCC_VER=14.2.0
ARG BINUTILS_VER=2.44

# ── builder base ───────────────────────────────────────────────────

FROM alpine:${ALPINE_VERSION} AS builder-base

# hadolint ignore=DL3018
RUN apk add --no-cache build-base wget tar xz patch texinfo linux-headers git bash

ARG MUSL_CROSS_MAKE_TAG
RUN git clone https://github.com/richfelker/musl-cross-make.git /musl-cross-make
WORKDIR /musl-cross-make
RUN git checkout "${MUSL_CROSS_MAKE_TAG}"

# Pin GCC/binutils versions and use reliable mirrors (GNU ftpmirror is often down)
ARG GCC_VER
ARG BINUTILS_VER
# hadolint ignore=SC2016
RUN printf '%s\n' \
    "GCC_VER = ${GCC_VER}" \
    "BINUTILS_VER = ${BINUTILS_VER}" \
    'GNU_SITE = https://mirrors.kernel.org/gnu' \
    'GCC_SITE = $(GNU_SITE)/gcc' \
    'BINUTILS_SITE = $(GNU_SITE)/binutils' \
    'GMP_SITE = $(GNU_SITE)/gmp' \
    'MPC_SITE = $(GNU_SITE)/mpc' \
    'MPFR_SITE = $(GNU_SITE)/mpfr' \
    'DL_CMD = wget -c --tries=5 --timeout=30 -O' \
    > config.mak

RUN mkdir -p /toolchains

# ── amd64 host: all 4 targets ─────────────────────────────────────

FROM builder-base AS build-amd64

RUN make TARGET=aarch64-linux-musl -j"$(nproc)" && \
    make TARGET=aarch64-linux-musl OUTPUT=/toolchains/aarch64-linux-musl-cross install && \
    make clean

RUN make TARGET=x86_64-linux-musl -j"$(nproc)" && \
    make TARGET=x86_64-linux-musl OUTPUT=/toolchains/x86_64-linux-musl-cross install && \
    make clean

RUN make TARGET=riscv64-linux-musl -j"$(nproc)" && \
    make TARGET=riscv64-linux-musl OUTPUT=/toolchains/riscv64-linux-musl-cross install && \
    make clean

RUN make TARGET=arm-linux-musleabihf -j"$(nproc)" && \
    make TARGET=arm-linux-musleabihf OUTPUT=/toolchains/arm-linux-musleabihf-cross install && \
    make clean

# ── arm64 host: all 4 targets ──────────────────────────────────────

FROM builder-base AS build-arm64

RUN make TARGET=x86_64-linux-musl -j"$(nproc)" && \
    make TARGET=x86_64-linux-musl OUTPUT=/toolchains/x86_64-linux-musl-cross install && \
    make clean

RUN make TARGET=aarch64-linux-musl -j"$(nproc)" && \
    make TARGET=aarch64-linux-musl OUTPUT=/toolchains/aarch64-linux-musl-cross install && \
    make clean

RUN make TARGET=riscv64-linux-musl -j"$(nproc)" && \
    make TARGET=riscv64-linux-musl OUTPUT=/toolchains/riscv64-linux-musl-cross install && \
    make clean

RUN make TARGET=arm-linux-musleabihf -j"$(nproc)" && \
    make TARGET=arm-linux-musleabihf OUTPUT=/toolchains/arm-linux-musleabihf-cross install && \
    make clean

# ── riscv64 host: not supported ───────────────────────────────────

FROM alpine:${ALPINE_VERSION} AS build-riscv64
RUN mkdir -p /toolchains

# ── final ──────────────────────────────────────────────────────────

# hadolint ignore=DL3006
FROM build-${TARGETARCH} AS build

FROM scratch
COPY --from=build /toolchains /toolchains
