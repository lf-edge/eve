FROM busybox@sha256:ef320ff10026a50cf5f0213d35537ce0041ac1d96e9b7800bafd8bc9eff6c693 AS base

ARG TARGETARCH
ENV ROOTFS_VERSION=3.20.1

FROM base as rootfs-amd64
ENV ALPINE_TARGETARCH=x86_64
FROM base as rootfs-arm64
ENV ALPINE_TARGETARCH=aarch64
FROM base as rootfs-riscv64
ENV ALPINE_TARGETARCH=riscv64

# hadolint ignore=DL3006
FROM rootfs-${TARGETARCH} as builder

ADD https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/${ALPINE_TARGETARCH}/alpine-minirootfs-${ROOTFS_VERSION}-${ALPINE_TARGETARCH}.tar.gz /alpine-rootfs.tar.gz

WORKDIR /rootfs
RUN tar -xpzf /alpine-rootfs.tar.gz -C ./

FROM scratch

# seed the root filesystem
COPY --from=builder /rootfs/ /

# set the defaults for docker run
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CMD sh
