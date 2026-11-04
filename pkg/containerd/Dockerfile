# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# containerd for the rootfs, built from source the way linuxkit's
# pkg/containerd builds it (static, CRI disabled in the config) but on
# eve-alpine, so that it follows the containerd releases and eve-alpine's
# Go toolchain instead of linuxkit's package releases. pkg/runc builds the
# runc release this containerd is tested with.

FROM lfedge/eve-alpine:8c9af5568049068f10bc630065793c15d52fa931 AS build
ENV BUILD_PKGS="bash gcc git libc-dev libseccomp-dev linux-headers make"
ENV PKGS="tzdata"
RUN eve-alpine-deploy.sh

ENV CONTAINERD_VERSION=v2.2.10
ADD --keep-git-dir=true https://github.com/containerd/containerd.git#${CONTAINERD_VERSION} /containerd
WORKDIR /containerd
# containerd pins module releases with published advisories that its own
# code does not reach (gRPC xDS authorization and HTTP/2 server limits,
# HTML parsing, SSH, OpenTelemetry resource detection on macOS and BSD);
# the module versions show up in the SBOM, so move them to their current
# releases before building.
RUN go get golang.org/x/net@v0.62.0 golang.org/x/crypto@v0.58.0 golang.org/x/sys@v0.49.0 \
        golang.org/x/text@v0.43.0 google.golang.org/grpc@v1.85.0 \
        github.com/klauspost/compress@v1.20.3 go.opentelemetry.io/otel/sdk@v1.45.0 && \
    go mod vendor
# The build linuxkit's containerd-dev image uses, without the btrfs
# snapshotter (EVE has no btrfs and eve-alpine no btrfs-progs-dev) and with
# the symbol tables stripped. VERSION is passed because the shallow checkout
# has no tags for git describe to find.
RUN make binaries VERSION="${CONTAINERD_VERSION}" EXTRA_FLAGS="-buildmode pie" \
        EXTRA_LDFLAGS='-s -w -extldflags "-fno-PIC -static"' \
        BUILDTAGS="static_build no_btrfs no_devmapper"

# eve-alpine-deploy.sh left an Alpine base in /out; the package is only the
# binaries, the hook linuxkit's init starts containerd through, the config
# that disables CRI, /etc/localtime for UTC timestamps, and the SBOM record.
RUN cp /out/usr/share/zoneinfo/UTC /tmp/UTC && rm -rf /out
RUN mkdir -p /out/usr/bin /out/etc/init.d /out/etc/containerd
RUN cp bin/containerd bin/ctr bin/containerd-shim-runc-v2 /out/usr/bin/
RUN cp /tmp/UTC /out/etc/localtime
RUN ln -s /usr/bin/service /out/etc/init.d/020-containerd
COPY etc/containerd/config.toml /out/etc/containerd/config.toml
RUN register-sbom-pkg.sh -n containerd -v "${CONTAINERD_VERSION#v}" -l Apache-2.0 -u https://github.com/containerd/containerd

FROM scratch
WORKDIR /
ENTRYPOINT []
COPY --from=build /out/ /
