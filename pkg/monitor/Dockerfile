# Copyright (c) 2024-2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

ARG RUST_VERSION=lfedge/eve-rust:1.93.1-1
# RUST_VERSION carries an explicit tag by default
# hadolint ignore=DL3006
FROM --platform=$BUILDPLATFORM ${RUST_VERSION} AS toolchain-base
ARG TARGETARCH

FROM toolchain-base AS target-amd64
ENV CARGO_BUILD_TARGET="x86_64-unknown-linux-musl"

FROM toolchain-base AS target-arm64
ENV CARGO_BUILD_TARGET="aarch64-unknown-linux-musl"

FROM toolchain-base AS target-riscv64
ENV CARGO_BUILD_TARGET="riscv64gc-unknown-linux-musl"

# target-$TARGETARCH is a build stage, not an image
# hadolint ignore=DL3006
FROM target-$TARGETARCH AS toolchain
RUN echo "Cargo target: $CARGO_BUILD_TARGET"

FROM toolchain AS planer
COPY . /app

WORKDIR /app
# create a recipe
RUN cargo chef prepare --recipe-path recipe.json

FROM toolchain AS cacher
# copy the recipe
WORKDIR /app
COPY --from=planer /app/recipe.json recipe.json
# build the dependencies
RUN cargo chef cook --release --recipe-path recipe.json

# building the final image
FROM toolchain AS builder
COPY . /app
WORKDIR /app

# copy prebuilt dependencies
# and the cargo directory with crates.io index
COPY --from=cacher /app/target /app/target
COPY --from=cacher $CARGO_HOME $CARGO_HOME
RUN echo "Cargo target: $CARGO_BUILD_TARGET"

RUN cargo build --release
RUN cargo sbom > sbom.spdx.json
RUN cp "/app/target/$CARGO_BUILD_TARGET/release/monitor" /app/target/
# Single source of truth for the version: the crate manifest.
RUN awk -F'"' '/^version = / {print $2; exit}' Cargo.toml > /app/monitor-version.txt


FROM lfedge/eve-alpine:39f46094f640424c345164420ed789afd8a4088b AS runtime
ENV PKGS="kbd pciutils usbutils"
RUN eve-alpine-deploy.sh

# Register the monitor TUI in the APK DB (mandatory for SBOM inclusion). The
# version comes from the crate manifest (Cargo.toml) — the single source of
# truth now that the source is colocated and no longer pulled by git tag.
COPY --from=builder /app/monitor-version.txt /tmp/monitor-version
RUN register-sbom-pkg.sh -n eve-monitor-rs -v "$(cat /tmp/monitor-version)" -l Apache-2.0 -u https://github.com/lf-edge/eve/tree/master/pkg/monitor

FROM scratch
COPY --from=runtime /out/usr/bin/openvt /usr/bin/openvt
COPY --from=runtime /out/usr/bin/loadkeys /usr/bin/loadkeys
COPY --from=runtime /out/bin/dmesg /usr/bin/dmesg
COPY --from=runtime /out/usr/bin/lsusb /usr/bin/lsusb
COPY --from=runtime /out/usr/bin/lspci /usr/bin/lspci
COPY --from=runtime /out/usr/share/keymaps/xkb/us.map.gz /usr/share/keymaps/xkb/us.map.gz
COPY --from=runtime /out/lib /lib
COPY --from=runtime /out/usr/lib /usr/lib

# copy busybox and install all symbolic links but just for debugging
COPY --from=runtime /out/bin/busybox /bin/busybox
# using an 'exec' form of RUN, shell form of 'RUN'
# command expects /bin/sh which doesn't yet exist
RUN [ "/bin/busybox", "--install", "-s", "/bin" ]
COPY --from=runtime /out/usr/bin/du /usr/bin/du

COPY --from=builder /app/target/monitor /sbin/monitor
COPY --from=builder /app/sbom.spdx.json /sbin/sbom.spdx.json
COPY run-monitor.sh /sbin/run-monitor.sh
COPY monitor-wrapper.sh /sbin/monitor-wrapper.sh

CMD ["/sbin/run-monitor.sh"]
