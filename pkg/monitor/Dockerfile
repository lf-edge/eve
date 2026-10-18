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


FROM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544 AS runtime
SHELL ["/bin/bash", "-eo", "pipefail", "-c"]
ENV BUILD_PKGS="console-setup"
ENV PKGS="kbd pciutils usbutils util-linux coreutils"
RUN eve-ubuntu-deploy.sh

# Ubuntu ships no compiled console keymaps: generate the us keymap that
# run-monitor.sh loads from the xkb data, where loadkeys looks for it
RUN mkdir -p /out/usr/share/keymaps/xkb && ckbcomp us | gzip -9n > /out/usr/share/keymaps/xkb/us.map.gz
# kbd depends on console-setup, which brings fonts and the X keyboard database
# that nothing here uses: run-monitor.sh only needs loadkeys, openvt and the
# keymap generated above
RUN rm -rf /out/usr/share/consolefonts /out/usr/share/consoletrans /out/usr/share/unimaps \
           /out/usr/share/X11 /out/usr/share/xkeyboard-config-2 /out/usr/share/keymaps/i386 \
           /out/usr/share/keymaps/include /out/usr/share/keymaps/mac /out/usr/share/keymaps/amiga \
           /out/usr/share/keymaps/atari /out/usr/share/keymaps/sun /out/usr/share/keymaps/ppc \
           /out/usr/share/console-setup /out/etc/console-setup

# Register the monitor TUI in the dpkg status area (mandatory for SBOM inclusion). The
# version comes from the crate manifest (Cargo.toml) — the single source of
# truth now that the source is colocated and no longer pulled by git tag.
COPY --from=builder /app/monitor-version.txt /tmp/monitor-version
RUN register-sbom-pkg.sh -n eve-monitor-rs -v "$(cat /tmp/monitor-version)" -l Apache-2.0 -u https://github.com/lf-edge/eve/tree/master/pkg/monitor

FROM scratch
COPY --from=runtime /out/ /

COPY --from=builder /app/target/monitor /sbin/monitor
COPY --from=builder /app/sbom.spdx.json /sbin/sbom.spdx.json
COPY run-monitor.sh /sbin/run-monitor.sh
COPY monitor-wrapper.sh /sbin/monitor-wrapper.sh

CMD ["/sbin/run-monitor.sh"]
