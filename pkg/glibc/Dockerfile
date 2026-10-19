# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# ubuntu:24.04 already has libc6 and libgcc-s1 installed as part of the
# base image, so there is nothing to apt-get install here -- we only
# harvest the files that are already present. That makes the image the
# version pin, hence the digest: the tag moves with every Ubuntu point update.
FROM ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55 AS build-harvest

RUN set -eu; \
    mkdir -p /staging; \
    for f in $(dpkg -L libc6 libgcc-s1); do \
        case "$f" in \
            /usr/share/*) continue ;; \
        esac; \
        if [ -L "$f" ] || [ -f "$f" ]; then \
            cp -a --parents "$f" /staging; \
        fi; \
    done

# Build a valid ld.so.cache for the staged tree so the glibc dynamic linker
# resolves libraries from the cache rather than needing an ldconfig run at boot.
#
# /etc/ld.so.conf itself belongs to libc-bin and is NOT harvested, but libc6 owns
# /etc/ld.so.conf.d/x86_64-linux-gnu.conf, which IS - and that fragment is what
# names the multiarch directory. Verified in a container: ldconfig -r on this
# staged tree emits no warning and produces a 21-entry cache resolving libc.so.6,
# libm.so.6 and libgcc_s.so.1 to /usr/lib/x86_64-linux-gnu.
RUN ldconfig -r /staging

# Ubuntu is usr-merged: /lib64 and /lib are symlinks into /usr, so the harvest
# above lands the loader at /usr/lib64/ld-linux-x86-64.so.2. EVE's Alpine rootfs
# is NOT usr-merged - /lib is a real directory and /lib64 does not exist at all -
# while every glibc binary hardcodes PT_INTERP=/lib64/ld-linux-x86-64.so.2. Without
# this symlink every glibc binary fails to exec with a bare ENOENT that names the
# binary rather than the missing loader, which is deeply unobvious to debug.
#
# Creating /lib64 is safe: Alpine has no such path, so nothing is shadowed. We
# deliberately do NOT touch /lib, which is a real directory in the Alpine rootfs.
RUN ln -s usr/lib64 /staging/lib64

# Visible in build logs so staged size regressions are easy to spot.
RUN du -sh /staging

# Record what was harvested for the SBOM stage below: name, version, SPDX
# licence and source URL, tab-separated. Versions come from dpkg so they always
# match the base image actually used.
RUN mkdir -p /sbom && \
    for p in libc6 libgcc-s1; do \
        case "$p" in \
            libc6) lic="LGPL-2.1-or-later" ;; \
            libgcc-s1) lic="GPL-3.0-or-later WITH GCC-exception-3.1" ;; \
        esac; \
        printf '%s\t%s\t%s\thttps://launchpad.net/ubuntu/+source/%s\n' \
            "$p" "$(dpkg-query -W -f='${Version}' "$p")" "$lic" \
            "$(dpkg-query -W -f='${source:Package}' "$p")" >> /sbom/pkgs.tsv; \
    done

# This package is amd64-only for now: the harvested paths bake in the
# Debian/Ubuntu multiarch triplet (x86_64-linux-gnu), which is
# x86_64-specific. Adding arm64 support means handling the
# aarch64-linux-gnu triplet as its own case below, not just pointing
# the base image at an arm64 ubuntu:24.04.
FROM build-harvest AS build-amd64

# Empty package on non-amd64 architectures: same base image, but skip
# the harvest so /staging exists and is empty.
FROM ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55 AS build-empty
RUN mkdir -p /staging /sbom && : > /sbom/pkgs.tsv

FROM build-empty AS build-arm64
FROM build-empty AS build-riscv64

# hadolint ignore=DL3006
FROM build-${TARGETARCH} AS build

# register-sbom-pkg.sh needs apk, so registration runs in eve-alpine rather
# than in the Ubuntu stage that knows the versions; pkgs.tsv carries them over.
# The init-only call guarantees the DB file exists on architectures that
# register nothing.
FROM lfedge/eve-alpine:1fdf3241f1aef1dd3e8ad7433c85474bc522f3f5 AS sbom
COPY --from=build /sbom/pkgs.tsv /pkgs.tsv
RUN register-sbom-pkg.sh -o /sbom-out && \
    tab="$(printf '\t')" && \
    while IFS="$tab" read -r name ver lic url; do \
        register-sbom-pkg.sh -n "$name" -v "$ver" -l "$lic" -u "$url" \
            -d "$name (Ubuntu 24.04 binary package)" -o /sbom-out; \
    done < /pkgs.tsv

FROM scratch
COPY --from=build /staging/ /
COPY --from=sbom /sbom-out/lib/apk/db/installed /lib/apk/db/installed

ENTRYPOINT []
CMD []
