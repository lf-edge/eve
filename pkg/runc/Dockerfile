# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# runc for the rootfs, built from source the way linuxkit's pkg/runc builds
# it (static, seccomp enabled) but on eve-alpine, and linked without the
# symbol table and DWARF sections: with them runc is 17 MB that cost 7 MB
# in the compressed rootfs.

FROM lfedge/eve-alpine:b1b51db20be9651c521bf5ba14eb5c6d7481eed7 AS build
ENV BUILD_PKGS="bash gcc git libc-dev libseccomp-dev libseccomp-static linux-headers make"
RUN eve-alpine-deploy.sh

ENV RUNC_VERSION=v1.3.3
ADD --keep-git-dir=true https://github.com/opencontainers/runc.git#${RUNC_VERSION} /runc
WORKDIR /runc
# The build linuxkit/runc uses, plus -s -w.
RUN make static BUILDTAGS="seccomp" EXTRA_FLAGS="-buildmode pie" EXTRA_LDFLAGS="-s -w -extldflags \\\"-fno-PIC -static\\\""

# eve-alpine-deploy.sh left an Alpine base in /out; the package is only the
# binary, the hooks linuxkit's init runs around the onboot and shutdown
# containers, and the SBOM record.
RUN rm -rf /out
RUN mkdir -p /out/usr/bin /out/etc/init.d /out/etc/shutdown.d
RUN cp runc /out/usr/bin/runc
RUN ln -s /usr/bin/service /out/etc/init.d/010-onboot
RUN ln -s /usr/bin/service /out/etc/shutdown.d/010-onshutdown
RUN register-sbom-pkg.sh -n runc -v "${RUNC_VERSION#v}" -l Apache-2.0 -u https://github.com/opencontainers/runc

FROM scratch
WORKDIR /
ENTRYPOINT []
COPY --from=build /out/ /
