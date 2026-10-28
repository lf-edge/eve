# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# The test stage checks that stripping leaves Go's crash traces intact; it
# is not part of the package build. Run it with:
#   docker build --rm --target test --progress=plain --no-cache .

FROM prom/node-exporter:v1.9.1@sha256:d00a542e409ee618a4edc67da14dd48c5da66726bbd5537ab2af9c1dfc442c8a AS upstream

# the release binary ships its symbol tables: 21 MB, 14.5 MB stripped
FROM lfedge/eve-alpine:b1b51db20be9651c521bf5ba14eb5c6d7481eed7 AS strip
ENV BUILD_PKGS="binutils"
RUN eve-alpine-deploy.sh
COPY --from=upstream /bin/node_exporter /node_exporter
RUN strip /node_exporter

# The Go runtime prints crash traces from its own line table, which strip
# keeps, not from the ELF symbol table and DWARF sections, which strip
# removes. Both binaries are crashed under an address-space limit too small
# for the Go heap to initialise and the two traces are diffed; the build
# fails if they differ or if the stripped binary does not crash with a trace.
FROM strip AS test
COPY --from=upstream /bin/node_exporter /node_exporter.unstripped
# strip removed the ELF symbol table and DWARF, and the binary still runs
RUN /node_exporter --version
# Before main runs the Go runtime reserves over 500 MiB of address space for
# its page summaries; a lower limit makes it throw with a full stack trace.
# hadolint ignore=SC3045
RUN (ulimit -v 65536; /node_exporter.unstripped --version) > /unstripped.stacktrace 2>&1 || true
# hadolint ignore=SC3045
RUN (ulimit -v 65536; /node_exporter --version) > /stripped.stacktrace 2>&1 || true
RUN grep -q '^fatal error:' /unstripped.stacktrace
RUN grep -q '^fatal error:' /stripped.stacktrace
# Stack and pointer addresses differ from run to run, so compare copies with
# the addresses masked; everything else must match.
RUN sed -E 's/0x[0-9a-f]+/0xX/g' /unstripped.stacktrace > /unstripped.masked
RUN sed -E 's/0x[0-9a-f]+/0xX/g' /stripped.stacktrace > /stripped.masked
RUN diff /unstripped.masked /stripped.masked
RUN cat /stripped.stacktrace
RUN cat /unstripped.stacktrace

FROM upstream
COPY --from=strip /node_exporter /bin/node_exporter

LABEL org.opencontainers.image.title="EVE Node Exporter"
LABEL org.opencontainers.image.description="Prometheus Node Exporter with EVE specific flags"
LABEL org.opencontainers.image.authors="Zededa, Inc."
LABEL org.opencontainers.image.license="Apache-2.0"

CMD ["--path.procfs=/hostfs/proc", "--path.sysfs=/hostfs/sys", "--path.rootfs=/hostfs", "--collector.cgroups", "--collector.processes"]
