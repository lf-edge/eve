# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM prom/node-exporter:v1.13.1@sha256:7296504d4ada44b7d7ab4431e27e9f9900d8488f8d55842f4b12ae2704e16dfe

LABEL org.opencontainers.image.title="EVE Node Exporter"
LABEL org.opencontainers.image.description="Prometheus Node Exporter with EVE specific flags"
LABEL org.opencontainers.image.authors="Zededa, Inc."
LABEL org.opencontainers.image.license="Apache-2.0"

CMD ["--path.procfs=/hostfs/proc", "--path.sysfs=/hostfs/sys", "--path.rootfs=/hostfs", "--collector.cgroups", "--collector.processes"]
