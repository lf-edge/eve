# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM prom/node-exporter:v1.9.1 AS upstream

# the release binary ships its symbol tables: 21 MB, 14.5 MB stripped
FROM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544 AS strip
COPY --from=upstream /bin/node_exporter /node_exporter
RUN strip /node_exporter

FROM upstream
COPY --from=strip /node_exporter /bin/node_exporter

LABEL org.opencontainers.image.title="EVE Node Exporter"
LABEL org.opencontainers.image.description="Prometheus Node Exporter with EVE specific flags"
LABEL org.opencontainers.image.authors="Zededa, Inc."
LABEL org.opencontainers.image.license="Apache-2.0"

CMD ["--path.procfs=/hostfs/proc", "--path.sysfs=/hostfs/sys", "--path.rootfs=/hostfs", "--collector.cgroups", "--collector.processes"]
