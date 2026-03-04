FROM lfedge/eve-alpine:17d3d6e74f232848aef1c44cf3a1512c73fe8298 AS tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
